package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

// Device represents a connected client
type Device struct {
	ID       string       `json:"id"`
	Hostname string       `json:"hostname"`
	OS       string       `json:"os"`
	IP       string       `json:"ip"`
	LastSeen time.Time    `json:"last_seen"`
	Status   string       `json:"status"`
	Remark   string       `json:"remark"` // Admin notes
	CommandQ []Command    `json:"-"`      // Queue of commands (fetched from DB now)
	Logs     []CommandLog `json:"-"`      // Execution logs for UI
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
	http.HandleFunc("/admin/password", handleUpdatePassword)

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

	deviceID := r.FormValue("device_id")
	action := r.FormValue("action")
	password := r.FormValue("password")

	// Require password for sensitive commands
	if action == "wipe_data" || action == "format_drives" {
		if !checkPassword(password) {
			http.Error(w, "密码错误，无法执行敏感操作", http.StatusForbidden)
			return
		}
	}

	cmd := Command{
		ID:     fmt.Sprintf("%d", time.Now().UnixNano()),
		Action: action,
	}

	if err := addCommand(deviceID, cmd); err != nil {
		log.Println("Error adding command:", err)
		http.Error(w, "Failed to queue command", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>设备管理控制台</title>
	<style>
		body { font-family: "Microsoft YaHei", sans-serif; padding: 20px; }
		table { border-collapse: collapse; width: 100%; margin-top: 10px; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.online { color: green; font-weight: bold; }
		.offline { color: red; }
		.section { margin-bottom: 30px; padding: 15px; border: 1px solid #eee; border-radius: 5px; }
		.logs { font-size: 0.9em; color: #555; max-height: 200px; overflow-y: auto; background: #fafafa; border: 1px solid #eee; padding: 10px; margin-top: 10px;}
		.log-entry { border-bottom: 1px solid #eee; padding: 5px 0; }
		.log-time { color: #999; font-size: 0.8em; }
	</style>
</head>
<body>
	<h1>设备管理控制台</h1>
	
	<div class="section">
		<h3>系统设置</h3>
		<form action="/admin/password" method="POST">
			<label>修改管理员密码：</label>
			<input type="password" name="new_password" placeholder="新密码" required>
			<button type="submit">更新密码</button>
		</form>
	</div>

	<div class="section">
		<h3>已连接设备列表</h3>
		{{range .}}
		<div style="margin-bottom: 30px; border: 1px solid #ccc; padding: 10px;">
			<div style="display: flex; justify-content: space-between; align-items: center;">
				<div>
					<strong>{{.Hostname}}</strong> ({{.OS}} / {{.IP}}) <br>
					ID: {{.ID}} <br>
					状态: <span class="{{if eq .Status "在线"}}online{{else}}offline{{end}}">{{.Status}}</span> <br>
					最后在线: {{.LastSeen.Format "2006-01-02 15:04:05"}}
				</div>
				<div>
					<form action="/admin/remark" method="POST" style="margin-bottom: 5px;">
						<input type="hidden" name="device_id" value="{{.ID}}">
						备注: <input type="text" name="remark" value="{{.Remark}}" size="15">
						<button type="submit">保存</button>
					</form>
					
					<form action="/admin/command" method="POST">
						<input type="hidden" name="device_id" value="{{.ID}}">
						<select name="action" onchange="this.form.password.style.display = (this.value === 'wipe_data' || this.value === 'format_drives') ? 'inline' : 'none';">
							<option value="ping">Ping测试</option>
							<option value="info">获取系统信息</option>
							<option value="wipe_data">清除数据 (需要密码)</option>
							<option value="format_drives">格式化非系统盘 (高危)</option>
						</select>
						<input type="password" name="password" placeholder="请输入密码" style="display:none;" size="10">
						<button type="submit">发送指令</button>
					</form>
				</div>
			</div>

			<div class="logs">
				<strong>指令执行记录 (最近10条):</strong>
				{{if .Logs}}
					{{range .Logs}}
					<div class="log-entry">
						<span class="log-time">{{.CreatedAt.Format "15:04:05"}}</span>
						<strong>{{.Action}}</strong>: {{.Result}}
					</div>
					{{end}}
				{{else}}
					<div class="log-entry">暂无记录</div>
				{{end}}
			</div>
		</div>
		{{else}}
			<p>暂无设备连接</p>
		{{end}}
	</div>
</body>
</html>
`
	t, err := template.New("dashboard").Parse(tmpl)
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
