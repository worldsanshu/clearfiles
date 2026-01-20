package main

import (
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() {
	var err error
	// Open SQLite database file "clearfile.db"
	// Set busy_timeout to 5000ms to avoid SQLITE_BUSY errors
	// Enable WAL mode for better concurrency
	db, err = sql.Open("sqlite", "clearfile.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatal(err)
	}

	// Optional: optimize connection pool for SQLite
	db.SetMaxOpenConns(25) // WAL allows concurrent reads, increase limit

	createTables := `
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		hostname TEXT,
		os TEXT,
		ip TEXT,
		last_seen DATETIME,
		status TEXT,
		remark TEXT
	);

	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT
	);

	CREATE TABLE IF NOT EXISTS commands (
		id TEXT PRIMARY KEY,
		device_id TEXT,
		action TEXT,
		payload TEXT,
		created_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS command_logs (
		id TEXT PRIMARY KEY,
		device_id TEXT,
		action TEXT,
		result TEXT,
		created_at DATETIME
	);
	`

	// Try to add group_name column if it doesn't exist (migration for existing DBs)
	// We ignore error if column already exists
	db.Exec("ALTER TABLE devices ADD COLUMN group_name TEXT DEFAULT 'Default'")

	// Add payload column to commands table if it doesn't exist
	db.Exec("ALTER TABLE commands ADD COLUMN payload TEXT DEFAULT ''")

	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	// Set default password if not exists
	setPasswordIfMissing("admin")
}

func setPasswordIfMissing(defaultPwd string) {
	var val string
	err := db.QueryRow("SELECT value FROM config WHERE key = 'admin_password'").Scan(&val)
	if err == sql.ErrNoRows {
		setPassword(defaultPwd)
	}
}

func checkPassword(inputPwd string) bool {
	var storedPwd string
	err := db.QueryRow("SELECT value FROM config WHERE key = 'admin_password'").Scan(&storedPwd)
	if err != nil {
		return false
	}
	return inputPwd == storedPwd
}

func setPassword(newPwd string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('admin_password', ?)", newPwd)
	return err
}

func upsertDevice(d *Device) error {
	_, err := db.Exec(`
		INSERT INTO devices (id, hostname, os, ip, last_seen, status, remark)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname,
			os=excluded.os,
			ip=excluded.ip,
			last_seen=excluded.last_seen,
			status=excluded.status
	`, d.ID, d.Hostname, d.OS, d.IP, d.LastSeen, d.Status, d.Remark)
	return err
}

func updateDeviceGroup(deviceID, groupName string) error {
	_, err := db.Exec("UPDATE devices SET group_name = ? WHERE id = ?", groupName, deviceID)
	return err
}

func getAllDevices() ([]*Device, error) {
	rows, err := db.Query("SELECT id, hostname, os, ip, last_seen, status, remark, group_name FROM devices ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.OS, &d.IP, &d.LastSeen, &d.Status, &d.Remark, &d.GroupName); err != nil {
			return nil, err
		}

		if time.Since(d.LastSeen) > 1*time.Minute {
			d.Status = "离线"
		} else {
			d.Status = "在线"
		}

		// Load logs for UI
		logs, _ := getCommandLogs(d.ID)
		d.Logs = logs

		d.CommandQ = []Command{}
		list = append(list, &d)
	}
	return list, nil
}

func updateDeviceRemark(id, remark string) error {
	_, err := db.Exec("UPDATE devices SET remark = ? WHERE id = ?", remark, id)
	return err
}

func getDevice(id string) (*Device, error) {
	var d Device
	var lastSeen time.Time
	err := db.QueryRow("SELECT id, hostname, os, ip, last_seen, status, remark FROM devices WHERE id = ?", id).
		Scan(&d.ID, &d.Hostname, &d.OS, &d.IP, &lastSeen, &d.Status, &d.Remark)
	if err != nil {
		return nil, err
	}
	d.LastSeen = lastSeen
	return &d, nil
}

func addCommand(deviceID string, cmd Command) error {
	_, err := db.Exec("INSERT INTO commands (id, device_id, action, payload, created_at) VALUES (?, ?, ?, ?, ?)",
		cmd.ID, deviceID, cmd.Action, cmd.Payload, time.Now())
	return err
}

func getNextCommand(deviceID string) (*Command, error) {
	row := db.QueryRow("SELECT id, action, payload FROM commands WHERE device_id = ? ORDER BY created_at ASC LIMIT 1", deviceID)

	var cmd Command
	err := row.Scan(&cmd.ID, &cmd.Action, &cmd.Payload)
	if err == sql.ErrNoRows {
		return nil, nil // No commands
	}
	if err != nil {
		return nil, err
	}

	_, _ = db.Exec("DELETE FROM commands WHERE id = ?", cmd.ID)
	return &cmd, nil
}

type CommandLog struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

func addCommandLog(logEntry CommandLog) error {
	_, err := db.Exec("INSERT INTO command_logs (id, device_id, action, result, created_at) VALUES (?, ?, ?, ?, ?)",
		logEntry.ID, logEntry.DeviceID, logEntry.Action, logEntry.Result, time.Now())
	return err
}

func getCommandLogs(deviceID string) ([]CommandLog, error) {
	rows, err := db.Query("SELECT id, device_id, action, result, created_at FROM command_logs WHERE device_id = ? ORDER BY created_at DESC LIMIT 10", deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []CommandLog
	for rows.Next() {
		var l CommandLog
		var createdAt time.Time
		if err := rows.Scan(&l.ID, &l.DeviceID, &l.Action, &l.Result, &createdAt); err != nil {
			return nil, err
		}
		l.CreatedAt = createdAt
		logs = append(logs, l)
	}
	return logs, nil
}
