# Secure Device Management System

This project demonstrates a secure client-server architecture for remote device management using Go. It includes a web dashboard for administration and a cross-platform client agent.

## Components

1.  **Server (`server/`)**: 
    *   Manages connected devices.
    *   Provides a Web UI for administrators.
    *   Queues commands for devices.
    *   REST API for client communication.

2.  **Client (`client/`)**:
    *   Runs on Windows/macOS/Linux.
    *   Registers device info (Hostname, OS).
    *   Polls for commands via secure HTTP.
    *   Executes administrative tasks.

## Security Features

*   **Encryption**: The architecture supports TLS (HTTPS). In production, `http.ListenAndServeTLS` should be used with valid certificates (e.g., Let's Encrypt).
*   **Privacy**: Request and response bodies are encrypted over the wire using standard HTTPS.

## How to Run

### Prerequisites
*   Go 1.20+ installed.

### 1. Start the Server

```bash
cd server
go run main.go
```
The server will start on `http://localhost:8080`.
Access the dashboard at `http://localhost:8080`.

### 2. Start the Client

Open a new terminal:
```bash
cd client
go run main.go
```

The client will:
1.  Connect to the server.
2.  Register itself.
3.  Start polling for commands.

### 3. Send Commands
1.  Go to the Web Dashboard.
2.  You should see the connected device listed.
3.  Select a command (e.g., "Ping") and click "Send".
4.  Check the Client terminal to see the command received.

## Deployment Notes
*   **Domain**: Update `ServerURL` in `client/main.go` to your domain (e.g., `https://clearpc.zm-tool.me`).
*   **TLS**: Ensure the server has valid SSL certificates and listens on port 443.
