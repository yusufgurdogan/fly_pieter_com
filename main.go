package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Constants
const (
	MaxPositionAge    = 5 * time.Second
	BroadcastInterval = 500 * time.Millisecond
	BlocklistFile     = "fly_ip_blocklist.txt"
)

// Global variables and mutex to protect them
var (
	clients               = make(map[*Client]bool)
	ipToClient            = make(map[string]*Client)
	blockedIPs            = make(map[string]bool)
	planeSecrets          = make(map[string]string)
	blocklistLastModified time.Time

	mu sync.RWMutex

	// Loggers
	infoLog  = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	errorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
	warnLog  = log.New(os.Stderr, "WARN: ", log.Ldate|log.Ltime)
)

// Position represents the 3D position and orientation of a plane.
type Position struct {
	X             float64 `json:"x"`
	Y             float64 `json:"y"`
	Z             float64 `json:"z"`
	Heading       float64 `json:"heading,omitempty"`
	VerticalSpeed float64 `json:"verticalSpeed,omitempty"`
	Timestamp     int64   `json:"timestamp"`
}

// Message is the structure used for WebSocket messages.
type Message struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	PlaneID string      `json:"planeId,omitempty"`
}

// PlayerData holds information to be broadcasted.
type PlayerData struct {
	Position   Position  `json:"position"`
	PlaneID    string    `json:"planeId"`
	LastUpdate time.Time `json:"lastUpdate"`
}

// Client wraps a WebSocket connection with its send channel and metadata.
type Client struct {
	conn       *websocket.Conn
	send       chan []byte
	ip         string
	planeID    string
	position   Position
	lastUpdate time.Time
}

// readPump handles incoming messages from the client.
func (c *Client) readPump() {
	defer disconnectClient(c)

	// Set a reasonable message size limit.
	c.conn.SetReadLimit(5000)

	for {
		messageType, message, err := c.conn.ReadMessage()
		if err != nil {
			// Read error implies client disconnect.
			break
		}
		// Only process text messages.
		if messageType != websocket.TextMessage {
			continue
		}

		// Check for suspicious messages.
		if isSuspiciousMessage(message) {
			warnLog.Printf("Suspicious message from IP: %s", c.ip)
			continue
		}

		// Decode the message.
		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			warnLog.Printf("Invalid JSON from IP: %s", c.ip)
			continue
		}

		// Process only "position" messages.
		if msg.Type == "position" {
			// Expecting Data to be a map.
			dataMap, ok := msg.Data.(map[string]interface{})
			if !ok {
				continue
			}

			var pos Position
			if x, ok := dataMap["x"].(float64); ok {
				pos.X = x
			}
			if y, ok := dataMap["y"].(float64); ok {
				pos.Y = y
			}
			if z, ok := dataMap["z"].(float64); ok {
				pos.Z = z
			}
			if heading, ok := dataMap["heading"].(float64); ok {
				pos.Heading = heading
			}
			if vs, ok := dataMap["verticalSpeed"].(float64); ok {
				pos.VerticalSpeed = vs
			}
			if ts, ok := dataMap["timestamp"].(float64); ok {
				pos.Timestamp = int64(ts)
			}

			// Update client data.
			mu.Lock()
			if c.planeID != msg.PlaneID {
				infoLog.Printf("Plane %s connected from IP: %s", msg.PlaneID, c.ip)
				c.planeID = msg.PlaneID
			}
			c.position = pos
			c.lastUpdate = time.Now()
			mu.Unlock()
		}
	}
}

// writePump is the dedicated writer goroutine for the client.
func (c *Client) writePump() {
	defer c.conn.Close()
	for {
		message, ok := <-c.send
		if !ok {
			// Channel closed.
			return
		}
		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			return
		}
	}
}

// disconnectClient cleans up when a client disconnects.
func disconnectClient(c *Client) {
	mu.Lock()
	if _, exists := clients[c]; exists {
		delete(clients, c)
		if ipToClient[c.ip] == c {
			delete(ipToClient, c.ip)
		}
		infoLog.Printf("Client from IP %s disconnected (Plane %s)", c.ip, c.planeID)
	}
	mu.Unlock()
	close(c.send)
}

// isSuspiciousMessage filters out messages that are too large or low entropy.
func isSuspiciousMessage(message []byte) bool {
	if len(message) > 5000 {
		return true
	}
	uniqueChars := make(map[byte]bool)
	for _, c := range message {
		uniqueChars[c] = true
	}
	charRatio := float64(len(uniqueChars)) / float64(len(message))
	return charRatio < 0.1
}

// loadIPBlocklist reads the blocklist file and returns a set of IPs.
func loadIPBlocklist() map[string]bool {
	newBlockedIPs := make(map[string]bool)

	if _, err := os.Stat(BlocklistFile); os.IsNotExist(err) {
		// Create the file with a comment if it doesn't exist.
		ioutil.WriteFile(BlocklistFile, []byte("# Add IPs to block, one per line\n"), 0644)
		return newBlockedIPs
	}

	fileInfo, err := os.Stat(BlocklistFile)
	if err != nil {
		errorLog.Printf("Error checking blocklist file: %v", err)
		return blockedIPs
	}

	currentMtime := fileInfo.ModTime()
	if !currentMtime.After(blocklistLastModified) {
		return blockedIPs
	}

	content, err := ioutil.ReadFile(BlocklistFile)
	if err != nil {
		errorLog.Printf("Error reading blocklist file: %v", err)
		return blockedIPs
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			newBlockedIPs[line] = true
		}
	}
	blocklistLastModified = currentMtime
	return newBlockedIPs
}

// handleWebSocket upgrades the HTTP connection and registers a new client.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections
	},
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	mu.RLock()
	if blockedIPs[clientIP] {
		mu.RUnlock()
		infoLog.Printf("Rejected connection from blocked IP: %s", clientIP)
		http.Error(w, "IP is blocked", http.StatusForbidden)
		return
	}
	if _, exists := ipToClient[clientIP]; exists {
		mu.RUnlock()
		infoLog.Printf("Rejected duplicate connection from IP: %s", clientIP)
		http.Error(w, "Only one connection per IP allowed", http.StatusTooManyRequests)
		return
	}
	mu.RUnlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		errorLog.Printf("Error upgrading to WebSocket: %v", err)
		return
	}

	client := &Client{
		conn:       conn,
		send:       make(chan []byte, 256), // Buffered channel for outgoing messages.
		ip:         clientIP,
		lastUpdate: time.Now(),
	}

	// Register the new client.
	mu.Lock()
	clients[client] = true
	ipToClient[clientIP] = client
	mu.Unlock()

	// Launch the dedicated writer goroutine.
	go client.writePump()
	// Read pump runs in this goroutine.
	client.readPump()
}

// broadcastPositions periodically sends all updated positions to all clients.
func broadcastPositions() {
	ticker := time.NewTicker(BroadcastInterval)
	defer ticker.Stop()

	for range ticker.C {
		mu.RLock()
		if len(clients) == 0 {
			mu.RUnlock()
			continue
		}

		var positions []PlayerData
		for client := range clients {
			// Only broadcast if the client has a registered plane.
			if client.planeID != "" {
				positions = append(positions, PlayerData{
					Position:   client.position,
					PlaneID:    client.planeID,
					LastUpdate: client.lastUpdate,
				})
			}
		}
		mu.RUnlock()

		if len(positions) == 0 {
			continue
		}

		msg := Message{
			Type: "positions",
			Data: positions,
		}
		payload, err := json.Marshal(msg)
		if err != nil {
			errorLog.Printf("Error marshaling broadcast message: %v", err)
			continue
		}

		mu.RLock()
		for client := range clients {
			// Non-blocking send to avoid slow clients stalling broadcast.
			select {
			case client.send <- payload:
			default:
				warnLog.Printf("Send buffer full for client %s; dropping broadcast", client.ip)
			}
		}
		mu.RUnlock()
	}
}

// cleanupStalePlayers removes clients that have not sent updates recently.
func cleanupStalePlayers() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		mu.Lock()
		for client := range clients {
			if now.Sub(client.lastUpdate) > MaxPositionAge {
				infoLog.Printf("Removing stale client %s (Plane %s)", client.ip, client.planeID)
				client.conn.Close() // This triggers disconnectClient.
			}
		}

		// Clean up unused plane secrets.
		activePlaneIDs := make(map[string]bool)
		for client := range clients {
			if client.planeID != "" {
				activePlaneIDs[client.planeID] = true
			}
		}
		for planeID := range planeSecrets {
			if !activePlaneIDs[planeID] {
				delete(planeSecrets, planeID)
			}
		}
		mu.Unlock()
	}
}

// checkBlocklistUpdates periodically reloads the blocklist and disconnects clients if needed.
func checkBlocklistUpdates() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		newBlockedIPs := loadIPBlocklist()
		for ip, client := range ipToClient {
			if newBlockedIPs[ip] {
				// Send a close message before disconnecting.
				closeMsg := websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "IP has been blocked")
				client.conn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(5*time.Second))
				client.conn.Close()
				infoLog.Printf("Closed connection from blocked IP: %s", ip)
			}
		}
		blockedIPs = newBlockedIPs
		mu.Unlock()
	}
}

func main() {
	// Use all available CPU cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Initialize blocklist.
	mu.Lock()
	blockedIPs = loadIPBlocklist()
	mu.Unlock()

	// Start background goroutines.
	go broadcastPositions()
	go cleanupStalePlayers()
	go checkBlocklistUpdates()

	// Set up HTTP handler.
	http.HandleFunc("/", handleWebSocket)

	// Start the plain HTTP server on 127.0.0.1:8080.
	infoLog.Printf("Server running on ws://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
