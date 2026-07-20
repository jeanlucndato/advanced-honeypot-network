package mysqld

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to start MySQL honeypot: %v", err)
	}
	fmt.Printf("🐬 MySQL Honeypot active on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// 1. Send MySQL Server Greeting (Handshake V10)
	// This is a minimal valid handshake to make scanners think it's a real MySQL 5.7+ db
	greeting := []byte{
		0x4a, 0x00, 0x00, 0x00, // Packet length (74), Sequence ID (0)
		0x0a, // Protocol Version
		0x35, 0x2e, 0x37, 0x2e, 0x33, 0x33, 0x00, // Server Version: "5.7.33"
		0x01, 0x00, 0x00, 0x00, // Thread ID
		0x73, 0x6f, 0x6d, 0x65, 0x73, 0x61, 0x6c, 0x74, 0x00, // Salt part 1
		0xff, 0xff, // Capability Flags (lower 2 bytes)
		0x08, // Character Set (latin1)
		0x02, 0x00, // Status Flags (Autocommit)
		0xff, 0xff, // Capability Flags (upper 2 bytes)
		0x15, // Length of auth plugin data
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved (10 bytes)
		0x6d, 0x6f, 0x72, 0x65, 0x73, 0x61, 0x6c, 0x74, 0x68, 0x65, 0x72, 0x65, 0x00, // Salt part 2
		0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, // Auth plugin name
	}
	conn.Write(greeting)

	// 2. Read Login Request
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 36 {
		return
	}

	// Basic parsing of Login Request to extract username
	// Usually username starts around byte 36 depending on client capabilities
	// This is a simplified extraction
	username := extractNullTerminatedString(buf[36:])
	if username == "" {
		username = "unknown"
	}

	event.GlobalBus.Publish(types.Event{
		AttackerIP: ip,
		Service:    "mysql",
		EventType:  "auth_attempt",
		Username:   username,
		Payload:    fmt.Sprintf("Login request for user: %s", username),
	})

	// 3. Send Access Denied Error
	// Packet format: length (3), seq (2), header (0xff = error), errcode (1045)
	errPacket := []byte{
		0x17, 0x00, 0x00, 0x02, 
		0xff, 
		0x15, 0x04, // Error code 1045
		0x23, 0x32, 0x38, 0x30, 0x30, 0x30, // SQL State marker (#28000)
		0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, // "Access denied"
	}
	conn.Write(errPacket)
}

func extractNullTerminatedString(b []byte) string {
	idx := bytes.IndexByte(b, 0x00)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}
