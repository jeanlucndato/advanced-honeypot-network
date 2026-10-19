package mysqld

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	addr := os.Getenv("HIVE_MYSQL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:" + port
	}
	listener, err := net.Listen("tcp", addr)
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
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	ip, sourcePort, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Protocol 10 greeting for a MySQL 5.7-style decoy.
	greetingBody := []byte{0x0a}
	greetingBody = append(greetingBody, []byte("5.7.33\x00")...)
	greetingBody = append(greetingBody, 1, 0, 0, 0) // connection id
	greetingBody = append(greetingBody, []byte("somesalt\x00")...)
	capabilities := uint32(0x0008a205) // protocol 4.1, transactions, secure auth, plugin auth
	greetingBody = append(greetingBody, byte(capabilities), byte(capabilities>>8), 0x08, 0x02, 0x00, byte(capabilities>>16), byte(capabilities>>24), 0x15)
	greetingBody = append(greetingBody, make([]byte, 10)...)
	greetingBody = append(greetingBody, []byte("moresalt1234\x00mysql_native_password\x00")...)
	greeting := make([]byte, 4, len(greetingBody)+4)
	greeting[0] = byte(len(greetingBody))
	greeting[1] = byte(len(greetingBody) >> 8)
	greeting[2] = byte(len(greetingBody) >> 16)
	greeting = append(greeting, greetingBody...)
	if _, err := conn.Write(greeting); err != nil {
		return
	}

	// 2. Read Login Request
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	packetLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if packetLen < 32 || packetLen > 64<<10 {
		return
	}
	packet := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return
	}

	// Basic parsing of Login Request to extract username
	// Usually username starts around byte 36 depending on client capabilities
	// This is a simplified extraction
	username := extractNullTerminatedString(packet[32:])
	if username == "" {
		username = "unknown"
	}
	if len(username) > 256 {
		username = username[:256]
	}

	event.GlobalBus.Publish(types.Event{
		AttackerIP:   ip,
		AttackerPort: sourcePort,
		Service:      "mysql",
		EventType:    "auth_attempt",
		Username:     username,
		Payload:      fmt.Sprintf("Login request for user: %s", username),
	})

	// 3. Send Access Denied Error
	// Packet format: length (3), seq (2), header (0xff = error), errcode (1045)
	errBody := []byte{
		0xff,
		0x15, 0x04, // Error code 1045
		0x23, 0x32, 0x38, 0x30, 0x30, 0x30, // SQL State marker (#28000)
		0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, // "Access denied"
	}
	errPacket := make([]byte, 4, len(errBody)+4)
	errPacket[0], errPacket[1], errPacket[2], errPacket[3] = byte(len(errBody)), byte(len(errBody)>>8), byte(len(errBody)>>16), 0x02
	errPacket = append(errPacket, errBody...)
	_, _ = conn.Write(errPacket)
}

func extractNullTerminatedString(b []byte) string {
	idx := bytes.IndexByte(b, 0x00)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}
