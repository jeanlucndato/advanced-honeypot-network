package redisd

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to start Redis honeypot: %v", err)
	}
	fmt.Printf("🔴 Redis Honeypot active on port %s...\n", port)

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
	reader := bufio.NewReader(conn)

	for {
		// Read a line from the client (RESP protocol)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// A very basic RESP array parser to grab the actual commands
		// e.g. *2\r\n$4\r\nINFO\r\n$7\r\nCOMMAND\r\n
		var payload string
		if strings.HasPrefix(line, "*") {
			// It's an array of bulk strings, read the elements
			// We'll just collect everything into a single string
			parts := []string{}
			// Skip the array length line
			for i := 0; i < 20; i++ { // limit to 20 lines to avoid infinite loops on bad parsing
				l, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "$") {
					// It's a bulk string length, read the actual string next
					strLine, _ := reader.ReadString('\n')
					parts = append(parts, strings.TrimSpace(strLine))
				}
				// Break out if we haven't seen a $ or if we've read enough (simplified)
				if !strings.HasPrefix(l, "$") && i > 1 {
					break
				}
			}
			payload = strings.Join(parts, " ")
		} else {
			// Inline command (like older redis or manual telnet)
			payload = line
		}

		if payload == "" {
			continue
		}

		// Publish event
		eventType := "command_exec"
		if strings.Contains(strings.ToLower(payload), "config") || strings.Contains(strings.ToLower(payload), "slaveof") {
			eventType = "exploit_attempt"
		}

		event.GlobalBus.Publish(types.Event{
			AttackerIP: ip,
			Service:    "redis",
			EventType:  eventType,
			Payload:    payload,
		})

		// Send generic OK response to keep them interacting
		conn.Write([]byte("+OK\r\n"))
	}
}
