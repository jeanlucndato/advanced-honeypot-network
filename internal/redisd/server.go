package redisd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sanitize"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	addr := os.Getenv("HIVE_REDIS_ADDR")
	if addr == "" {
		addr = ":" + port
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to start Redis honeypot: %v", err)
	}
	fmt.Printf("Redis honeypot listening on %s\n", addr)
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
	ip, sourcePort, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		line, err := readRESPLine(reader)
		if err != nil {
			return
		}
		if line == "" {
			continue
		}
		parts, err := readRESPCommand(reader, line)
		if err != nil {
			return
		}
		if len(parts) == 0 {
			continue
		}
		payload := sanitize.Redact(strings.Join(redactRedisSecrets(parts), " "))
		kind := "command_exec"
		lower := strings.ToLower(parts[0])
		if strings.Contains(lower, "config") || strings.Contains(lower, "slaveof") || strings.Contains(lower, "replicaof") {
			kind = "exploit_attempt"
		}
		event.GlobalBus.Publish(types.Event{AttackerIP: ip, AttackerPort: sourcePort, Service: "redis", EventType: kind, Payload: payload})
		if _, err := io.WriteString(conn, redisReply(parts)); err != nil {
			return
		}
	}
}

func redactRedisSecrets(parts []string) []string {
	copyParts := append([]string(nil), parts...)
	if len(copyParts) == 0 {
		return copyParts
	}
	switch strings.ToUpper(copyParts[0]) {
	case "AUTH":
		for i := 1; i < len(copyParts); i++ {
			copyParts[i] = "[REDACTED]"
		}
	case "CONFIG":
		if len(copyParts) > 3 && strings.EqualFold(copyParts[1], "SET") && strings.EqualFold(copyParts[2], "requirepass") {
			copyParts[3] = "[REDACTED]"
		}
	case "ACL":
		if len(copyParts) > 3 && strings.EqualFold(copyParts[1], "SETUSER") {
			for i := 3; i < len(copyParts); i++ {
				if strings.HasPrefix(copyParts[i], ">") {
					copyParts[i] = ">[REDACTED]"
				}
			}
		}
	}
	return copyParts
}

func readRESPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 64<<10 {
		return "", fmt.Errorf("RESP line too large")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func readRESPCommand(reader *bufio.Reader, first string) ([]string, error) {
	if !strings.HasPrefix(first, "*") {
		return strings.Fields(first), nil
	}
	count, err := strconv.Atoi(strings.TrimPrefix(first, "*"))
	if err != nil || count < 1 || count > 128 {
		return nil, fmt.Errorf("invalid RESP array length")
	}
	parts := make([]string, 0, count)
	total := 0
	for i := 0; i < count; i++ {
		lengthLine, err := readRESPLine(reader)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(lengthLine, "$") {
			return nil, fmt.Errorf("expected RESP bulk string")
		}
		n, err := strconv.Atoi(strings.TrimPrefix(lengthLine, "$"))
		if err != nil || n < 0 || n > 64<<10 {
			return nil, fmt.Errorf("invalid RESP bulk length")
		}
		total += n
		if total > 64<<10 {
			return nil, fmt.Errorf("RESP command too large")
		}
		data := make([]byte, n+2)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		if data[n] != '\r' || data[n+1] != '\n' {
			return nil, fmt.Errorf("malformed RESP bulk terminator")
		}
		parts = append(parts, string(data[:n]))
	}
	return parts, nil
}

func redisReply(parts []string) string {
	command := strings.ToUpper(parts[0])
	switch command {
	case "PING":
		if len(parts) > 1 {
			return fmt.Sprintf("$%d\r\n%s\r\n", len(parts[1]), parts[1])
		}
		return "+PONG\r\n"
	case "ECHO":
		if len(parts) < 2 {
			return "-ERR wrong number of arguments for 'echo' command\r\n"
		}
		return fmt.Sprintf("$%d\r\n%s\r\n", len(parts[1]), parts[1])
	case "GET":
		return "$-1\r\n"
	case "EXISTS", "DBSIZE", "PUBLISH":
		return ":0\r\n"
	case "KEYS":
		return "*0\r\n"
	case "INFO":
		info := "# Server\r\nredis_version:7.0.15\r\nredis_mode:standalone\r\n# Clients\r\nconnected_clients:1\r\n# Stats\r\ntotal_connections_received:1\r\n"
		return fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)
	case "CONFIG":
		if len(parts) > 2 && strings.EqualFold(parts[1], "GET") {
			key := parts[2]
			value := ""
			switch strings.ToLower(key) {
			case "dir":
				value = "/var/lib/redis"
			case "dbfilename":
				value = "dump.rdb"
			case "appendonly":
				value = "no"
			}
			return fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(key), key, len(value), value)
		}
		return "+OK\r\n"
	case "SET", "CLIENT", "AUTH", "SELECT", "QUIT", "REPLICAOF", "SLAVEOF":
		return "+OK\r\n"
	default:
		return fmt.Sprintf("-ERR unknown command '%s'\r\n", strings.ReplaceAll(command, "'", ""))
	}
}
