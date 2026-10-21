package redisd

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadRESPCommand(t *testing.T) {
	input := "$4\r\nAUTH\r\n$9\r\nsecret123\r\n"
	parts, err := readRESPCommand(bufio.NewReader(strings.NewReader(input)), "*2")
	if err != nil || len(parts) != 2 || parts[1] != "secret123" {
		t.Fatalf("parts=%q err=%v", parts, err)
	}
	if got := redactRedisSecrets(parts); got[1] != "[REDACTED]" {
		t.Fatalf("AUTH secret not redacted: %q", got)
	}
}

func TestReadRESPRejectsOversize(t *testing.T) {
	if _, err := readRESPCommand(bufio.NewReader(strings.NewReader("")), "*129"); err == nil {
		t.Fatal("expected invalid array length")
	}
}
