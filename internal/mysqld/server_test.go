package mysqld

import "testing"

func TestExtractNullTerminatedUsername(t *testing.T) {
	if got := extractNullTerminatedString([]byte("analyst\x00secret response")); got != "analyst" {
		t.Fatalf("username=%q", got)
	}
	if got := extractNullTerminatedString([]byte("legacy")); got != "legacy" {
		t.Fatalf("username=%q", got)
	}
}
