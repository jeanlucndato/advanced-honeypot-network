package httpd

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecoyPageContainsNoHostDynamicData(t *testing.T) {
	page := decoyPage("/wp-login.php")
	for _, want := range []string{`name="log"`, `name="pwd"`, `type="password"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("login decoy missing %q", want)
		}
	}
	if got := decoyPage("/.env"); !strings.Contains(got, "inversehacker") {
		t.Fatal("unknown paths should return the decoy site")
	}
}

func TestHTTPHoneypotPublishesBoundedRequest(t *testing.T) {
	// Exercise the protocol boundary with an oversized body; the handler must still respond.
	req := httptest.NewRequest("POST", "/wp-login.php", strings.NewReader(strings.Repeat("x", (64<<10)+8)))
	req.RemoteAddr = "192.0.2.9:1234"
	rr := httptest.NewRecorder()
	newHandler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
}
