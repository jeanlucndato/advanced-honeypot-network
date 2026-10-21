package httpd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"advance-honeypot-network/internal/event"
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
	landing := decoyPage("/")
	for _, want := range []string{`id="site-navigation"`, `class="menu-toggle"`, `href="#contact"`, `id="contact-form"`, `fetch("/__hive/contact"`, `sendBeacon("/__hive/click"`} {
		if !strings.Contains(landing, want) {
			t.Fatalf("landing page is missing working interaction %q", want)
		}
	}
}

func TestHTTPHoneypotPublishesBoundedRequest(t *testing.T) {
	// Exercise the protocol boundary with an oversized body; the handler must still respond.
	req := httptest.NewRequest("POST", "/wp-login.php", strings.NewReader(strings.Repeat("x", (64<<10)+8)))
	req.RemoteAddr = "192.0.2.9:1234"
	rr := httptest.NewRecorder()
	event.InitBus()
	sub := event.GlobalBus.Subscribe(1)
	defer event.GlobalBus.Unsubscribe(sub)
	newHandler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	select {
	case observed := <-sub:
		if len(observed.Payload) > (64<<10)+256 {
			t.Fatalf("oversized event payload: %d bytes", len(observed.Payload))
		}
	default:
		t.Fatal("request did not publish an event")
	}
}

func TestDecoyLinkAndContactInteractionsArePublishedSafely(t *testing.T) {
	event.InitBus()
	sub := event.GlobalBus.Subscribe(2)
	defer event.GlobalBus.Unsubscribe(sub)
	handler := newHandler()

	click := httptest.NewRequest(http.MethodPost, "/__hive/click", strings.NewReader(`{"target":"/#approach"}`))
	click.Header.Set("Content-Type", "application/json")
	click.RemoteAddr = "192.0.2.10:4321"
	clickResponse := httptest.NewRecorder()
	handler.ServeHTTP(clickResponse, click)
	if clickResponse.Code != http.StatusNoContent {
		t.Fatalf("click status=%d", clickResponse.Code)
	}
	if got := <-sub; got.EventType != "link_click" || !strings.Contains(got.Payload, "#approach") {
		t.Fatalf("click event=%+v", got)
	}

	form := httptest.NewRequest(http.MethodPost, "/__hive/contact", strings.NewReader(`{"name":"A Person","email":"person@example.test","message":"private details"}`))
	form.Header.Set("Content-Type", "application/json")
	form.RemoteAddr = "192.0.2.10:4321"
	formResponse := httptest.NewRecorder()
	handler.ServeHTTP(formResponse, form)
	if formResponse.Code != http.StatusAccepted {
		t.Fatalf("form status=%d body=%s", formResponse.Code, formResponse.Body.String())
	}
	if got := <-sub; got.EventType != "form_submit" || strings.Contains(got.Payload, "person@example.test") || strings.Contains(got.Payload, "private details") {
		t.Fatalf("form event retained submitted data: %+v", got)
	}
}
