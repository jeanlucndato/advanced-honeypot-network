package httpd

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sanitize"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	mux := http.NewServeMux()

	// Capture All routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, sourcePort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		requestPath := r.URL.Path
		if r.URL.RawQuery != "" {
			requestPath += "?" + r.URL.RawQuery
		}
		payload := sanitize.Redact(fmt.Sprintf("%s %s", r.Method, requestPath))

		// Capture User-Agent
		if ua := r.Header.Get("User-Agent"); ua != "" {
			payload += fmt.Sprintf(" (UA: %s)", ua)
		}

		// Capture Body if POST
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				payload += fmt.Sprintf(" | Body: %s", sanitize.Redact(string(body)))
			}
		}

		// Detect if it's a known exploit attempt path
		eventType := "web_scan"
		if strings.Contains(r.URL.Path, "wp-login") || strings.Contains(r.URL.Path, "phpmyadmin") || strings.Contains(r.URL.Path, ".env") {
			eventType = "exploit_attempt"
		}

		event.GlobalBus.Publish(types.Event{
			AttackerIP:   ip,
			AttackerPort: sourcePort,
			Service:      "http",
			EventType:    eventType,
			Payload:      payload,
		})

		// Always return 200 OK with a fake generic response to keep them engaged
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, decoyPage(r.URL.Path))
	})

	fmt.Printf("🕸️  HTTP Honeypot active on port %s...\n", port)
	addr := ":" + port
	if configured := os.Getenv("HIVE_HTTP_ADDR"); configured != "" {
		addr = configured
	}
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func decoyPage(path string) string {
	if strings.HasSuffix(strings.ToLower(path), "/wp-login.php") || strings.EqualFold(path, "/wp-login.php") {
		return `<!doctype html><html><head><title>Log In &lsaquo; WordPress</title></head><body><main><h1>WordPress</h1><form method="post" action="/wp-login.php"><label>Username or Email Address<input name="log" autocomplete="username"></label><label>Password<input type="password" name="pwd" autocomplete="current-password"></label><button type="submit">Log In</button><input type="hidden" name="redirect_to" value="/wp-admin/"></form></main></body></html>`
	}
	return `<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>`
}
