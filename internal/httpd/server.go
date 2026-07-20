package httpd

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	mux := http.NewServeMux()

	// Capture All routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		
		payload := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		
		// Capture User-Agent
		if ua := r.Header.Get("User-Agent"); ua != "" {
			payload += fmt.Sprintf(" (UA: %s)", ua)
		}
		
		// Capture Body if POST
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				payload += fmt.Sprintf(" | Body: %s", string(body))
			}
		}

		// Detect if it's a known exploit attempt path
		eventType := "web_scan"
		if strings.Contains(r.URL.Path, "wp-login") || strings.Contains(r.URL.Path, "phpmyadmin") || strings.Contains(r.URL.Path, ".env") {
			eventType = "exploit_attempt"
		}

		event.GlobalBus.Publish(types.Event{
			AttackerIP: ip,
			Service:    "http",
			EventType:  eventType,
			Payload:    payload,
		})

		// Always return 200 OK with a fake generic response to keep them engaged
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>It works!</h1></body></html>"))
	})

	fmt.Printf("🕸️  HTTP Honeypot active on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
