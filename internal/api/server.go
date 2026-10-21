package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"advance-honeypot-network/internal/event"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

func StartServer(port string) {
	r := chi.NewRouter()
	token := strings.TrimSpace(os.Getenv("HIVE_API_TOKEN"))

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	origins := []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	if configured := os.Getenv("HIVE_ALLOWED_ORIGINS"); configured != "" {
		origins = strings.Split(configured, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
	}))
	// A configured token protects both HTTP APIs and the live event stream.
	if token != "" {
		r.Use(tokenAuth(token))
	}

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "ok",
			"sensor_id": event.GlobalBus.SensorID(),
		})
	})
	r.Get("/api/events", func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}
		if limit > 500 {
			limit = 500
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(event.GlobalBus.Recent(limit))
	})
	r.Get("/api/search", func(w http.ResponseWriter, r *http.Request) {
		limit, offset := 100, 0
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
			limit = n
		}
		if limit > 500 {
			limit = 500
		}
		if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n > 0 {
			offset = n
		}
		items, total, err := event.GlobalBus.Search(r.URL.Query().Get("q"), r.URL.Query().Get("service"), limit, offset)
		if err != nil {
			http.Error(w, "event search failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"events": items, "total": total, "limit": limit, "offset": offset})
	})
	r.Get("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		clients, dropped, journalErrors := event.GlobalBus.Stats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"subscribers": clients, "dropped_events": dropped, "journal_errors": journalErrors})
	})

	r.Get("/ws/events", handleWebSocket)

	fmt.Printf("🌐 Hive API/WebSocket active on port %s...\n", port)
	addr := os.Getenv("HIVE_API_ADDR")
	if addr == "" {
		addr = "127.0.0.1:" + port
	}
	if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil && token == "" {
		ip := net.ParseIP(host)
		if host == "0.0.0.0" || host == "::" || ip == nil || !ip.IsLoopback() {
			log.Fatal("HIVE_API_TOKEN is required when HIVE_API_ADDR is not loopback")
		}
	}
	server := &http.Server{Addr: addr, Handler: r, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to start API server: %v", err)
	}
}

func websocketProtocols(value string) []string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func tokenAuth(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			supplied := req.Header.Get("Authorization") == "Bearer "+token
			if req.URL.Path == "/ws/events" {
				for _, protocol := range websocketProtocols(req.Header.Get("Sec-WebSocket-Protocol")) {
					if protocol == "hive-auth."+token {
						supplied = true
					}
				}
			}
			if !supplied {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	allowed := []string{"localhost:5173", "127.0.0.1:5173"}
	if configured := os.Getenv("HIVE_ALLOWED_ORIGINS"); configured != "" {
		allowed = strings.Split(configured, ",")
		for i := range allowed {
			allowed[i] = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(allowed[i], "http://"), "https://"))
		}
	}
	protocols := []string{}
	if token := strings.TrimSpace(os.Getenv("HIVE_API_TOKEN")); token != "" {
		protocols = append(protocols, "hive-auth."+token)
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: allowed, Subprotocols: protocols})
	if err != nil {
		log.Printf("WebSocket Accept error: %v", err)
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	log.Printf("WebSocket client connected: %v", r.RemoteAddr)

	subChan := event.GlobalBus.Subscribe(256)
	defer event.GlobalBus.Unsubscribe(subChan)
	disconnected := make(chan struct{})
	go func() {
		defer close(disconnected)
		_, _, _ = c.Read(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-disconnected:
			return
		case e, ok := <-subChan:
			if !ok {
				return
			}
			err = wsjson.Write(ctx, c, e)
			if err != nil {
				log.Printf("WebSocket Write error: %v", err)
				return
			}
		}
	}
}
