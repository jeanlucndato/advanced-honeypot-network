package api

import (
	"encoding/json"
	"fmt"
	"log"
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
	server := &http.Server{Addr: addr, Handler: r, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to start API server: %v", err)
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
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: allowed})
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
