package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
	}))

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "ok",
			"sensor_id": "hive-01",
		})
	})

	r.Get("/ws/events", handleWebSocket)

	fmt.Printf("🌐 Hive API/WebSocket active on port %s...\n", port)
	err := http.ListenAndServe(":"+port, r)
	if err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow all origins for dev
	})
	if err != nil {
		log.Printf("WebSocket Accept error: %v", err)
		return
	}
	defer c.CloseNow()

	ctx := r.Context()
	log.Printf("WebSocket client connected: %v", r.RemoteAddr)

	// In a real app, we would register to the EventBus pubsub.
	// For this prototype, we'll poll or hook into a channel.
	// Since EventBus currently doesn't support multiple subscribers,
	// let's create a hacky way to distribute events, or simply
	// we will create a dedicated channel for this connection.
	
	// Quick hack for dev: subscribe to a new channel from a global broadcaster
	subChan := make(chan interface{}, 10)
	event.RegisterSubscriber(subChan)
	defer event.UnregisterSubscriber(subChan)

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-subChan:
			err = wsjson.Write(ctx, c, e)
			if err != nil {
				log.Printf("WebSocket Write error: %v", err)
				return
			}
		}
	}
}
