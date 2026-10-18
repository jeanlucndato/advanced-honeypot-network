package main

import (
	"fmt"
	"log"
	"os"

	"advance-honeypot-network/internal/api"
	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/httpd"
	"advance-honeypot-network/internal/mitre"
	"advance-honeypot-network/internal/mysqld"
	"advance-honeypot-network/internal/redisd"
	"advance-honeypot-network/internal/sshd"
	"advance-honeypot-network/internal/store"
)

func main() {
	fmt.Println("🚀 Advanced Honeypot Network - Hive Backend Initialized")
	apiPort := envOr("HIVE_API_PORT", "8000")
	httpPort := envOr("HIVE_HTTP_PORT", "8080")
	mysqlPort := envOr("HIVE_MYSQL_PORT", "3306")
	redisPort := envOr("HIVE_REDIS_PORT", "6379")
	sshPort := envOr("HIVE_SSH_PORT", "2222")
	eventLog := envOr("HIVE_EVENT_LOG", "data/events.jsonl")

	// Initialize the typed event bus and attach synchronous event enrichment.
	event.InitBus()
	if err := event.GlobalBus.ConfigureJournal(eventLog); err != nil {
		log.Fatalf("could not open event journal %q: %v", eventLog, err)
	}
	event.GlobalBus.SetEnricher(mitre.Enrich)

	// Démarrer les moteurs d'intelligence (en tâche de fond)
	mitre.StartEngine()
	store.StartThreatIntelProcessor()

	// Démarrer l'API REST et WebSockets (en tâche de fond)
	go api.StartServer(apiPort)

	// Démarrer les honeypots supplémentaires (en tâche de fond)
	go httpd.StartServer(httpPort)
	go mysqld.StartServer(mysqlPort)
	go redisd.StartServer(redisPort)

	// Lance le serveur SSH sur le port 2222 (bloquant, pour garder le programme ouvert)
	sshd.StartSSHServer(sshPort)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
