package main

import (
	"fmt"
	
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
	
	// Initialize the global event bus (100% Lock-Free)
	event.InitBus()

	// Démarrer les moteurs d'intelligence (en tâche de fond)
	mitre.StartEngine()
	store.StartThreatIntelProcessor()

	// Démarrer l'API REST et WebSockets (en tâche de fond)
	go api.StartServer("8000")

	// Démarrer les honeypots supplémentaires (en tâche de fond)
	go httpd.StartServer("8080")
	go mysqld.StartServer("3306")
	go redisd.StartServer("6379")

	// Lance le serveur SSH sur le port 2222 (bloquant, pour garder le programme ouvert)
	sshd.StartSSHServer("2222")
}
