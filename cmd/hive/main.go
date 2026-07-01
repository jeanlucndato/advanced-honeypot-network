package main

import (
	"advance-honeypot-network/internal/api"
	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sshd"
	"fmt"
)

func main() {
	fmt.Println("🚀 Advanced Honeypot Network - Hive Backend Initialized")
	
	// Initialize the global event bus
	event.InitBus()

	// Démarrer l'API REST et WebSockets (en tâche de fond)
	go api.StartServer("8000")

	// Lance le serveur SSH sur le port 2222 (bloquant)
	sshd.StartSSHServer("2222")
}
