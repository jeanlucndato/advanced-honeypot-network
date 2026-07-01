package main

import (
	"advance-honeypot-network/internal/sshd"
	"fmt"
)

func main() {
	fmt.Println("🚀 Advanced Honeypot Network - Hive Backend Initialized")
	
	// Lance le serveur SSH sur le port 2222
	sshd.StartSSHServer("2222")
}
