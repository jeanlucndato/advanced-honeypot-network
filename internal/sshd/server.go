package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"golang.org/x/crypto/ssh"
	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/pkg/types"
)

func StartSSHServer(port string) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			event.GlobalBus.Publish(types.Event{
				AttackerIP: c.RemoteAddr().String(),
				Service:    "ssh",
				EventType:  "auth_attempt",
				Username:   c.User(),
				Payload:    string(pass),
			})
			// Accept all passwords to let them into the honeypot
			return nil, nil
		},
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("Génération de clé échouée: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("Impossible d'écouter sur le port %s: %v", port, err)
	}
	fmt.Printf("🛡️  Hive SSH Honeypot actif avec Shell sur le port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
			if err != nil {
				return
			}
			// Rejeter les requêtes globales hors canaux
			go ssh.DiscardRequests(reqs)
			// Gérer les canaux entrants (les demandes de session shell)
			handleChannels(sshConn, chans)
		}(conn)
	}
}

func handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		// On ne gère que les demandes de type "session" (le terminal standard)
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		// Gérer les requêtes à l'intérieur de la session (comme la demande de shell)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell", "pty":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)

		// Lancer notre faux terminal interactif pour cet attaquant
		go runFakeShell(channel, sshConn)
	}
}

func runFakeShell(channel ssh.Channel, sshConn *ssh.ServerConn) {
	defer channel.Close()

	// Message de bienvenue classique pour faire croire à un vrai serveur Linux
	io.WriteString(channel, "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-87-generic x86_64)\n\n")
	
	// Prompt initial (ex: root@ubuntu:~# )
	prompt := fmt.Sprintf("root@ubuntu:~# ")
	io.WriteString(channel, prompt)

	buf := make([]byte, 1024)
	var currentCmd string

	for {
		n, err := channel.Read(buf)
		if err != nil {
			break // L'attaquant a fermé la connexion
		}

		data := buf[:n]
		
		// Gestion basique du comportement du terminal (touche Entrée, etc.)
		for _, b := range data {
			if b == '\r' || b == '\n' { // L'attaquant valide sa commande
				io.WriteString(channel, "\n")
				cmd := strings.TrimSpace(currentCmd)
				
				if cmd != "" {
					// LOG DE LA COMMANDE EXÉCUTÉE
					event.GlobalBus.Publish(types.Event{
						AttackerIP: sshConn.RemoteAddr().String(),
						Service:    "ssh",
						EventType:  "command_exec",
						Username:   sshConn.User(),
						Payload:    cmd,
					})
					
					// Traitement des fausses commandes
					switch cmd {
					case "exit":
						io.WriteString(channel, "logout\n")
						return
					case "whoami":
						io.WriteString(channel, "root\n")
					case "pwd":
						io.WriteString(channel, "/root\n")
					case "ls":
						io.WriteString(channel, "data.txt  backups  config.json\n")
					case "id":
						io.WriteString(channel, "uid=0(root) gid=0(root) groups=0(root)\n")
					default:
						// Réponse générique si la commande n'est pas émulée
						io.WriteString(channel, fmt.Sprintf("bash: %s: command not found\n", cmd))
					}
				}
				
				currentCmd = ""
				io.WriteString(channel, prompt)
			} else if b == 127 { // Gestion rudimentaire de la touche Retour arrière (Backspace)
				if len(currentCmd) > 0 {
					currentCmd = currentCmd[:len(currentCmd)-1]
					channel.Write([]byte{'\b', ' ', '\b'})
				}
			} else {
				currentCmd += string(b)
				channel.Write([]byte{b}) // Écho du caractère pour que l'attaquant voie ce qu'il tape
			}
		}
	}
}
