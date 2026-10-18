package sshd

import (
	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sanitize"
	"advance-honeypot-network/internal/types"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func remotePort(addr net.Addr) string {
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return port
}

func StartSSHServer(port string) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			event.GlobalBus.Publish(types.Event{
				AttackerIP:   remoteIP(c.RemoteAddr()),
				AttackerPort: remotePort(c.RemoteAddr()),
				Service:      "ssh",
				EventType:    "auth_attempt",
				Username:     c.User(),
				Payload:      "Password authentication attempt (credential redacted)",
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

	addr := os.Getenv("HIVE_SSH_ADDR")
	if addr == "" {
		addr = "0.0.0.0:" + port
	}
	listener, err := net.Listen("tcp", addr)
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

		go func() {
			defer channel.Close()
			shellStarted := false
			for req := range requests {
				switch req.Type {
				case "pty":
					req.Reply(true, nil)
				case "shell":
					req.Reply(!shellStarted, nil)
					if !shellStarted {
						shellStarted = true
						runFakeShell(channel, sshConn)
						return
					}
				case "exec":
					// Record submitted commands without running them on the host.
					var command string
					if err := ssh.Unmarshal(req.Payload, &command); err == nil && command != "" {
						event.GlobalBus.Publish(types.Event{AttackerIP: remoteIP(sshConn.RemoteAddr()), AttackerPort: remotePort(sshConn.RemoteAddr()), Service: "ssh", EventType: "command_exec", Username: sshConn.User(), Payload: sanitize.Redact(command)})
					}
					req.Reply(false, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}()
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
						AttackerIP:   remoteIP(sshConn.RemoteAddr()),
						AttackerPort: remotePort(sshConn.RemoteAddr()),
						Service:      "ssh",
						EventType:    "command_exec",
						Username:     sshConn.User(),
						Payload:      sanitize.Redact(cmd),
					})

					// Traitement des fausses commandes
					fields := strings.Fields(cmd)
					verb := ""
					if len(fields) > 0 {
						verb = fields[0]
					}
					switch verb {
					case "exit", "logout":
						io.WriteString(channel, "logout\n")
						return
					case "whoami":
						io.WriteString(channel, "root\n")
					case "pwd":
						io.WriteString(channel, "/root\n")
					case "ls":
						if strings.Contains(cmd, "-l") || strings.Contains(cmd, "-a") {
							io.WriteString(channel, "total 24\ndrwx------ 1 root root 4096 Oct 18 09:12 .\ndrwxr-xr-x 1 root root 4096 Oct 18 09:12 ..\n-rw-r--r-- 1 root root  220 .bash_logout\n-rw-r--r-- 1 root root 3771 .bashrc\ndrwxr-xr-x 2 root root 4096 backups\n-rw-r--r-- 1 root root  183 config.json\n-rw-r--r-- 1 root root   18 data.txt\n")
						} else {
							io.WriteString(channel, "backups  config.json  data.txt\n")
						}
					case "id":
						io.WriteString(channel, "uid=0(root) gid=0(root) groups=0(root)\n")
					case "uname":
						io.WriteString(channel, "Linux ubuntu 5.15.0-87-generic #97-Ubuntu SMP x86_64 GNU/Linux\n")
					case "hostname":
						io.WriteString(channel, "ubuntu\n")
					case "date":
						io.WriteString(channel, time.Now().UTC().Format("Mon Jan 2 15:04:05 UTC 2006\n"))
					case "cat":
						if len(fields) > 1 && fields[1] == "/etc/passwd" {
							io.WriteString(channel, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
						} else {
							io.WriteString(channel, "cat: file not found\n")
						}
					case "clear":
						io.WriteString(channel, "\033[2J\033[H")
					case "echo":
						io.WriteString(channel, strings.TrimSpace(strings.TrimPrefix(cmd, "echo"))+"\n")
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
				if len(currentCmd) < 8192 {
					currentCmd += string(b)
				}
				channel.Write([]byte{b}) // Écho du caractère pour que l'attaquant voie ce qu'il tape
			}
		}
	}
}
