package sshd

import (
	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sanitize"
	"advance-honeypot-network/internal/types"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	pathpkg "path"
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

	signer, err := loadOrCreateHostKey("data/ssh_host_ed25519")
	if err != nil {
		log.Fatalf("Could not load or create SSH host key: %v", err)
	}
	config.AddHostKey(signer)

	addr := os.Getenv("HIVE_SSH_ADDR")
	if addr == "" {
		addr = "127.0.0.1:" + port
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

func loadOrCreateHostKey(filename string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(filename)
	if err == nil {
		return ssh.ParsePrivateKey(keyData)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}

	if err := os.MkdirAll(pathpkg.Dir(filename), 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode Ed25519 key: %w", err)
	}
	keyData = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("save %s: %w", filename, err)
		}
		// Another Hive process may have created the key at the same time.
		keyData, err = os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read concurrently created %s: %w", filename, err)
		}
		return ssh.ParsePrivateKey(keyData)
	}
	if _, err := keyFile.Write(keyData); err != nil {
		_ = keyFile.Close()
		return nil, fmt.Errorf("write %s: %w", filename, err)
	}
	if err := keyFile.Close(); err != nil {
		return nil, fmt.Errorf("close %s: %w", filename, err)
	}
	return ssh.NewSignerFromKey(privateKey)
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
	cwd := "/root"
	writePrompt := func() {
		shownPath := cwd
		if shownPath == "/root" {
			shownPath = "~"
		} else if strings.HasPrefix(shownPath, "/root/") {
			shownPath = "~" + strings.TrimPrefix(shownPath, "/root")
		}
		_, _ = io.WriteString(channel, fmt.Sprintf("root@ubuntu:%s# ", shownPath))
	}
	writePrompt()

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

					output, shouldExit := fakeCommand(cmd, &cwd)
					if shouldExit {
						io.WriteString(channel, "logout\n")
						return
					}
					_, _ = io.WriteString(channel, output)
				}

				currentCmd = ""
				writePrompt()
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

// fakeCommand only returns canned responses. It never launches a process or
// accesses the host filesystem, even when the submitted command contains shell syntax.
func fakeCommand(command string, cwd *string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", false
	}
	verb := fields[0]
	arg := ""
	if len(fields) > 1 {
		arg = fields[len(fields)-1]
	}
	switch verb {
	case "exit", "logout":
		return "", true
	case "whoami":
		return "root\n", false
	case "pwd":
		return *cwd + "\n", false
	case "cd":
		destination := "/root"
		if len(fields) > 1 && fields[1] != "~" {
			if strings.HasPrefix(fields[1], "/") {
				destination = pathpkg.Clean(fields[1])
			} else {
				destination = pathpkg.Clean(pathpkg.Join(*cwd, fields[1]))
			}
		}
		if destination != "/root" && !strings.HasPrefix(destination, "/root/") && destination != "/var/www/html" && !strings.HasPrefix(destination, "/var/www/html/") {
			return fmt.Sprintf("bash: cd: %s: No such file or directory\n", fields[len(fields)-1]), false
		}
		*cwd = destination
		return "", false
	case "ls":
		if strings.Contains(command, "-l") || strings.Contains(command, "-a") {
			return "total 32\ndrwx------ 1 root root 4096 Oct 18 09:12 .\ndrwxr-xr-x 1 root root 4096 Oct 18 09:12 ..\n-rw------- 1 root root  188 Oct 18 09:15 .bash_history\n-rw-r--r-- 1 root root  220 Oct 18 09:12 .bash_logout\n-rw-r--r-- 1 root root 3771 Oct 18 09:12 .bashrc\ndrwxr-xr-x 2 root root 4096 Oct 18 09:12 backups\n-rw-r--r-- 1 root root  183 Oct 18 09:12 config.json\n-rw-r--r-- 1 root root   18 Oct 18 09:12 data.txt\n", false
		}
		if *cwd == "/var/www/html" {
			return "index.html  index.php  uploads\n", false
		}
		return "backups  config.json  data.txt\n", false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n", false
	case "groups":
		return "root\n", false
	case "uname":
		return "Linux ubuntu 5.15.0-87-generic #97-Ubuntu SMP x86_64 GNU/Linux\n", false
	case "hostname":
		return "ubuntu\n", false
	case "date":
		return time.Now().UTC().Format("Mon Jan 2 15:04:05 UTC 2006\n"), false
	case "cat", "less", "more", "head", "tail":
		content, ok := fakeFile(arg)
		if !ok {
			return fmt.Sprintf("%s: %s: No such file or directory\n", verb, arg), false
		}
		return content, false
	case "clear":
		return "\033[2J\033[H", false
	case "echo":
		return strings.TrimSpace(strings.TrimPrefix(command, "echo")) + "\n", false
	case "ps":
		return "    PID TTY          TIME CMD\n      1 ?        00:00:03 systemd\n    642 ?        00:00:01 sshd\n    811 ?        00:00:00 nginx\n   1042 pts/0    00:00:00 bash\n   1078 pts/0    00:00:00 ps\n", false
	case "top":
		return "top - 09:15:22 up 12 days,  4:31,  1 user,  load average: 0.08, 0.11, 0.09\nTasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n%Cpu(s):  2.1 us,  1.0 sy, 96.4 id\nMiB Mem :   3924.0 total,   1821.0 free,   1402.0 used\n", false
	case "free":
		return "               total        used        free      shared  buff/cache   available\nMem:         4018176     1435648     1864704       12480      718824     2352128\nSwap:              0           0           0\n", false
	case "df":
		return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/vda1       20511356 6242812  13200944  33% /\ntmpfs             401816       0    401816   0% /dev/shm\n", false
	case "uptime":
		return " 09:15:22 up 12 days,  4:31,  1 user,  load average: 0.08, 0.11, 0.09\n", false
	case "ip":
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n", false
	case "ifconfig":
		return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\nlo:   flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n", false
	case "ss", "netstat":
		return "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*     users:((\"sshd\",pid=642,fd=3))\ntcp   LISTEN 0      511    0.0.0.0:80      0.0.0.0:*     users:((\"nginx\",pid=811,fd=6))\n", false
	case "who", "w":
		return " 09:15:22 up 12 days,  4:31,  1 user,  load average: 0.08, 0.11, 0.09\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.0.2.10       09:14    0.00s  0.02s  0.00s w\n", false
	case "history":
		return "    1  whoami\n    2  pwd\n    3  ls -la\n", false
	case "systemctl", "service":
		return "● nginx.service - A high performance web server\n     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n     Active: active (running) since Mon 2026-10-05 04:42:18 UTC\n", false
	case "docker":
		return "CONTAINER ID   IMAGE          COMMAND                  STATUS        PORTS                 NAMES\n9c12ab73d221   nginx:1.24    \"/docker-entrypoint…\"   Up 12 days    0.0.0.0:80->80/tcp    web\n", false
	case "which":
		if len(fields) > 1 {
			return "/usr/bin/" + fields[len(fields)-1] + "\n", false
		}
		return "", false
	case "help":
		return "Available commands: cat cd clear date df echo free hostname id ip ls pwd ps whoami uname uptime\n", false
	default:
		return fmt.Sprintf("bash: %s: command not found\n", command), false
	}
}

func fakeFile(name string) (string, bool) {
	switch name {
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", true
	case "/etc/hostname":
		return "ubuntu\n", true
	case "/etc/os-release":
		return "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\n", true
	case "/etc/issue":
		return "Ubuntu 22.04.3 LTS \\n \\l\n", true
	case "/root/config.json", "config.json":
		return "{\n  \"app\": \"web-portal\",\n  \"environment\": \"production\",\n  \"database_host\": \"db.internal\",\n  \"debug\": false\n}\n", true
	case "/root/data.txt", "data.txt":
		return "backup completed\n", true
	case "/var/www/html/index.php":
		return "<?php\nrequire_once 'config.php';\n// Portal home page\necho 'Welcome';\n", true
	case "/var/www/html/index.html":
		return "<!doctype html><title>Company Portal</title><h1>Welcome</h1>\n", true
	case "/root/.bash_history":
		return "whoami\npwd\nls -la\n", true
	default:
		return "", false
	}
}
