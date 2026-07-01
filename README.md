# Advanced Honeypot Network (Hive) 🐝🛡️

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev)
[![React Version](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active_Development-success.svg)]()

> **An enterprise-grade, event-driven cyber deception platform built for real-time threat intelligence gathering.**

**Hive** is a high-performance network honeypot designed to attract, deceive, and analyze cyber threats in real-time. Built from the ground up with **Go** for maximum concurrency and networking performance, and paired with a modern **React 19** frontend, it emulates vulnerable services to capture attacker behavior and automatically maps their actions to the **MITRE ATT&CK** framework.

---

## 🎯 Executive Summary (For Recruiters & Engineering Managers)

This project demonstrates proficiency in building scalable, asynchronous backend systems and modern frontend dashboards. Key engineering highlights include:

- **Event-Driven Architecture**: Implemented a highly concurrent, lock-free (where possible) Event Bus in Go using goroutines and channels to process thousands of attack events per second without dropping packets.
- **Low-Level Network Protocol Emulation**: Hand-crafted TCP listeners and protocol emulators (SSH, HTTP, MySQL, Redis) to simulate a realistic operating system environment, including a custom interactive pseudo-terminal (PTY) for SSH attackers.
- **Real-Time Data Streaming**: Engineered a WebSocket streaming pipeline to push real-time attack data from the Go backend directly to a React frontend with sub-millisecond latency.
- **Modern Full-Stack Expertise**: Showcases a strong understanding of both high-performance backend engineering (Go, Chi Router, Pub/Sub) and reactive frontend development (React 19, TypeScript, state management).
- **Cybersecurity & Threat Intelligence**: Deep integration with the MITRE ATT&CK matrix using sliding-window algorithms and pattern matching to categorize attacker TTPs (Tactics, Techniques, and Procedures).

---

## 🏗️ System Architecture

Hive relies on an asynchronous event-driven pipeline to ensure the simulated services are never blocked by data processing or database writes.

```text
                  ┌─────────────────────────────────────────────┐
  Attackers       │              Hive Backend (Go)              │
                  │                                             │
┌──────┐         │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
│ SSH  │────2222──│──│ sshd │  │ httpd│  │ ftpd │  │ smbd │   │
│Client│         │  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘   │
└──────┘         │     │         │         │         │        │
                 │  ┌──┴───┐  ┌──┴───┐                        │
                 │  │mysqld│  │redisd│                        │
                 │  └──┬───┘  └──┬───┘                        │
                 │     │         │                             │
                 │     ▼         ▼                             │
                 │  ┌─────────────────┐                        │
                 │  │    Event Bus    │  (Go Channels Pub/Sub) │
                 │  └────────┬────────┘                        │
                 │           │                                 │
                 │     ┌─────┴─────┐                           │
                 │     │ Processor │  (GeoIP Enrichment &      │
                 │     │  MITRE    │   ATT&CK Mapping)         │
                 │     │  Storage  │                           │
                 │     └───────────┘                           │
                 │                                             │
                 │  ┌─────────────────┐                        │
                 │  │   REST API      │  (go-chi Router)       │
                 │  │   WebSocket     │  /ws/events            │
                 │  └─────────────────┘                        │
                 └──────────────┬──────────────────────────────┘
                                │
                 ┌──────────────┴──────────────────┐
                 │    React 19 Dashboard (Vite)    │
                 │    Real-time Attack Stream      │
                 │    MITRE Heatmap • Export CTI   │
                 └─────────────────────────────────┘
```

---

## 🚀 Key Features

* **Multi-Service Emulation:** Intelligent simulation of SSH (fake interactive shell), HTTP (WordPress/phpMyAdmin traps), FTP, SMB, MySQL, and Redis.
* **Asynchronous Event Pipeline:** Centralized background processing using Go channels, decoupling the network listeners from the heavy analytics processing.
* **Live Threat Dashboard:** Watch attacks happen in real-time as the WebSocket stream pushes live JSON payloads straight to the React UI.
* **GeoIP & MITRE ATT&CK Mapping:** Instantly enriches IP addresses with geographical data and matches terminal commands to 27 distinct MITRE ATT&CK techniques.
* **Actionable CTI Export:** Automated extraction of Indicators of Compromise (IOCs) with STIX 2.1 formatting and firewall blocklist generation (iptables, Nginx).

---

## 💻 Quick Start (Developer Mode)

To run the platform locally and see the real-time event stream in action:

1. **Start the Go Backend & API:**
   ```bash
   cd advance-honeypot-network
   go run ./cmd/hive
   ```
   *The backend will start listening on port 2222 for SSH connections and port 8000 for the WebSocket API.*

2. **Start the React Dashboard:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   *Navigate to `http://localhost:5173` in your browser.*

3. **Simulate an Attack:**
   Open a new terminal window and connect to your own honeypot:
   ```bash
   ssh root@localhost -p 2222
   ```
   Type any password, then run commands like `ls`, `whoami`, or `pwd`. Watch the React dashboard light up with your real-time actions!

---

## 🗂️ Project Structure

```text
advance-honeypot-network/
├── cmd/hive/              # Go entry point (main binary)
├── pkg/types/             # Shared domain structures (Event, Session, IOC)
├── internal/
│   ├── sshd/              # SSH Honeypot (Custom PTY & auth bypass)
│   ├── httpd/             # HTTP Honeypot (Vulnerability traps)
│   ├── event/             # Concurrent Event Bus & Pub/Sub pipeline
│   ├── mitre/             # MITRE ATT&CK correlation engine
│   ├── store/             # PostgreSQL & Redis storage interfaces
│   └── api/               # REST API & WebSocket server
├── frontend/              # React 19 + TypeScript SPA
└── README.md              # Project documentation
```

---

## 🛡️ Legal Disclaimer

This tool is developed strictly for **educational purposes and security research**. Deploying honeypots on networks without explicit authorization from the network owner or cloud infrastructure provider is strictly prohibited and may violate local laws. The authors assume no liability for the misuse of this software.