# Hive — Honeypot Network

Hive is a Go-based multi-service honeypot with a React operations dashboard. It accepts connections on SSH, HTTP, MySQL, and Redis decoys, normalizes observed activity into events, adds heuristic MITRE ATT&CK tags, writes IP intelligence suggestions, and streams events to the browser.

> **Deployment boundary:** Hive is an interactive sensor, not a production SSH, web, MySQL, or Redis server. Run it on a dedicated, isolated host or VM you control. Do not give it access to production credentials, internal services, container sockets, or sensitive file shares. The fake SSH shell never executes submitted commands. Generated firewall rules are suggestions and are never applied automatically.

## Requirements

- Go 1.26.4 or later
- Node.js 20.19+ or 22.12+, with npm (Vite 8 requirement)

## Start Hive locally

Open a terminal at the repository root and start the backend:

```sh
go run ./cmd/hive
```

The SSH, HTTP, MySQL, and Redis listeners bind to all interfaces by default. The API binds to `127.0.0.1:8000` by default. For a local demo, this keeps the dashboard API off the network while the decoy services are reachable on the host. Before running on an internet-facing system, configure host-level firewall rules and deploy on an isolated sensor host.

Open a second terminal and launch the dashboard:

```sh
cd frontend
npm ci
npm run dev
```

Open the URL printed by Vite, normally `http://localhost:5173`. The dashboard loads recent events from the local journal through the API and then receives new events over WebSocket.

### Generate safe sample activity

In another terminal, use local requests to trigger example events:

```sh
curl -i http://127.0.0.1:8080/wp-login.php
redis-cli -h 127.0.0.1 -p 6379 PING
mysql --protocol=TCP -h 127.0.0.1 -P 3306 -u demo
ssh -p 2222 root@127.0.0.1
```

Any password entered in the SSH or MySQL decoy is discarded. The SSH shell records commands and returns a small set of canned responses; it does not execute shell commands on the host. For a quick browser/API check, use `curl http://127.0.0.1:8000/api/health` and `curl http://127.0.0.1:8000/api/events?limit=20`.

## Configuration

Set environment variables before starting `go run ./cmd/hive`:

| Variable | Default | Purpose |
|---|---:|---|
| `HIVE_SSH_PORT` | `2222` | SSH decoy port |
| `HIVE_HTTP_PORT` | `8080` | HTTP decoy port |
| `HIVE_MYSQL_PORT` | `3306` | MySQL decoy port |
| `HIVE_REDIS_PORT` | `6379` | Redis decoy port |
| `HIVE_API_PORT` | `8000` | API port used when `HIVE_API_ADDR` is unset |
| `HIVE_SENSOR_ID` | `hive-01` | Sensor identifier attached to events and health responses |
| `HIVE_EVENT_LOG` | `data/events.jsonl` | Append-only event journal; retains the active file and one rotated backup (64 MiB each) |
| `HIVE_SSH_ADDR` | `0.0.0.0:<port>` | SSH bind address |
| `HIVE_HTTP_ADDR` | `:<port>` | HTTP bind address |
| `HIVE_MYSQL_ADDR` | `:<port>` | MySQL bind address |
| `HIVE_REDIS_ADDR` | `:<port>` | Redis bind address |
| `HIVE_API_ADDR` | `127.0.0.1:<port>` | API bind address; set to a private interface address to allow a remote dashboard |
| `HIVE_ALLOWED_ORIGINS` | localhost Vite origins | Comma-separated browser origins allowed by HTTP CORS and WebSocket checks |
| `VITE_WS_URL` | `ws(s)://<dashboard-host>:8000/ws/events` | Optional dashboard WebSocket URL, set when starting Vite |

Example: bind decoys to all interfaces while keeping the API private on a LAN address:

```sh
HIVE_API_ADDR=192.168.1.20:8000 HIVE_ALLOWED_ORIGINS=http://192.168.1.20:5173 go run ./cmd/hive
```

For a remote dashboard, allow only its exact origin and protect the API behind a trusted reverse proxy or private network. The API does not implement user authentication; do not expose it directly to an untrusted network.

## How the system works

1. `cmd/hive` initializes one typed event bus, installs the MITRE enrichment hook, and starts the four honeypot listeners, the API, and the threat-intelligence subscriber.
2. Each decoy records an interaction as an event. Common fields include a UTC timestamp, sensor ID, source IP and port, service, event type, and observed payload. Authentication passwords are not stored.
3. The event bus assigns IDs, applies heuristic ATT&CK tags, appends events to a local JSONL journal, keeps the newest 1,000 events in process memory, and fans out to subscribers using bounded queues. On restart, the dashboard history window reloads from the journal. Slow subscribers can miss live events; the API reports total queue drops and journal errors in `/api/metrics`.
4. The dashboard fetches up to 100 recent events, listens for new WebSocket events, reconnects with backoff, and retains up to 500 events in browser memory. Search and service filters operate on the events currently loaded in the browser.
5. The threat-intelligence processor deduplicates valid source IPs and writes suggested `iptables`/`ip6tables` DROP commands plus STIX 2.1 indicators to files in the backend working directory. It never executes those rules.

### Decoy behavior and limits

- **SSH:** accepts password attempts into a fake Ubuntu-style shell, records usernames and submitted commands, and supports a few canned command responses. SSH `exec` requests are recorded but rejected. Passwords are discarded, and common password/token command-line flags are redacted from captured commands. The SSH host key is generated at startup, so its fingerprint changes after a restart.
- **HTTP:** records method, path, user agent, and up to 64 KiB of a non-GET request body. Common password, token, secret, authorization, and API-key fields are redacted. This is best-effort text redaction, not a guarantee that all secrets or personal data are removed. Every request receives a generic HTML decoy page.
- **MySQL:** sends a minimal MySQL handshake, parses a bounded login packet to capture the attempted username, then returns access denied. It does not store the password response and does not implement SQL sessions.
- **Redis:** parses simple inline commands and RESP arrays of bulk strings with bounded element and payload sizes. It returns plausible minimal replies for common commands such as `PING`, `INFO`, and `CONFIG GET`, and records commands. Values supplied to `AUTH`, `CONFIG SET requirepass`, and common secret assignments are redacted. It is not a Redis-compatible database.

MITRE ATT&CK tags are keyword and event-type heuristics. Country fields and GeoIP lookup are not implemented. Credential redaction is best-effort; captured data should still be treated as sensitive. These tags and source-IP indicators are investigative hints, not proof that an IP is malicious.

## API

- `GET /api/health` — process health response.
- `GET /api/events?limit=100` — newest in-memory events, newest first; maximum 500.
- `GET /api/metrics` — current subscriber count and cumulative dropped event count.
- `GET /ws/events` — WebSocket stream of new events.

The event journal is local JSONL, not a database: it has no indexed search and rotates at 64 MiB, keeping the active file and one previous file. The dashboard only loads the latest 100 events at startup; it does not offer pagination or historical search. The API currently has no authentication.

## Output files

- `iptables-blocklist.txt` contains suggested firewall commands. Review and adapt every entry before use; never pipe this file directly to a shell.
- `threat-intel.stix.json` contains generated STIX 2.1 indicator objects. Back up existing files before changing or migrating them.

The event journal and intelligence files are written relative to the backend's current working directory unless `HIVE_EVENT_LOG` is an absolute path. Run the backend from a dedicated writable data directory if you want to keep generated files separate from the source checkout.

## Development commands

```sh
go build ./cmd/hive
go test ./...
```

For the dashboard:

```sh
cd frontend
npm run build
npm run lint
```

## Production-readiness checklist

Before operating beyond a lab, use an isolated VM or host, restrict inbound and outbound network access, protect the management/dashboard path with authentication at a trusted proxy, configure log retention and backups, monitor disk and resource use, and review privacy and legal requirements for the data you collect. Hive currently has no durable event database, authenticated API, GeoIP service, or complete protocol implementations; it is a development-stage honeypot, not a turnkey production SOC platform.
