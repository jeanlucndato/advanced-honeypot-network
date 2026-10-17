import { useEffect, useState } from 'react';
import { Terminal, Shield, Activity, ShieldAlert, Globe } from 'lucide-react';
import './App.css';

interface Event {
  id: string;
  timestamp: string;
  attacker_ip: string;
  service: string;
  event_type: string;
  payload: string;
  username?: string;
  country_code: string;
  country_name: string;
  mitre_techniques?: string[];
}

function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let socket: WebSocket | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let retryDelay = 1000;
    const connect = () => {
      if (stopped) return;
      const address = import.meta.env.VITE_WS_URL ?? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.hostname}:8000/ws/events`;
      socket = new WebSocket(address);
      socket.onopen = () => { retryDelay = 1000; setConnected(true); };
      socket.onmessage = (msg) => {
        try {
          const e: Event = JSON.parse(msg.data);
          setEvents((prev) => [e, ...prev].slice(0, 100));
        } catch (err) { console.error('Failed to parse event', err); }
      };
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) {
          reconnectTimer = setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, 30000);
        }
      };
      socket.onerror = () => socket?.close();
    };
    connect();
    return () => { stopped = true; if (reconnectTimer) clearTimeout(reconnectTimer); socket?.close(); };
  }, []);

  const getEventTypeClass = (type: string) => {
    const lower = type.toLowerCase();
    if (lower.includes('fail') || lower.includes('error')) return 'type-warning';
    if (lower.includes('success') || lower.includes('exec') || lower.includes('exploit')) return 'type-critical';
    return 'type-badge';
  };

  const getServiceClass = (service: string) => {
    const s = service.toLowerCase();
    if (s === 'ssh') return 'service-ssh';
    if (s === 'http' || s === 'web') return 'service-http';
    if (s === 'mysql' || s === 'db') return 'service-mysql';
    return 'service-default';
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <Shield className="header-icon" />
        <h1>HIVE // COMMAND CENTER</h1>
        <div className={`status-badge ${connected ? 'status-online' : 'status-offline'}`}>
          {connected ? 'SYSTEM SECURE: LIVE FEED ACTIVE' : 'SYSTEM OFFLINE: CONNECTION LOST'}
        </div>
      </header>

      <main className="dashboard-main">
        <div className="card">
          <div className="card-header">
            <Activity className="card-icon" />
            <h2>REAL-TIME THREAT TELEMETRY</h2>
          </div>
          
          <div className="events-table-wrapper">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Target Service</th>
                  <th>Source IP</th>
                  <th>Attack Vector</th>
                  <th>Identity</th>
                  <th>Payload / Command</th>
                  <th>MITRE ATT&amp;CK</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      <ShieldAlert className="empty-state-icon" />
                      <div>No malicious activity detected. Monitoring all vectors.</div>
                    </td>
                  </tr>
                ) : (
                  events.map((e, idx) => (
                    <tr key={e.id || idx}>
                      <td className="time-cell">{new Date(e.timestamp).toLocaleTimeString()}</td>
                      <td>
                        <span className={`service-badge ${getServiceClass(e.service)}`}>{e.service.toUpperCase()}</span>
                      </td>
                      <td className="ip-cell">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Globe size={14} style={{ color: 'var(--text-secondary)' }} />
                          {e.attacker_ip}
                        </div>
                      </td>
                      <td>
                        <span className={`type-badge ${getEventTypeClass(e.event_type)}`}>
                          {e.event_type.replace(/_/g, ' ').toUpperCase()}
                        </span>
                      </td>
                      <td style={{ color: e.username ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                        {e.username || 'UNKNOWN'}
                      </td>
                      <td className="payload-cell">
                        {e.event_type === 'command_exec' ? (
                          <span className="command-text">
                            <Terminal size={14} className="cmd-icon" />
                            {e.payload}
                          </span>
                        ) : (
                          <span style={{ fontFamily: 'var(--mono)', fontSize: '0.85rem' }}>
                            {e.payload || '-'}
                          </span>
                        )}
                      </td>
                      <td>{e.mitre_techniques?.length ? e.mitre_techniques.join(', ') : '—'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
