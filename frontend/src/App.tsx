import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, ArrowDownToLine, CircleDot, Database, Globe2, Search, Shield, Terminal, Wifi, WifiOff } from 'lucide-react';
import './App.css';

interface Event {
  id: string; timestamp: string; attacker_ip: string; attacker_port?: string;
  service: string; event_type: string; payload: string; username?: string;
  sensor_id?: string; mitre_techniques?: string[];
}
const services = ['all', 'ssh', 'http', 'mysql', 'redis'];

function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [dropped, setDropped] = useState(0);
  const [journalErrors, setJournalErrors] = useState(0);

  useEffect(() => {
    let socket: WebSocket | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let retryDelay = 1000;
    const wsAddress = import.meta.env.VITE_WS_URL ?? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.hostname}:8000/ws/events`;
    const apiAddress = wsAddress.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:').replace(/\/ws\/events(?:\?.*)?$/, '');

    fetch(`${apiAddress}/api/events?limit=100`).then((response) => response.ok ? response.json() : []).then((items: Event[]) => {
      if (!stopped && Array.isArray(items)) setEvents((current) => {
        const merged = new Map<string, Event>();
        for (const item of items) merged.set(item.id, item);
        for (const item of current) merged.set(item.id, item);
        return [...merged.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 500);
      });
    }).catch(() => undefined);
    const pollMetrics = () => fetch(`${apiAddress}/api/metrics`).then((r) => r.ok ? r.json() : null).then((data) => {
      if (!stopped && data) {
        setDropped(Number(data.dropped_events ?? 0));
        setJournalErrors(Number(data.journal_errors ?? 0));
      }
    }).catch(() => undefined);
    pollMetrics();
    const metricsTimer = setInterval(pollMetrics, 10000);

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(wsAddress);
      socket.onopen = () => { retryDelay = 1000; setConnected(true); };
      socket.onmessage = (msg) => {
        try {
          const item: Event = JSON.parse(msg.data);
          setEvents((prev) => [item, ...prev.filter((old) => old.id !== item.id)].slice(0, 500));
        } catch (error) { console.error('Could not parse event from Hive', error); }
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
    return () => { stopped = true; clearInterval(metricsTimer); if (reconnectTimer) clearTimeout(reconnectTimer); socket?.close(); };
  }, []);

  const visibleEvents = useMemo(() => events.filter((item) => {
    const matchesService = filter === 'all' || item.service.toLowerCase() === filter;
    const searchable = `${item.attacker_ip} ${item.service} ${item.event_type} ${item.username ?? ''} ${item.payload}`.toLowerCase();
    return matchesService && searchable.includes(query.toLowerCase());
  }), [events, filter, query]);
  const attacks = events.filter((item) => item.event_type.includes('exploit') || item.event_type.includes('auth_attempt')).length;
  const uniqueSources = new Set(events.map((item) => item.attacker_ip)).size;
  const serviceCount = (service: string) => service === 'all' ? events.length : events.filter((item) => item.service.toLowerCase() === service).length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>HIVE</strong><span>SENSOR CONSOLE</span></div></div>
        <div className="sidebar-label">MONITORING</div>
        <button className="nav-item active"><Activity size={17} />Event stream</button>
        <div className="sidebar-spacer" />
        <div className="sensor-card"><span className="sensor-dot" /><div><strong>hive-01</strong><small>LOCAL SENSOR</small></div><CircleDot size={14} /></div>
        <div className="sidebar-footer">HIVE · DEVELOPMENT BUILD</div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="heading"><div className="eyebrow">SECURITY OBSERVABILITY / SENSOR 01</div><h1>Threat activity</h1><p>Live telemetry captured by your deception services.</p></div>
          <div className={`connection ${connected ? 'online' : 'offline'}`}>{connected ? <Wifi size={15} /> : <WifiOff size={15} />}{connected ? 'STREAM CONNECTED' : 'RECONNECTING'}</div>
        </header>

        <section className="stats-grid" aria-label="Event summary">
          <article className="stat-card"><div className="stat-label"><Activity size={15} /> EVENTS IN VIEW</div><strong>{events.length}</strong><span>Most recent 500 events</span></article>
          <article className="stat-card"><div className="stat-label"><AlertTriangle size={15} /> AUTH / EXPLOIT SIGNALS</div><strong>{attacks}</strong><span>Heuristic event categories</span></article>
          <article className="stat-card"><div className="stat-label"><Globe2 size={15} /> UNIQUE SOURCES</div><strong>{uniqueSources}</strong><span>Distinct source IPs in view</span></article>
          <article className="stat-card"><div className="stat-label"><Database size={15} /> DELIVERY / STORAGE</div><strong>{dropped}</strong><span>{journalErrors} journal write errors · {dropped} dropped deliveries</span></article>
        </section>

        <section className="stream-card">
          <div className="stream-heading"><div><h2>Captured events</h2><p>Newest first · payloads are untrusted input</p></div><span className="event-count">{visibleEvents.length} EVENTS</span></div>
          <div className="toolbar">
            <div className="filters" role="group" aria-label="Filter events by service">
              {services.map((service) => <button key={service} className={filter === service ? 'filter-button selected' : 'filter-button'} onClick={() => setFilter(service)}>{service === 'all' ? 'All services' : service.toUpperCase()}<span>{serviceCount(service)}</span></button>)}
            </div>
            <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP, payload, identity…" aria-label="Search events" /></label>
          </div>
          <div className="table-scroll"><table className="events-table"><thead><tr><th>TIME</th><th>SERVICE</th><th>SOURCE</th><th>ACTIVITY</th><th>IDENTITY</th><th>OBSERVED INPUT</th><th>ATT&amp;CK</th></tr></thead>
            <tbody>{visibleEvents.length === 0 ? <tr><td colSpan={7}><div className="empty-state"><Terminal size={25} /><strong>{events.length ? 'No matching events' : 'Waiting for activity'}</strong><span>{events.length ? 'Try another service filter or search.' : 'Connect to a honeypot service to see its captured activity here.'}</span></div></td></tr> : visibleEvents.map((item) => <tr key={item.id}>
              <td className="time-cell"><span>{new Date(item.timestamp).toLocaleTimeString()}</span><small>{new Date(item.timestamp).toLocaleDateString()}</small></td>
              <td><span className={`service-pill ${item.service}`}>{item.service}</span></td>
              <td className="source-cell">{item.attacker_ip}{item.attacker_port && <small>:{item.attacker_port}</small>}</td>
              <td><span className={`event-pill ${item.event_type.includes('exploit') ? 'danger' : item.event_type.includes('auth') ? 'warning' : ''}`}>{item.event_type.replaceAll('_', ' ')}</span></td>
              <td className="identity-cell">{item.username || '—'}</td>
              <td className="payload-cell" title={item.payload}>{item.payload || '—'}</td>
              <td className="mitre-cell">{item.mitre_techniques?.length ? item.mitre_techniques.map((technique) => <code key={technique}>{technique}</code>) : '—'}</td>
            </tr>)}</tbody></table></div>
          <footer className="stream-footer"><span><span className={`footer-dot ${connected ? 'on' : ''}`} />{connected ? 'Receiving live events' : 'Trying to reconnect'}</span><span><ArrowDownToLine size={14} /> Recent window from local journal · no indexed search</span></footer>
        </section>
        <div className="safety-note"><Shield size={15} /><span>Honeypot telemetry can contain sensitive, attacker-supplied data. Restrict dashboard access and configure retention before external deployment.</span></div>
      </main>
    </div>
  );
}

export default App;
