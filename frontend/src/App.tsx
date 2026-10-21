import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Activity, AlertTriangle, ArrowDownToLine, CircleDot, Database, Download, Globe2, Search, Shield, Terminal, Wifi, WifiOff, X } from 'lucide-react';
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
  const [apiToken, setApiToken] = useState(() => sessionStorage.getItem('hive-api-token') ?? '');
  const [tokenInput, setTokenInput] = useState('');
  const [authRequired, setAuthRequired] = useState(false);
  const [activeView, setActiveView] = useState<'events' | 'website'>('events');
  const [sitePreviewKey, setSitePreviewKey] = useState(0);
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const wsAddress = import.meta.env.VITE_WS_URL ?? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.hostname}:8000/ws/events`;
  const apiAddress = wsAddress.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:').replace(/\/ws\/events(?:\?.*)?$/, '');

  useEffect(() => {
    let socket: WebSocket | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let retryDelay = 1000;
    const headers = apiToken ? { Authorization: `Bearer ${apiToken}` } : undefined;

    const pollMetrics = () => fetch(`${apiAddress}/api/metrics`, { headers }).then((r) => r.ok ? r.json() : null).then((data) => {
      if (!stopped && data) {
        setDropped(Number(data.dropped_events ?? 0));
        setJournalErrors(Number(data.journal_errors ?? 0));
      }
    }).catch(() => undefined);
    fetch(`${apiAddress}/api/health`, { headers }).then((response) => { if (response.status === 401) setAuthRequired(true); }).catch(() => undefined);
    pollMetrics();
    const metricsTimer = setInterval(pollMetrics, 10000);

    const connect = () => {
      if (stopped) return;
      socket = new WebSocket(wsAddress, apiToken ? [`hive-auth.${apiToken}`] : []);
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
  }, [apiAddress, apiToken, wsAddress]);

  useEffect(() => {
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ q: query, limit: '500' });
      if (filter !== 'all') params.set('service', filter);
      const headers = apiToken ? { Authorization: `Bearer ${apiToken}` } : undefined;
      fetch(`${apiAddress}/api/search?${params}`, { headers }).then((response) => { if (response.status === 401) setAuthRequired(true); return response.ok ? response.json() : null; }).then((result: { events?: Event[] } | null) => {
        if (result?.events) setEvents((current) => {
          const merged = new Map(result.events!.map((item) => [item.id, item]));
          for (const item of current) if (!merged.has(item.id) && Date.now() - Date.parse(item.timestamp) < 30000) merged.set(item.id, item);
          return [...merged.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 500);
        });
      }).catch(() => undefined);
    }, 250);
    return () => clearTimeout(timer);
  }, [apiAddress, apiToken, filter, query]);

  useEffect(() => {
    if (!selectedEvent) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setSelectedEvent(null); };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [selectedEvent]);

  const visibleEvents = useMemo(() => events.filter((item) => {
    const matchesService = filter === 'all' || item.service.toLowerCase() === filter;
    const searchable = `${item.attacker_ip} ${item.service} ${item.event_type} ${item.username ?? ''} ${item.payload}`.toLowerCase();
    return matchesService && searchable.includes(query.toLowerCase());
  }), [events, filter, query]);
  const attacks = events.filter((item) => item.event_type.includes('exploit') || item.event_type.includes('auth_attempt')).length;
  const uniqueSources = new Set(events.map((item) => item.attacker_ip)).size;
  const serviceCount = (service: string) => service === 'all' ? events.length : events.filter((item) => item.service.toLowerCase() === service).length;
  const siteUrl = import.meta.env.VITE_HIVE_SITE_URL ?? `${location.protocol}//${location.hostname}:8080/`;
  const exportEvents = () => {
    const csvCell = (value: string) => `"${value.replaceAll('"', '""')}"`;
    const rows = [['timestamp','service','attacker_ip','attacker_port','event_type','username','payload','mitre_techniques'], ...visibleEvents.map((e) => [e.timestamp,e.service,e.attacker_ip,e.attacker_port ?? '',e.event_type,e.username ?? '',e.payload,(e.mitre_techniques ?? []).join(';')])];
    const blob = new Blob([rows.map((row) => row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'hive-events.csv'; link.click(); URL.revokeObjectURL(url);
  };
  const authenticate = (formEvent: FormEvent<HTMLFormElement>) => {
    formEvent.preventDefault();
    const token = tokenInput.trim();
    if (!token) return;
    sessionStorage.setItem('hive-api-token', token);
    setApiToken(token);
    setAuthRequired(false);
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>HIVE</strong><span>SENSOR CONSOLE</span></div></div>
        <div className="sidebar-label">MONITORING</div>
        <button className={`nav-item ${activeView === 'events' ? 'active' : ''}`} aria-current={activeView === 'events' ? 'page' : undefined} onClick={() => setActiveView('events')}><Activity size={17} />Event stream</button>
        <button className={`nav-item ${activeView === 'website' ? 'active' : ''}`} aria-current={activeView === 'website' ? 'page' : undefined} onClick={() => setActiveView('website')}><Globe2 size={17} />Decoy website<span className="nav-live-dot" /></button>
        <div className="sidebar-spacer" />
        <div className="sensor-card"><span className="sensor-dot" /><div><strong>hive-01</strong><small>LOCAL SENSOR</small></div><CircleDot size={14} /></div>
        {apiToken && <button className="auth-logout" onClick={() => { sessionStorage.removeItem('hive-api-token'); setApiToken(''); setAuthRequired(true); }}>Sign out</button>}
        <div className="sidebar-footer">HIVE · DEVELOPMENT BUILD</div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="heading"><div className="eyebrow">SECURITY OBSERVABILITY / SENSOR 01</div><h1>{activeView === 'events' ? 'Threat activity' : 'Decoy website'}</h1><p>{activeView === 'events' ? 'Live telemetry captured by your deception services.' : 'Preview the inversehacker site served by your HTTP honeypot.'}</p></div>
          <div className={`connection ${connected ? 'online' : 'offline'}`}>{connected ? <Wifi size={15} /> : <WifiOff size={15} />}{connected ? 'STREAM CONNECTED' : 'RECONNECTING'}</div>
        </header>

        {activeView === 'website' ? <section className="website-preview-card" aria-label="Inversehacker decoy website preview">
          <div className="preview-toolbar">
            <div className="preview-address"><span className="preview-status-dot" /><span>{siteUrl}</span><small>HTTP DECOY</small></div>
            <div className="preview-actions">
              <button className="preview-button" onClick={() => setSitePreviewKey((key) => key + 1)} title="Reload preview">↻ <span>Reload</span></button>
              <a className="preview-button preview-open" href={siteUrl} target="_blank" rel="noreferrer">Open separately <span aria-hidden="true">↗</span></a>
            </div>
          </div>
          <iframe key={sitePreviewKey} className="website-preview-frame" src={siteUrl} title="inversehacker decoy website" sandbox="allow-scripts allow-same-origin" />
          <div className="preview-caption"><span><span className="preview-status-dot" /> Site is served by the HTTP decoy</span><span>Requests appear in Event stream under HTTP</span></div>
        </section> : <>
        <section className="stats-grid" aria-label="Event summary">
          <article className="stat-card"><div className="stat-label"><Activity size={15} /> EVENTS IN VIEW</div><strong>{events.length}</strong><span>Most recent 500 events</span></article>
          <article className="stat-card"><div className="stat-label"><AlertTriangle size={15} /> AUTH / EXPLOIT SIGNALS</div><strong>{attacks}</strong><span>Heuristic event categories</span></article>
          <article className="stat-card"><div className="stat-label"><Globe2 size={15} /> UNIQUE SOURCES</div><strong>{uniqueSources}</strong><span>Distinct source IPs in view</span></article>
          <article className={`stat-card ${dropped || journalErrors ? 'health-warning' : ''}`}><div className="stat-label"><Database size={15} /> DELIVERY / STORAGE</div><strong>{dropped + journalErrors}</strong><span>{journalErrors} journal write errors · {dropped} dropped deliveries</span></article>
        </section>

        <section className="stream-card">
          <div className="stream-heading"><div><h2>Captured events</h2><p>Newest first · payloads are untrusted input</p></div><div className="stream-actions"><button className="filter-button" onClick={exportEvents} disabled={!visibleEvents.length}><Download size={14}/> Export CSV</button><span className="event-count">{visibleEvents.length} EVENTS</span></div></div>
          <div className="toolbar">
            <div className="filters" role="group" aria-label="Filter events by service">
              {services.map((service) => <button key={service} className={filter === service ? 'filter-button selected' : 'filter-button'} onClick={() => setFilter(service)}>{service === 'all' ? 'All services' : service.toUpperCase()}<span>{serviceCount(service)}</span></button>)}
            </div>
            <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP, payload, identity…" aria-label="Search events" /></label>
          </div>
          <div className="table-scroll"><table className="events-table"><thead><tr><th>TIME</th><th>SERVICE</th><th>SOURCE</th><th>ACTIVITY</th><th>IDENTITY</th><th>OBSERVED INPUT</th><th>ATT&amp;CK</th></tr></thead>
            <tbody>{visibleEvents.length === 0 ? <tr><td colSpan={7}><div className="empty-state"><Terminal size={25} /><strong>{events.length ? 'No matching events' : 'Waiting for activity'}</strong><span>{events.length ? 'Try another service filter or search.' : 'Connect to a honeypot service to see its captured activity here.'}</span></div></td></tr> : visibleEvents.map((item) => <tr key={item.id} className="event-row" tabIndex={0} aria-label={`Open details for ${item.service} ${item.event_type} from ${item.attacker_ip}`} onClick={() => setSelectedEvent(item)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedEvent(item); } }}>
              <td className="time-cell"><span>{new Date(item.timestamp).toLocaleTimeString()}</span><small>{new Date(item.timestamp).toLocaleDateString()}</small></td>
              <td><span className={`service-pill ${item.service}`}>{item.service}</span></td>
              <td className="source-cell">{item.attacker_ip}{item.attacker_port && <small>:{item.attacker_port}</small>}</td>
              <td><span className={`event-pill ${item.event_type.includes('exploit') ? 'danger' : item.event_type.includes('auth') ? 'warning' : item.event_type === 'link_click' ? 'interaction' : ''}`}>{item.event_type.replaceAll('_', ' ')}</span></td>
              <td className="identity-cell">{item.username || '—'}</td>
              <td className="payload-cell" title={item.payload}>{item.payload || '—'}</td>
              <td className="mitre-cell">{item.mitre_techniques?.length ? item.mitre_techniques.map((technique) => <code key={technique}>{technique}</code>) : '—'}</td>
            </tr>)}</tbody></table></div>
          <footer className="stream-footer"><span><span className={`footer-dot ${connected ? 'on' : ''}`} />{connected ? 'Receiving live events' : 'Trying to reconnect'}</span><span><ArrowDownToLine size={14} /> Search covers retained journal events · CSV exports current results</span></footer>
        </section>
        <div className="safety-note"><Shield size={15} /><span>Honeypot telemetry can contain sensitive, attacker-supplied data. Restrict dashboard access and configure retention before external deployment.</span></div>
        </>}
      </main>
      {selectedEvent && <div className="event-detail-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelectedEvent(null); }}>
        <section className="event-detail-panel" role="dialog" aria-modal="true" aria-labelledby="event-detail-title">
          <header className="event-detail-header">
            <div><div className="detail-pills"><span className={`service-pill ${selectedEvent.service}`}>{selectedEvent.service}</span><span className={`event-pill ${selectedEvent.event_type.includes('exploit') ? 'danger' : selectedEvent.event_type.includes('auth') ? 'warning' : selectedEvent.event_type === 'link_click' ? 'interaction' : ''}`}>{selectedEvent.event_type.replaceAll('_', ' ')}</span></div><h2 id="event-detail-title">Captured event</h2><p>{selectedEvent.id}</p></div>
            <button className="detail-close" autoFocus aria-label="Close event details" onClick={() => setSelectedEvent(null)}><X size={18}/></button>
          </header>
          <div className="event-detail-content">
            <section className="detail-section"><h3>When it happened</h3><p className="detail-timestamp">{new Date(selectedEvent.timestamp).toLocaleString()}</p></section>
            <section className="detail-section"><h3>Source and sensor</h3><dl className="detail-grid"><div><dt>Attacker IP</dt><dd>{selectedEvent.attacker_ip}{selectedEvent.attacker_port && <span>:{selectedEvent.attacker_port}</span>}</dd></div><div><dt>Service</dt><dd>{selectedEvent.service}</dd></div><div><dt>Username</dt><dd>{selectedEvent.username || 'Not captured'}</dd></div><div><dt>Sensor ID</dt><dd>{selectedEvent.sensor_id || 'Unknown'}</dd></div></dl></section>
            <section className="detail-section"><h3>Observed input</h3><pre className="detail-payload">{selectedEvent.payload || 'No payload was captured for this event.'}</pre></section>
            <section className="detail-section"><h3>MITRE ATT&amp;CK techniques</h3>{selectedEvent.mitre_techniques?.length ? <div className="detail-techniques">{selectedEvent.mitre_techniques.map((technique) => <code key={technique}>{technique}</code>)}</div> : <p className="detail-muted">No techniques were assigned.</p>}</section>
          </div>
        </section>
      </div>}
      {authRequired && <div className="auth-overlay"><form className="auth-card" onSubmit={authenticate}><Shield size={25}/><h2>Dashboard access</h2><p>Enter the HIVE_API_TOKEN configured for this sensor.</p><label>API token<input autoFocus type="password" value={tokenInput} onChange={(event) => setTokenInput(event.target.value)} autoComplete="current-password" /></label><button type="submit">Connect to Hive</button></form></div>}
    </div>
  );
}

export default App;
