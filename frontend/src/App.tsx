import { useEffect, useState } from 'react';
import { Terminal, Shield, Activity } from 'lucide-react';
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
}

function App() {
  const [events, setEvents] = useState<Event[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws/events');

    ws.onopen = () => {
      console.log('Connected to event stream');
      setConnected(true);
    };

    ws.onmessage = (msg) => {
      try {
        const e: Event = JSON.parse(msg.data);
        setEvents((prev) => [e, ...prev].slice(0, 50)); // Keep last 50 events
      } catch (err) {
        console.error('Failed to parse event', err);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('Disconnected from event stream');
    };

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <Shield className="header-icon" />
        <h1>Hive Dashboard</h1>
        <div className={`status-badge ${connected ? 'status-online' : 'status-offline'}`}>
          {connected ? 'Live Stream Active' : 'Disconnected'}
        </div>
      </header>

      <main className="dashboard-main">
        <div className="card">
          <div className="card-header">
            <Activity className="card-icon" />
            <h2>Live Attack Stream</h2>
          </div>
          
          <div className="events-table-wrapper">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Service</th>
                  <th>Attacker IP</th>
                  <th>Type</th>
                  <th>User</th>
                  <th>Payload/Command</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-state">No events captured yet. Try connecting to SSH!</td>
                  </tr>
                ) : (
                  events.map((e, idx) => (
                    <tr key={e.id || idx}>
                      <td className="time-cell">{new Date(e.timestamp).toLocaleTimeString()}</td>
                      <td>
                        <span className={`service-badge service-${e.service}`}>{e.service}</span>
                      </td>
                      <td className="ip-cell">{e.attacker_ip}</td>
                      <td>{e.event_type}</td>
                      <td>{e.username || '-'}</td>
                      <td className="payload-cell">
                        {e.event_type === 'command_exec' ? (
                          <span className="command-text">
                            <Terminal size={14} className="cmd-icon" />
                            {e.payload}
                          </span>
                        ) : (
                          e.payload
                        )}
                      </td>
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
