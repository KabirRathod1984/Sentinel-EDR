# File: server.py
"""
Endpoint Detection Server + Dashboard
Requirements: Flask, flask_cors
Run: python3 server.py
"""
from flask import Flask, request, jsonify, render_template_string, abort
from flask_cors import CORS
from datetime import datetime, timezone
import threading
import uuid

API_KEY = "d96dcbc5fc27f69de91a59e1c222ffe3"  # change this before production

app = Flask(__name__)
CORS(app)

# In-memory store for alerts
ALERTS = []
ALERT_LOCK = threading.Lock()
MAX_ALERTS = 1000

# Severity to color mapping (like Burp Suite style)
SEVERITY_STYLES = {
    'critical': {'bg': '#ff4d4f', 'text': '#ffffff'},
    'high': {'bg': '#ff7a45', 'text': '#000000'},
    'medium': {'bg': '#ffd666', 'text': '#000000'},
    'low': {'bg': '#bae637', 'text': '#000000'},
    'info': {'bg': '#91d5ff', 'text': '#000000'}
}


def add_alert(agent_id, title, desc, severity='info', raw=None):
    alert = {
        'id': str(uuid.uuid4()),
        'agent': agent_id,
        'title': title,
        'description': desc,
        'severity': severity,
        'raw': raw or {},
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    with ALERT_LOCK:
        ALERTS.insert(0, alert)
        # keep size bounded
        if len(ALERTS) > MAX_ALERTS:
            ALERTS.pop()
    return alert


@app.route('/ingest', methods=['POST'])
def ingest():
    # Simple API key auth
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({'error': 'unauthorized'}), 401
    payload = request.get_json() or {}
    agent = payload.get('agent', 'unknown')
    events = payload.get('events', [])
    created = []
    for ev in events:
        title = ev.get('title', 'event')
        desc = ev.get('description', '')
        severity = ev.get('severity', 'info')
        raw = ev.get('raw')
        created.append(add_alert(agent, title, desc, severity, raw))
    return jsonify({'created': len(created)})


@app.route('/alerts', methods=['GET'])
def get_alerts():
    # return recent alerts
    with ALERT_LOCK:
        return jsonify(ALERTS[:200])


DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EDR Dashboard</title>
  <style>
    body{font-family:Inter, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; margin:0; padding:0; background:#0d1117; color:#e6edf3;}
    .top{background:#161b22;color:#fff;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 6px rgba(0,0,0,0.5)}
    .container{padding:16px}
    .card{padding:10px;border-radius:10px;background:#1c2128;box-shadow:0 4px 14px rgba(0,0,0,0.7);margin-bottom:12px}
    .alertrow{display:flex;gap:12px;align-items:center;padding:10px;border-radius:8px;margin-bottom:8px;background:#22272e}
    .sev{width:110px;padding:6px 10px;border-radius:6px;font-weight:600;text-align:center}
    .meta{font-size:12px;color:#8b949e}
    .title{font-weight:700;color:#e6edf3}
    .desc{margin-top:6px;color:#c9d1d9}
    .right{margin-left:auto;text-align:right}
    #filters{display:flex;gap:8px;align-items:center}
    .pill{padding:6px 10px;border-radius:999px;background:#30363d;font-weight:600;color:#c9d1d9}
  </style>
</head>
<body>
  <div class="top">
    <div style="display:flex;align-items:center;gap:12px">
      <img src="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='30' height='30'><rect rx='6' width='30' height='30' fill='%23007acc'/></svg>"/>
      <div>
        <div style="font-weight:800">EDR Dashboard ~ By Cyspy Maiden</div>
        <div style="font-size:12px;color:#8b949e">Live alerts & Logs</div>
      </div>
    </div>
    <div id="filters">
      <div class="pill">Showing: <span id="count">0</span></div>
      <div class="pill">Agents: <span id="agents">0</span></div>
    </div>
  </div>
  <div class="container">
    <div class="card" id="alerts"></div>
  </div>

<script>
const sevStyle = {
  'critical': {bg:'#ff4d4f', color:'#fff'},
  'high': {bg:'#ff7a45', color:'#000'},
  'medium': {bg:'#ffd666', color:'#000'},
  'low': {bg:'#bae637', color:'#000'},
  'info': {bg:'#91d5ff', color:'#000'}
};

async function fetchAlerts(){
  try{
    const res = await fetch('/alerts');
    const data = await res.json();
    render(data);
  }catch(e){
    console.error(e);
  }
}

function render(alerts){
  document.getElementById('count').innerText = alerts.length;
  const agents = [...new Set(alerts.map(a=>a.agent))];
  document.getElementById('agents').innerText = agents.join(', ');
  const container = document.getElementById('alerts');
  container.innerHTML = '';
  for(const a of alerts){
    const row = document.createElement('div');
    row.className = 'alertrow';
    const s = sevStyle[a.severity]||sevStyle.info;
    const sev = document.createElement('div');
    sev.className='sev';
    sev.style.background = s.bg;
    sev.style.color = s.color;
    sev.innerText = a.severity.toUpperCase();
    const body = document.createElement('div');
    body.style.flex='1';
    body.innerHTML = `<div class='title'>${escapeHtml(a.title)}</div><div class='meta'>${a.agent} · ${new Date(a.timestamp).toLocaleString()}</div><div class='desc'>${escapeHtml(a.description)}</div>`;
    const raw = document.createElement('div');
    raw.className='right';
    raw.innerHTML = `<div style='font-size:12px;color:#8b949e'>id: ${a.id.slice(0,8)}</div>`;
    row.appendChild(sev);
    row.appendChild(body);
    row.appendChild(raw);
    container.appendChild(row);
  }
}

function escapeHtml(s){
  if(!s) return '';
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

// Poll every 2.5s
setInterval(fetchAlerts, 2500);
fetchAlerts();
</script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == '__main__':
    print('Starting server on http://0.0.0.0:8000')
    app.run(host='0.0.0.0', port=8000, debug=False)
