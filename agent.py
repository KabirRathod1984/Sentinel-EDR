"""
Simple endpoint agent that collects local telemetry and sends suspicious events
Requirements: requests, psutil
Run: python3 agent.py --server http://<server-ip>:8000 --agent <agent-name> --key <api-key>
"""

# The agent code is included below as a module; when running as a script it will execute.
import argparse
import time
import socket
import threading
import json
import requests
import psutil
from datetime import datetime

# Basic detection rules — tune these for your environment
SUSPICIOUS_PROCESSES = ['nc', 'ncat', 'netcat', 'meterpreter', 'msfconsole', 'powershell.exe', 'psexec']
SUS_OUTBOUND_PORTS = [4444, 5555, 1337, 9999]
CPU_HIGH_THRESHOLD = 80.0
MEM_HIGH_THRESHOLD = 80.0

SEND_INTERVAL = 10  # seconds between batches


def collect_events(agent_name):
    events = []
    now = datetime.utcnow().isoformat() + 'Z'

    # 1) CPU / Memory spike
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    if cpu >= CPU_HIGH_THRESHOLD:
        events.append({
            'title': 'High CPU usage',
            'description': f'CPU at {cpu}%',
            'severity': 'high',
            'raw': {'cpu': cpu, 'time': now}
        })
    if mem >= MEM_HIGH_THRESHOLD:
        events.append({
            'title': 'High memory usage',
            'description': f'Memory at {mem}%',
            'severity': 'medium',
            'raw': {'mem': mem, 'time': now}
        })

    # 2) Suspicious processes
    for p in psutil.process_iter(['pid','name','cmdline']):
        try:
            name = (p.info.get('name') or '').lower()
            cmd = ' '.join(p.info.get('cmdline') or [])
            for suspect in SUSPICIOUS_PROCESSES:
                if suspect in name or suspect in cmd:
                    events.append({
                        'title': 'Suspicious process detected',
                        'description': f"{name} (pid {p.info.get('pid')}) cmd: {cmd}",
                        'severity': 'critical',
                        'raw': {'pid': p.info.get('pid'), 'name': name, 'cmdline': cmd}
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 3) Outbound network connections
    try:
        conns = psutil.net_connections(kind='inet')
        for c in conns:
            if c.raddr and c.status == psutil.CONN_ESTABLISHED:
                rport = c.raddr.port
                rhost = c.raddr.ip
                if rport in SUS_OUTBOUND_PORTS or rport > 49152:
                    events.append({
                        'title': 'Suspicious outbound connection',
                        'description': f'{rhost}:{rport} from pid {c.pid}',
                        'severity': 'high',
                        'raw': {'rhost': rhost, 'rport': rport, 'pid': c.pid}
                    })
    except Exception:
        pass

    # 4) New files in temp directory (quick heuristic)
    # To avoid heavy IO, this is a light check: list dir and check for many files
    try:
        import os
        tmp = '/tmp' if os.name!='nt' else os.environ.get('TEMP','C:\Windows\Temp')
        files = os.listdir(tmp)
        if len(files) > 200:
            events.append({
                'title': 'Large number of files in temp',
                'description': f'{len(files)} entries in {tmp}',
                'severity': 'medium',
                'raw': {'path': tmp, 'count': len(files)}
            })
    except Exception:
        pass

    # 5) Failed sudo or auth attempts (linux-only) — quick tail of auth log
    if psutil.OSX is False and hasattr(psutil, 'users'):
        try:
            if os.path.exists('/var/log/auth.log'):
                with open('/var/log/auth.log','r',errors='ignore') as f:
                    tail = ''.join(f.readlines()[-200:])
                    if 'failed password' in tail.lower() or 'authentication failure' in tail.lower():
                        events.append({
                            'title': 'Auth failures detected',
                            'description': 'Recent failed authentication attempts in /var/log/auth.log',
                            'severity': 'low',
                            'raw': {'snippet': tail[-800:]}
                        })
        except Exception:
            pass

    return events


def send_batch(server, agent_name, api_key, events):
    if not events:
        return
    payload = {
        'agent': agent_name,
        'events': events
    }
    try:
        headers = {'Content-Type':'application/json', 'X-API-KEY': api_key}
        r = requests.post(server.rstrip('/') + '/ingest', json=payload, headers=headers, timeout=6)
        if r.status_code == 200:
            print(f'[{datetime.utcnow().isoformat()}] Sent {len(events)} events')
        else:
            print('Server rejected payload', r.status_code, r.text)
    except Exception as e:
        print('Failed to send batch', e)


def run_agent(server, agent_name, api_key, interval=SEND_INTERVAL):
    print(f'Agent starting for {agent_name}, sending to {server}')
    while True:
        ev = collect_events(agent_name)
        if ev:
            send_batch(server, agent_name, api_key, ev)
        time.sleep(interval)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True, help='http://server:8000')
    parser.add_argument('--agent', required=True, help='agent name')
    parser.add_argument('--key', required=True, help='API key')
    args = parser.parse_args()
    try:
        run_agent(args.server, args.agent, args.key)
    except KeyboardInterrupt:
        print('Agent stopped')
