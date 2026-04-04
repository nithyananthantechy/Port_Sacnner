import os
import sys
import ssl
import socket
import json
import subprocess
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context
from port_scanner import scan_target, scan_generator_sync, parse_ports

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('APP_SECRET_KEY', 'dev-secret-change-me')

LOGIN_USERNAME = os.environ.get('SCAN_UI_USER', 'admin')
LOGIN_PASSWORD = os.environ.get('SCAN_UI_PASS', 'password')


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


# ─── PAGES ────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form or request.json or {}
        user = data.get('username')
        pwd = data.get('password')
        if user == LOGIN_USERNAME and pwd == LOGIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        if request.is_json:
            return jsonify({'error': 'invalid credentials'}), 403
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ─── PORT SCANNER ─────────────────────────────────────────────────────────────

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.json or {}
    target = data.get('target') or request.form.get('target')
    ports = data.get('ports', '1-1024')
    threads = int(data.get('threads', 100))
    timeout = float(data.get('timeout', 1.0))
    service = bool(data.get('service', True))
    if not target:
        return jsonify({'error': 'target required'}), 400
    try:
        results = scan_target(target, ports=ports, threads=threads, timeout=timeout, service=service)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    out = [{'port': p, 'service': s, 'banner': b} for p, s, b in results]
    return jsonify({'target': target, 'results': out})


@app.route('/check_port', methods=['POST'])
@login_required
def check_port():
    data = request.json or {}
    target = data.get('target')
    port = data.get('port')
    if not target or not port:
        return jsonify({'error': 'Target and port required'}), 400
    try:
        port = int(port)
        results = scan_target(target, ports=str(port), threads=1, timeout=2.0, service=False)
        is_open = len(results) > 0
        return jsonify({'target': target, 'port': port, 'open': is_open})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stream_scan')
@login_required
def stream_scan():
    target = request.args.get('target')
    ports = request.args.get('ports', '1-1024')
    threads = int(request.args.get('threads', 100))
    timeout = float(request.args.get('timeout', 1.0))
    service = request.args.get('service') == 'on'
    if not target:
        return jsonify({'error': 'target required'}), 400

    def generate():
        try:
            total_ports = len(parse_ports(ports))
        except Exception:
            total_ports = 0
        yield f"data: {json.dumps({'type': 'meta', 'total': total_ports})}\n\n"
        scanned_count = 0
        try:
            for port, is_open, svc, banner in scan_generator_sync(target, ports, threads, timeout, service):
                scanned_count += 1
                msg = {'type': 'result', 'port': port, 'open': is_open,
                       'service': svc, 'banner': banner, 'scanned': scanned_count}
                yield f"data: {json.dumps(msg)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


# ─── SSL CHECKER ──────────────────────────────────────────────────────────────

@app.route('/api/ssl_check', methods=['POST'])
@login_required
def ssl_check():
    data = request.json or {}
    host = data.get('host', '').strip().replace('https://', '').replace('http://', '').split('/')[0]
    port = int(data.get('port', 443))
    if not host:
        return jsonify({'error': 'host required'}), 400
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        # Parse expiry
        expire_str = cert.get('notAfter', '')
        expire_dt = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expire_dt - datetime.datetime.utcnow()).days

        # Subject info
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer',  []))

        # SANs
        sans = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']

        return jsonify({
            'host': host,
            'valid': True,
            'subject': subject.get('commonName', host),
            'issuer': issuer.get('organizationName', 'Unknown'),
            'expires': expire_str,
            'days_left': days_left,
            'protocol': protocol,
            'cipher': cipher[0] if cipher else 'Unknown',
            'sans': sans[:10],
        })
    except ssl.SSLCertVerificationError as e:
        return jsonify({'host': host, 'valid': False, 'error': f'Certificate invalid: {e}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── DNS LOOKUP ───────────────────────────────────────────────────────────────

@app.route('/api/dns_lookup', methods=['POST'])
@login_required
def dns_lookup():
    data = request.json or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'domain required'}), 400
    try:
        import dns.resolver
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return jsonify({'domain': domain, 'records': records})
    except ImportError:
        # Fallback using socket if dnspython not available
        try:
            ip = socket.gethostbyname(domain)
            return jsonify({'domain': domain, 'records': {'A': [ip], 'note': 'Install dnspython for full lookup'}})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── WHOIS ────────────────────────────────────────────────────────────────────

@app.route('/api/whois', methods=['POST'])
@login_required
def whois_lookup():
    data = request.json or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'domain required'}), 400
    try:
        import whois
        w = whois.whois(domain)
        def safe(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else None

        result = {
            'domain': domain,
            'registrar': safe(w.registrar),
            'creation_date': safe(w.creation_date),
            'expiration_date': safe(w.expiration_date),
            'updated_date': safe(w.updated_date),
            'name_servers': safe(w.name_servers),
            'status': safe(w.status),
            'emails': safe(w.emails),
            'country': safe(w.country),
            'org': safe(w.org),
        }
        return jsonify(result)
    except ImportError:
        return jsonify({'error': 'python-whois not installed. Run: pip install python-whois'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── PING ─────────────────────────────────────────────────────────────────────

@app.route('/api/ping', methods=['POST'])
@login_required
def ping():
    data = request.json or {}
    host = data.get('host', '').strip()
    count = min(int(data.get('count', 4)), 10)  # max 10
    if not host:
        return jsonify({'error': 'host required'}), 400
    # Basic validation to prevent command injection
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:')
    if not all(c in allowed for c in host):
        return jsonify({'error': 'Invalid host'}), 400
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', '2', host],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout or result.stderr
        # Parse avg RTT
        rtt = None
        for line in output.splitlines():
            if 'rtt' in line or 'round-trip' in line:
                parts = line.split('=')
                if len(parts) > 1:
                    rtt = parts[1].strip().split('/')[1] if '/' in parts[1] else parts[1].strip()
                    rtt = rtt.split(' ')[0] + ' ms'
        return jsonify({
            'host': host,
            'reachable': result.returncode == 0,
            'output': output,
            'avg_rtt': rtt
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Ping timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
