import os
import sys

# ensure project root is on sys.path so `port_scanner` can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context
from port_scanner import scan_target, scan_generator_sync, parse_ports
import json

app = Flask(__name__, template_folder='templates', static_folder='static')

# Secret key for session. In production set via env var.
app.secret_key = os.environ.get('APP_SECRET_KEY', 'dev-secret-change-me')

# simple credentials (override with env vars in deployment)
LOGIN_USERNAME = os.environ.get('SCAN_UI_USER', 'admin')
LOGIN_PASSWORD = os.environ.get('SCAN_UI_PASS', 'password')


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if not session.get('logged_in'):
        return jsonify({'error': 'authentication required'}), 401
    data = request.json or {}
    target = data.get('target') or request.form.get('target')
    ports = data.get('ports', '1-1024')
    threads = int(data.get('threads', 100))
    timeout = float(data.get('timeout', 1.0))
    service = bool(data.get('service', True))

    if not target:
        return jsonify({'error': 'target required'}), 400

    try:
        # scan_target is now using asyncio internally
        results = scan_target(target, ports=ports, threads=threads, timeout=timeout, service=service)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # results is list of (port, service, banner)
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
        # Use existing scan logic but for single port
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
    service = request.args.get('service') == 'true'

    if not target:
        return jsonify({'error': 'target required'}), 400

    def generate():
        # Initial stats
        try:
            total_ports = len(parse_ports(ports))
        except Exception:
            total_ports = 0
            
        yield f"data: {json.dumps({'type': 'meta', 'total': total_ports})}\n\n"

        # Stream results
        scanned_count = 0
        try:
            for port, is_open, svc, banner in scan_generator_sync(target, ports, threads, timeout, service):
                scanned_count += 1
                # We yield progress for every port (open or closed) so client can update bar
                msg = {
                    'type': 'result',
                    'port': port,
                    'open': is_open,
                    'service': svc,
                    'banner': banner,
                    'scanned': scanned_count
                }
                yield f"data: {json.dumps(msg)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # support form POST or JSON
    if request.method == 'POST':
        data = request.form or request.json or {}
        user = data.get('username')
        pwd = data.get('password')
        if user == LOGIN_USERNAME and pwd == LOGIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        # JSON clients get JSON error
        if request.is_json:
            return jsonify({'error': 'invalid credentials'}), 403
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Production configuration
    app.run(host='0.0.0.0', port=5000, debug=False)
