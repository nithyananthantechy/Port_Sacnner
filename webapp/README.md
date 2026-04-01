# Port Scanner Web UI

Quick Flask web interface for the terminal port scanner. To run locally:

```bash
python3 -m pip install -r webapp/requirements.txt
python3 webapp/app.py
```

Then open `http://127.0.0.1:5000/` and use the form. Use responsibly.

Authentication
--------------

This demo includes a simple session-based login. Default demo credentials:

- username: `admin`
- password: `password`

Override with environment variables before starting the server:

```bash
export SCAN_UI_USER=myuser
export SCAN_UI_PASS=strongpass
export APP_SECRET_KEY=some-long-secret
python3 webapp/app.py
```

