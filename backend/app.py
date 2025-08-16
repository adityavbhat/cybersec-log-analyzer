# backend/app.py
import os
import jwt
import math
import statistics
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps

from log_parser import read_csv_file  # <- the robust parser you just installed

# ---------------------------
# Config
# ---------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
TOKEN_TTL_MIN = int(os.getenv("TOKEN_TTL_MIN", "60"))

DEMO_USERNAME = os.getenv("DEMO_USERNAME", "analyst")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "password123")

app = Flask(__name__)

# Open CORS for all /api/* routes during local dev
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

# ---------------------------
# Helpers
# ---------------------------
def _now_utc():
    return datetime.now(timezone.utc)

def _make_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(_now_utc().timestamp()),
        "exp": int((_now_utc() + timedelta(minutes=TOKEN_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)

def _decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            _decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return fn(*args, **kwargs)
    return wrapper

def _iso(ts: datetime) -> str:
    # Return ISO8601 (always include timezone)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.isoformat()

def _percentile(sorted_vals, p: float, default=0):
    if not sorted_vals:
        return default
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1

# ---------------------------
# Anomaly detection (simple, explainable)
# ---------------------------
SENSITIVE_PATTERNS = ("/admin", "/wp-admin", "/api/keys", "/.env", "/etc/passwd", "/login")

def analyze_rows(rows):
    """
    Input rows: list of dicts with keys:
      timestamp (datetime), src_ip, dest_host, url_path, status (int), bytes_sent (int), user_agent
    Output:
      annotated_rows (list), summary (dict), timeline (list)
    """
    # Bytes P95 for "large transfer" heuristic
    bytes_vals = sorted([int(r.get("bytes_sent", 0) or 0) for r in rows])
    p95 = int(_percentile(bytes_vals, 0.95, default=0))

    # Simple IP rate monitor (requests per rolling 10 seconds)
    ip_windows = defaultdict(deque)  # src_ip -> deque of timestamps
    RATE_THRESHOLD = 20  # >20 events in 10s window => anomaly
    RATE_WINDOW_SEC = 10

    annotated = []
    anomalies = 0
    timeline_map = defaultdict(lambda: {"total": 0, "errors": 0})

    for r in rows:
        ts = r["timestamp"]
        minute_key = ts.strftime("%Y-%m-%d %H:%M")
        timeline_map[minute_key]["total"] += 1
        if int(r.get("status", 0) or 0) >= 500:
            timeline_map[minute_key]["errors"] += 1

        reasons = []
        conf = 0.0

        # Rule: Sensitive paths
        path = (r.get("url_path") or "").lower()
        if any(p in path for p in SENSITIVE_PATTERNS):
            reasons.append("Access to sensitive path")
            conf += 0.30

        # Rule: 5xx server errors
        status = int(r.get("status", 0) or 0)
        if status >= 500:
            reasons.append("Server error status (5xx)")
            conf += 0.35

        # Rule: unusually large transfer
        if p95 > 0 and int(r.get("bytes_sent", 0) or 0) >= p95:
            reasons.append(f"Unusually large bytes (>= P95={p95})")
            conf += 0.25

        # Rule: burst from same IP (rolling 10s)
        ip = r.get("src_ip") or ""
        if ip:
            q = ip_windows[ip]
            # pop anything older than 10s
            while q and (ts - q[0]).total_seconds() > RATE_WINDOW_SEC:
                q.popleft()
            q.append(ts)
            if len(q) > RATE_THRESHOLD:
                reasons.append(f"High request rate from {ip} (> {RATE_THRESHOLD}/10s)")
                conf += 0.25

        anomalous = len(reasons) > 0
        if anomalous:
            anomalies += 1
        annotated.append({
            "timestamp": _iso(ts),
            "src_ip": r.get("src_ip", ""),
            "dest_host": r.get("dest_host", ""),
            "url_path": r.get("url_path", ""),
            "status": status,
            "bytes_sent": int(r.get("bytes_sent", 0) or 0),
            "user_agent": r.get("user_agent", ""),
            "anomalous": anomalous,
            "reasons": reasons,
            "confidence": round(min(conf, 1.0), 2),
        })

    timeline = [
        {"minute": k, "total": v["total"], "errors": v["errors"]}
        for k, v in sorted(timeline_map.items())
    ]
    summary = {
        "total_rows": len(rows),
        "total_anomalies": anomalies,
        "big_bytes_threshold": p95,
    }
    return annotated, summary, timeline

# ---------------------------
# Routes
# ---------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username/password"}), 400

    if data["username"] != DEMO_USERNAME or data["password"] != DEMO_PASSWORD:
        return jsonify({"error": "Invalid credentials"}), 401

    token = _make_token(data["username"])
    return jsonify({"token": token})

@app.route("/api/analyze", methods=["POST"])
@token_required
def analyze():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    # DEBUG: peek first bytes to confirm what's arriving from the browser
    try:
        pos = file.stream.tell()
        sample = file.stream.read(160)
        print("DEBUG first160 bytes:", sample)
        file.stream.seek(pos)
    except Exception as e:
        print("DEBUG peek error:", e)

    try:
        rows = read_csv_file(file)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        # Unexpected parse error
        return jsonify({"error": f"Parse failure: {e}"}), 400

    annotated, summary, timeline = analyze_rows(rows)
    return jsonify({"rows": annotated, "summary": summary, "timeline": timeline})

# ---------------------------
# Entrypoint
# ---------------------------
if __name__ == "__main__":
    # Run directly (use this for local dev; in other cases you can use `flask run`)
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
