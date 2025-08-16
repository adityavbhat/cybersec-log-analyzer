from datetime import timedelta
from statistics import median
from collections import deque, defaultdict

SENSITIVE_PATTERNS = ["/admin","/wp-login","/login","/api/keys","/.git"]
CFG = {
    "ip_burst_threshold": 50,       # >50 reqs per IP per 60s
    "error_burst_threshold": 10,    # >10 5xx in 120s
    "window_ip_seconds": 60,
    "window_error_seconds": 120,
    "large_bytes_percentile": 95,   # we’ll approximate with a high cutoff
}

def _iso(dt):
    try:
        # RFC3339-ish
        return dt.strftime("%Y-%m-%dT%H:%M:%S%z") or dt.isoformat()
    except Exception:
        return None

def _percentile(values, p):
    if not values:
        return 0
    vals = sorted(values)
    k = max(0, min(len(vals)-1, round((p/100.0)*(len(vals)-1))))
    return vals[k]

def detect_anomalies(rows):
    # Precompute thresholds and rolling windows
    bytes_all = [r["bytes_sent"] for r in rows]
    big_thr = _percentile(bytes_all, CFG["large_bytes_percentile"]) if rows else 0

    # Sliding windows
    per_ip_windows = defaultdict(deque)     # ip -> timestamps in last 60s
    error_window = deque()                  # timestamps of 5xx in last 120s

    out_rows = []
    by_minute = defaultdict(lambda: {"total":0,"errors":0})

    for r in rows:
        ts = r["timestamp"]
        ip = r["src_ip"]
        status = r["status"]

        # Update minute summary
        minute = ts.replace(second=0, microsecond=0)
        by_minute[minute]["total"] += 1
        if 500 <= status <= 599:
            by_minute[minute]["errors"] += 1

        # Maintain IP window (60s)
        w_ip = per_ip_windows[ip]
        w_ip.append(ts)
        cutoff_ip = ts - timedelta(seconds=CFG["window_ip_seconds"])
        while w_ip and w_ip[0] < cutoff_ip:
            w_ip.popleft()

        # Maintain error window (120s)
        if 500 <= status <= 599:
            error_window.append(ts)
        cutoff_err = ts - timedelta(seconds=CFG["window_error_seconds"])
        while error_window and error_window[0] < cutoff_err:
            error_window.popleft()

        reasons = []
        score = 0.0

        # 1) IP burst
        if len(w_ip) > CFG["ip_burst_threshold"]:
            reasons.append(f"High request rate from {ip} in {CFG['window_ip_seconds']}s window")
            score += 0.45

        # 2) Error burst
        if len(error_window) > CFG["error_burst_threshold"]:
            reasons.append("Elevated 5xx error volume in last 2 minutes")
            score += 0.35

        # 3) Large transfer
        if r["bytes_sent"] > big_thr > 0:
            reasons.append(f"Unusually large response size (> P{CFG['large_bytes_percentile']})")
            score += 0.25

        # 4) Sensitive path
        path = (r.get("url_path") or "").lower()
        if any(p in path for p in SENSITIVE_PATTERNS):
            reasons.append("Access to sensitive path")
            score += 0.3

        score = min(score, 1.0)

        out_rows.append({
            "timestamp": _iso(ts),
            "src_ip": r["src_ip"],
            "dest_host": r["dest_host"],
            "url_path": r["url_path"],
            "status": r["status"],
            "bytes_sent": r["bytes_sent"],
            "user_agent": r["user_agent"],
            "anomalous": bool(reasons),
            "reasons": reasons,
            "confidence": round(score, 2),
        })

    timeline = [{"minute": _iso(k), "total": v["total"], "errors": v["errors"]}
                for k,v in sorted(by_minute.items(), key=lambda x: x[0])]

    return {
        "rows": out_rows,
        "summary": {
            "total_rows": len(rows),
            "big_bytes_threshold": int(big_thr),
            "total_anomalies": sum(1 for r in out_rows if r["anomalous"]),
        },
        "timeline": timeline,
    }
