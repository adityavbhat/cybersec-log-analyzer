# backend/log_parser.py
import csv, io, re
from dateutil import parser as dtparser

SYNONYMS = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "event_time", "ts", "logtime"],
    "src_ip": ["src_ip", "source_ip", "client_ip", "ip", "src", "srcaddr"],
    "dest_host": ["dest_host", "host", "hostname", "dst_host", "destination_host", "server", "remote_host"],
    "url_path": ["url_path", "path", "uri", "request", "url", "cs_uri_stem"],
    "status": ["status", "status_code", "code", "sc_status", "http_status"],
    "bytes_sent": ["bytes_sent", "bytes", "size", "bytes_out", "sc_bytes", "sent_bytes", "out_bytes"],
    "user_agent": ["user_agent", "ua", "agent", "cs_user_agent"],
}

DATE_LIKE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{4}/\d{2}/\d{2}")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HOSTLIKE = re.compile(r"^[A-Za-z0-9\.\-]+(?:\.[A-Za-z]{2,})$")
PATHLIKE = re.compile(r"^/|/")

def _norm(s: str) -> str:
    return (
        (s or "")
        .lstrip("\ufeff")
        .strip()
        .strip('"')
        .strip("'")
        .replace("\u200b", "")
        .lower()
    )

def _to_dt(x):
    try:
        return dtparser.parse(str(x))
    except Exception:
        return None

def _preprocess(raw_bytes: bytes) -> list[str]:
    text = raw_bytes.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for ln in text.split("\n"):
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("sep="):
            continue
        if s in ("@'", "'@"):    
            continue
        lines.append(ln.lstrip("\ufeff"))
    return lines

def _detect_delim(sample_line: str) -> str:
    try:
        dialect = csv.Sniffer().sniff(sample_line, delimiters=[",", "\t", ";", "|"])
        return dialect.delimiter
    except Exception:
        for d in [",", "\t", ";", "|"]:
            if d in sample_line:
                return d
        return ","

def _pick_timestamp_key(headers_norm, rows_sample):
    syn = { _norm(c) for c in SYNONYMS["timestamp"] }
    for h in headers_norm:
        if h in syn:
            return h
    if rows_sample:
        for h in headers_norm:
            vals = [r.get(h) for r in rows_sample]
            good = sum(1 for v in vals if v and (DATE_LIKE.search(str(v)) or _to_dt(v)))
            seen = sum(1 for v in vals if v not in (None, ""))
            if seen and good / seen >= 0.6:
                return h
    return None

def _auto_detect(headers_norm, rows_sample, keymap):
    # Only guess for fields we didn't map via synonyms
    def col_values(h):
        return [r.get(h) for r in rows_sample]

    # src_ip: mostly IPv4-looking values
    if not keymap.get("src_ip"):
        for h in headers_norm:
            vals = col_values(h)
            seen = [v for v in vals if v]
            if not seen: 
                continue
            good = sum(1 for v in seen if IPV4.match(str(v)))
            if good / len(seen) >= 0.6:
                keymap["src_ip"] = h
                break

    # status: integers mostly in HTTP status range
    if not keymap.get("status"):
        for h in headers_norm:
            ok, seen = 0, 0
            for v in col_values(h):
                if v in (None, ""): 
                    continue
                seen += 1
                try:
                    iv = int(float(str(v)))
                    if 100 <= iv <= 599:
                        ok += 1
                except Exception:
                    pass
            if seen and ok / seen >= 0.6:
                keymap["status"] = h
                break

    # bytes_sent: biggish integers (varied, typically > 0)
    if not keymap.get("bytes_sent"):
        for h in headers_norm:
            ints = []
            for v in col_values(h):
                if v in (None, ""): 
                    continue
                try:
                    ints.append(int(float(str(v))))
                except Exception:
                    pass
            if len(ints) >= 3 and sum(1 for x in ints if x > 0) / len(ints) >= 0.6:
                keymap["bytes_sent"] = h
                break

    # dest_host: host-ish strings (has dots, letters)
    if not keymap.get("dest_host"):
        for h in headers_norm:
            vals = [str(v) for v in col_values(h) if v]
            if not vals: 
                continue
            good = sum(1 for v in vals if HOSTLIKE.match(v))
            if good / len(vals) >= 0.6:
                keymap["dest_host"] = h
                break

    # url_path: has / or starts with /
    if not keymap.get("url_path"):
        for h in headers_norm:
            vals = [str(v) for v in col_values(h) if v]
            if not vals: 
                continue
            good = sum(1 for v in vals if PATHLIKE.search(v))
            if good / len(vals) >= 0.6:
                keymap["url_path"] = h
                break

    # user_agent: long-ish strings with slashes or typical UA tokens
    if not keymap.get("user_agent"):
        tokens = ("Mozilla", "Chrome", "Safari", "Edge", "curl", "Postman", "/")
        for h in headers_norm:
            vals = [str(v) for v in col_values(h) if v]
            if not vals: 
                continue
            good = sum(1 for v in vals if len(v) >= 6 and any(t in v for t in tokens))
            if good / len(vals) >= 0.5:
                keymap["user_agent"] = h
                break

def read_csv_file(file_storage):
    raw = file_storage.read()
    lines = _preprocess(raw)
    if not lines:
        raise ValueError("Uploaded file is empty.")

    header_line = lines[0]
    delim = _detect_delim(header_line)
    header_cells = next(csv.reader([header_line], delimiter=delim))
    header_norm = [_norm(h) for h in header_cells]

    data_text = "\n".join(lines[1:])
    reader = csv.DictReader(io.StringIO(data_text), fieldnames=header_norm, delimiter=delim)

    rows = []
    sample_rows = []
    for i, r in enumerate(reader):
        if i < 15:
            sample_rows.append(r)
        rows.append(r)

    # Build initial keymap from synonyms
    hdr_set = set(header_norm)
    keymap = {}
    for target, cand in SYNONYMS.items():
        found = None
        for c in cand:
            nc = _norm(c)
            if nc in hdr_set:
                found = nc
                break
        keymap[target] = found

    # Pick/auto-detect timestamp
    ts_key = keymap.get("timestamp") or _pick_timestamp_key(header_norm, sample_rows)
    keymap["timestamp"] = ts_key

    # Auto-detect missing fields
    _auto_detect(header_norm, sample_rows, keymap)

    print("DEBUG header_line:", header_line)
    print("DEBUG header_norm:", header_norm)
    print("DEBUG delimiter:", repr(delim))
    print("DEBUG keymap:", keymap)

    if not keymap.get("timestamp"):
        raise ValueError("No 'timestamp' (or synonym like time/@timestamp) column found.")

    def get_val(row, key, default=""):
        k = keymap.get(key)
        return (row.get(k) if k else default) or default

    def get_int(row, key, default=0):
        try:
            return int(float(get_val(row, key, default)))
        except Exception:
            return default

    out = []
    for r in rows:
        ts = _to_dt(get_val(r, "timestamp"))
        if not ts:
            continue
        out.append({
            "timestamp": ts,
            "src_ip": get_val(r, "src_ip", ""),
            "dest_host": get_val(r, "dest_host", ""),
            "url_path": get_val(r, "url_path", ""),
            "status": get_int(r, "status", 0),
            "bytes_sent": get_int(r, "bytes_sent", 0),
            "user_agent": get_val(r, "user_agent", ""),
        })

    if not out:
        raise ValueError("No valid rows parsed. Ensure there is a 'timestamp' column and data rows.")
    out.sort(key=lambda x: x["timestamp"])
    return out
