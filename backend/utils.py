from dateutil import parser as dtparser
from datetime import datetime

ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"

def to_dt(x):
    if isinstance(x, datetime):
        return x
    try:
        return dtparser.parse(str(x))
    except Exception:
        return None

def iso(dt):
    try:
        return dt.strftime(ISO_FMT)
    except Exception:
        return None