import requests
from io import BytesIO

BASE = "http://localhost:5001"

SAMPLE = """timestamp,src_ip,dest_host,url_path,status,bytes_sent,user_agent
2025-08-08T14:00:01Z,10.0.0.5,example.com,/home,200,1234,Mozilla/5.0
2025-08-08T14:00:10Z,10.0.0.5,example.com,/login,302,850,Mozilla/5.0
2025-08-08T14:00:12Z,10.0.0.5,example.com,/admin,200,950,Chrome/122
2025-08-08T14:00:18Z,10.0.0.8,api.example.com,/api/keys,200,5000,curl/8.0
2025-08-08T14:00:40Z,10.0.0.5,example.com,/home,503,100,Chrome/122
2025-08-08T14:00:41Z,10.0.0.5,example.com,/home,503,100,Chrome/122
2025-08-08T14:00:42Z,10.0.0.5,example.com,/home,503,100,Chrome/122
2025-08-08T14:00:43Z,10.0.0.5,example.com,/home,503,100,Chrome/122
2025-08-08T14:00:44Z,10.0.0.5,example.com,/home,503,100,Chrome/122
2025-08-08T14:02:00Z,10.0.0.9,example.org,/reports/weekly,200,9800,Edge/120
"""

print("Logging in...")
resp = requests.post(f"{BASE}/api/login", json={"username": "analyst", "password": "password123"})
resp.raise_for_status()
token = resp.json()["token"]
print("TOKEN:", token)

print("\nUploading sample log (inline bytes)...")
files = {
    "file": ("zscaler_like_sample.csv", BytesIO(SAMPLE.encode("utf-8")), "text/csv")
}
analyze_resp = requests.post(f"{BASE}/api/analyze",
                             headers={"Authorization": f"Bearer {token}"},
                             files=files)

if not analyze_resp.ok:
    print("Server said:", analyze_resp.text)
analyze_resp.raise_for_status()

result = analyze_resp.json()
print("\n=== Analysis Summary ===")
print(result["summary"])
print("\n=== First 2 Rows ===")
for row in result["rows"][:2]:
    print(row)
