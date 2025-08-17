CyberSec Log Analyzer

A simple full-stack prototype for cybersecurity log analysis.
This app lets you:

Log in (with basic demo credentials).

Upload log files (CSV or .log format).

Parse and visualize logs in a timeline.

Detect anomalies and highlight them with confidence scores + reasons.

It’s built with Next.js (TypeScript) for the frontend and Flask (Python) for the backend.

Features

Secure login screen (demo only, not production).

Upload and parse logs (supports CSV and .log).

Timeline view of events grouped by minute.

Anomaly detection rules:

Access to sensitive paths (like /admin, /api/keys).

Server error spikes (5xx).

Large request sizes (above P95).

Confidence score + explanation for every anomaly.

Project Structure
cybersec-log-analyzer/
│
├── backend/ # Flask API for log parsing + anomaly detection
│ └── app.py
│
├── frontend/ # Next.js frontend
│ ├── src/
│ ├── package.json
│ └── tailwind.config.ts
│
├── sample_logs/ # Example log files
│ └── zscaler_like_sample.csv
│
└── README.md

Getting Started

1. Backend (Flask + Python)
   cd backend
   python -m venv venv

# macOS/Linux

source venv/bin/activate

# Windows

venv\Scripts\activate

pip install -r requirements.txt
python app.py

Backend will start on http://127.0.0.1:5000.

2. Frontend (Next.js + TypeScript)
   cd frontend
   npm install
   npm run dev

Frontend will start on http://localhost:3000.

3. Demo Credentials

Use these to log in:

Username: admin  
Password: password123

How Anomaly Detection Works

The backend uses a mix of rule-based and simple statistical checks. For now:

Sensitive paths (/login, /admin, /api/keys) are flagged.

Any spike in server errors (5xx) gets flagged.

Requests above the 95th percentile (P95) of bytes_sent are flagged.

Each anomaly comes with:

The reason why it was flagged.

A confidence score between 0.2 and 0.9.

Example Output
Total Rows: 10
Anomalies: 9
P95 Bytes: 7639

timestamp src_ip dest_host url_path status bytes_sent anomalous confidence reasons
2025-08-08T14:00:10Z 10.0.0.5 example.com /login 302 850 Yes 0.30 Access to sensitive path
2025-08-08T14:00:18Z 10.0.0.8 api.example.com /api/keys 200 5000 Yes 0.30 Access to sensitive path
2025-08-08T14:00:40Z 10.0.0.5 example.com /home 503 100 Yes 0.35 Server error status (5xx)
...

Deployment

Frontend can be deployed to Vercel.

Backend can be deployed to PythonAnywhere, Heroku, or GCP App Engine.

For local dev, just make sure your frontend points to the backend with the NEXT_PUBLIC_API_URL variable.

Deliverables

✅ Source code in this repo
✅ README with setup + explanation
✅ Sample logs in sample_logs/
✅ Demo video (attached separately)
⬜ (Optional) Live demo link
