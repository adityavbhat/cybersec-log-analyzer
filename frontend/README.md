CyberSec Log Analyzer

A full-stack cybersecurity log analysis prototype.
This app allows users to:

Log in (basic authentication).

Upload log files (e.g., ZScaler-style CSV, server logs).

Parse & analyze logs into a timeline and anomaly report.

Highlight anomalies with reasons + confidence scores.

Built with Next.js (TypeScript) on the frontend and Flask (Python) on the backend.

🚀 Features

Secure login screen (dummy credentials for demo).

File upload + parsing of logs (.csv, .log).

Timeline of events grouped per minute.

Anomaly detection based on:

Access to sensitive paths (e.g., /admin, /api/keys).

Server error spikes (5xx).

Large request sizes (above P95).

Confidence score + explanation for each anomaly.

📂 Project Structure
cybersec-log-analyzer/
│
├── backend/ # Flask API for file upload & analysis
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
└── README.md # Project instructions

🛠️ Setup & Run Locally

1. Backend (Flask + Python)
   cd backend
   python -m venv venv
   source venv/bin/activate # on macOS/Linux
   venv\Scripts\activate # on Windows

pip install -r requirements.txt
python app.py

Backend will start at: http://127.0.0.1:5000

2. Frontend (Next.js + TypeScript)
   cd frontend
   npm install
   npm run dev

Frontend will start at: http://localhost:3000

3. Credentials

Use these demo credentials to sign in:

Username: admin
Password: password123

🤖 AI Anomaly Detection

Anomalies are flagged using rule-based + statistical checks:

Sensitive paths (/login, /admin, /api/keys).

Unusual errors (spikes in 5xx statuses).

Requests above 95th percentile (P95) in bytes_sent.

Each flagged entry includes:

Reason why it was flagged.

Confidence score (0.2–0.9).

📊 Example Output
Total Rows: 10
Anomalies: 9
P95 Bytes: 7639

timestamp src_ip dest_host url_path status bytes_sent anomalous confidence reasons
2025-08-08T14:00:10Z 10.0.0.5 example.com /login 302 850 Yes 0.30 Access to sensitive path
2025-08-08T14:00:18Z 10.0.0.8 api.example.com /api/keys 200 5000 Yes 0.30 Access to sensitive path
2025-08-08T14:00:40Z 10.0.0.5 example.com /home 503 100 Yes 0.35 Server error status (5xx)
...

📦 Deployment

Frontend can be deployed to Vercel.

Backend can be deployed to PythonAnywhere / Heroku / GCP App Engine.

For local dev, ensure frontend points to your backend URL (NEXT_PUBLIC_API_URL).

🎥 Demo Video

As part of the submission, please see the attached video walkthrough where I explain:

App architecture (frontend + backend).

How login + upload works.

How anomaly detection is performed.

Example run with the provided log file.

📌 Deliverables

✅ GitHub repo with code.

✅ README.md with setup + explanation.

✅ Sample log file in sample_logs/.

✅ Video walkthrough (attached separately).
