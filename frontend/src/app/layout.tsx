import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cybersecurity Log Analyzer",
  description: "Upload and analyze logs with anomaly detection",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100">
        <div className="mx-auto max-w-5xl p-6">
          <header className="mb-6">
            <h1 className="text-2xl font-bold">CyberSec Log Analyzer</h1>
            <p className="text-slate-400 text-sm">
              Login, upload logs, and review anomalies + timeline.
            </p>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
