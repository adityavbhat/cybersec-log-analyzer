"use client";
import { useState, useEffect } from "react";
import { analyzeFile } from "@/lib/api";
import { useRouter } from "next/navigation";

type Row = {
  timestamp: string; src_ip: string; dest_host: string; url_path: string;
  status: number; bytes_sent: number; user_agent: string;
  anomalous: boolean; reasons: string[]; confidence: number;
};
type Summary = { total_rows: number; total_anomalies: number; big_bytes_threshold: number };

export default function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [timeline, setTimeline] = useState<{minute:string; total:number; errors:number}[]>([]);
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const t = localStorage.getItem("token");
    if (!t) router.replace("/");
  }, [router]);

  async function onAnalyze() {
    const token = localStorage.getItem("token") || "";
    if (!file || !token) return;
    setLoading(true); setError("");
    try {
      const res = await analyzeFile(file, token);
      setRows(res.rows); setSummary(res.summary); setTimeline(res.timeline);
    } catch (e: any) {
      setError(e.message || "Analyze failed");
    } finally { setLoading(false); }
  }

  return (
    <main className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <input type="file" accept=".csv,.log,.txt" onChange={(e)=>setFile(e.target.files?.[0]||null)} />
        <button onClick={onAnalyze} disabled={!file||loading}
                className="bg-green-600 hover:bg-green-500 px-4 py-2 rounded-lg disabled:opacity-50">
          {loading ? "Analyzing…" : "Analyze"}
        </button>
        <button onClick={()=>{localStorage.removeItem("token"); router.push("/");}}
                className="px-3 py-2 rounded-lg bg-slate-800 border border-slate-700">
          Sign out
        </button>
      </div>

      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="text-slate-400 text-sm">Total Rows</div>
            <div className="text-2xl font-semibold">{summary.total_rows}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="text-slate-400 text-sm">Anomalies</div>
            <div className={`text-2xl font-semibold ${summary.total_anomalies>0?"text-amber-300":""}`}>{summary.total_anomalies}</div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div className="text-slate-400 text-sm">P95 Bytes</div>
            <div className="text-2xl font-semibold">{summary.big_bytes_threshold}</div>
          </div>
        </div>
      )}

      {rows.length>0 && (
        <div className="overflow-auto rounded-xl border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 sticky top-0">
              <tr className="text-left">
                {["timestamp","src_ip","dest_host","url_path","status","bytes_sent","anomalous","confidence","reasons"].map(h=>(
                  <th key={h} className="px-3 py-2 font-semibold border-b border-slate-800">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r,i)=>(
                <tr key={i} className={r.anomalous?"bg-amber-950/30":""}>
                  <td className="px-3 py-2 border-b border-slate-900 whitespace-nowrap">{r.timestamp}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.src_ip}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.dest_host}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.url_path}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.status}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.bytes_sent}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.anomalous?"Yes":"No"}</td>
                  <td className="px-3 py-2 border-b border-slate-900">{r.confidence.toFixed(2)}</td>
                  <td className="px-3 py-2 border-b border-slate-900 max-w-[28rem]">{r.reasons?.join("; ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {timeline.length>0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="font-semibold mb-2">Timeline (per minute)</div>
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {timeline.map((t,i)=>(
              <li key={i} className="flex justify-between bg-slate-800/60 rounded-lg px-3 py-2">
                <span className="text-slate-300">{t.minute}</span>
                <span className="text-slate-200">total: {t.total}, 5xx: {t.errors}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && <div className="text-red-400 text-sm">{error}</div>}
    </main>
  );
}
