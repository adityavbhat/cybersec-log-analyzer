// Force absolute URL to the Flask backend. No rewrites, no proxy.
const API_BASE = "http://127.0.0.1:5001";

export async function login(username: string, password: string) {
  console.log("POST", `${API_BASE}/api/login`); // debug
  const r = await fetch(`${API_BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json() as Promise<{ token: string }>;
}

export async function analyzeFile(file: File, token: string) {
  const fd = new FormData();
  fd.append("file", file);
  console.log("POST", `${API_BASE}/api/analyze`); // debug
  const r = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
