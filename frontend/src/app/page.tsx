"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";

export default function LoginPage() {
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("password123");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const data = await login(username, password);
      localStorage.setItem("token", data.token);
      router.push("/analyze");
    } catch (err: any) {
      setError(err.message || "Login failed");
    }
  };

  return (
    <main className="flex items-center justify-center min-h-[70vh]">
      <form onSubmit={handleLogin} className="bg-slate-900 p-6 rounded-xl border border-slate-800 w-80 space-y-4">
        <h2 className="text-xl font-semibold">Login</h2>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <input className="bg-slate-800 px-3 py-2 rounded-lg w-full" placeholder="Username"
               value={username} onChange={(e)=>setUsername(e.target.value)} />
        <input type="password" className="bg-slate-800 px-3 py-2 rounded-lg w-full" placeholder="Password"
               value={password} onChange={(e)=>setPassword(e.target.value)} />
        <button type="submit" className="bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded-lg w-full">
          Sign in
        </button>
      </form>
    </main>
  );
}
