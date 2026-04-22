"use client";

import { useEffect, useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Loader2 } from "lucide-react";

type AuthMode = "none" | "password" | "local" | "google";

const OAUTH_ERRORS: Record<string, string> = {
  oauth_denied: "google sign-in was cancelled.",
  oauth_invalid: "invalid oauth response. try again.",
  oauth_failed: "google authentication failed.",
  email_not_verified: "your google email is not verified.",
  not_allowed: "your email is not allow-listed. ask the admin.",
};

export default function LoginPage() {
  const router = useRouter();
  const [authMode, setAuthMode] = useState<AuthMode | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oauthError = params.get("error");
    if (oauthError) {
      setError(OAUTH_ERRORS[oauthError] ?? "authentication failed.");
      window.history.replaceState({}, "", "/login");
    }
  }, []);

  useEffect(() => {
    async function check() {
      try {
        const res = await fetch("/api/auth/me");
        const data = await res.json();
        if (res.ok && data.username) {
          window.location.href = "/";
          return;
        }
        const mode = data.authMode || data.mode;
        if (mode) {
          setAuthMode(mode as AuthMode);
          if (mode === "none") {
            window.location.href = "/";
            return;
          }
        }
      } catch {
        setAuthMode("local");
      } finally {
        setChecking(false);
      }
    }
    check();
  }, [router]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const body: Record<string, string> = { password };
      if (authMode === "local") body.username = username;
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        setError("invalid credentials.");
        setIsSubmitting(false);
        return;
      }
      window.location.href = "/";
    } catch {
      setError("invalid credentials.");
      setIsSubmitting(false);
    }
  }

  if (checking) {
    return (
      <div className="flex h-dvh items-center justify-center bg-[#0a0b10]">
        <Loader2 className="h-6 w-6 animate-spin text-[#00cc6e]" />
      </div>
    );
  }

  return (
    <div className="crt-scanlines relative h-dvh flex items-center justify-center bg-[#0a0b10] px-4 overflow-hidden">
      {/* Radial vignette */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse at center, transparent 50%, rgba(0, 0, 0, 0.7) 100%)",
        }}
      />

      <div className="relative w-full max-w-[440px] z-10">
        {/* Big brand mark */}
        <div className="flex items-baseline justify-center gap-0 text-[48px] md:text-[56px] font-bold tracking-tight text-[#e6f0e4] mb-3">
          <span
            className="text-[#00ff88]"
            style={{ textShadow: "0 0 20px rgba(0, 255, 136, 0.6)" }}
          >
            [
          </span>
          <span>terminalx</span>
          <span
            className="stx-cursor"
            style={{ height: "0.75em", width: "0.5em", marginLeft: 4 }}
          />
        </div>
        <p className="text-center text-[12px] text-[#6b7569] mb-8">your terminal, in a tab.</p>

        <div className="bg-[#0f1117] border border-[#1a1d24] rounded p-5">
          {authMode === "google" ? (
            <div className="flex flex-col gap-3">
              <button
                onClick={() => {
                  window.location.href = "/api/auth/google";
                }}
                className="w-full flex items-center justify-center gap-3 px-3 py-2.5 rounded
                  bg-[#14161e] border border-[#252933] hover:border-[#00cc6e] text-[#e6f0e4] text-[13px] transition-colors"
              >
                <svg width="16" height="16" viewBox="0 0 48 48">
                  <path
                    fill="#EA4335"
                    d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
                  />
                  <path
                    fill="#4285F4"
                    d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
                  />
                  <path
                    fill="#34A853"
                    d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
                  />
                </svg>
                sign in with google
              </button>

              <button
                disabled
                className="w-full flex items-center justify-center gap-3 px-3 py-2.5 rounded
                  bg-[#0a0b10] border border-[#1a1d24] text-[#6b7569] text-[13px] cursor-not-allowed"
                title="coming soon"
              >
                sign in with tailscale
                <span className="text-[9px] uppercase tracking-wider bg-[#1a1d24] text-[#6b7569] px-1 py-0.5 rounded">
                  soon
                </span>
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-3">
              {authMode === "local" && (
                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="username"
                    className="text-[10px] uppercase tracking-wider text-[#6b7569]"
                  >
                    username
                  </label>
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    className="px-2.5 py-1.5 rounded bg-[#07080c] border border-[#252933]
                      text-[13px] text-[#e6f0e4] placeholder:text-[#6b7569]/50
                      focus:outline-none focus:border-[#00ff88] transition-colors"
                  />
                </div>
              )}
              <div className="flex flex-col gap-1.5">
                <label
                  htmlFor="password"
                  className="text-[10px] uppercase tracking-wider text-[#6b7569]"
                >
                  password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  className="px-2.5 py-1.5 rounded bg-[#07080c] border border-[#252933]
                    text-[13px] text-[#e6f0e4] placeholder:text-[#6b7569]/50
                    focus:outline-none focus:border-[#00ff88] transition-colors"
                />
              </div>
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full flex items-center justify-center gap-2 mt-1 px-3 py-2 rounded
                  bg-[#002a17] border border-[#00cc6e] text-[#00ff88] text-[13px] font-medium
                  hover:bg-[#00ff88]/10 disabled:opacity-50 transition-colors"
                style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> signing in…
                  </>
                ) : (
                  "sign in →"
                )}
              </button>
            </form>
          )}

          {error && (
            <div className="mt-3 flex items-start gap-2 px-2.5 py-2 rounded bg-[#ff5c5c]/10 border border-[#ff5c5c]/30 text-[#ff5c5c] text-[11px]">
              <AlertCircle size={12} className="mt-[1px] shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        <p className="text-center text-[10px] text-[#6b7569] mt-6">
          sessions live in tmux · auth via sso · no state in the browser
        </p>
      </div>
    </div>
  );
}
