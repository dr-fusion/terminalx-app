"use client";

import { useState, useEffect, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Loader2, AlertCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";

type AuthMode = "none" | "password" | "local" | "google";

export default function LoginPage() {
  const router = useRouter();
  const [authMode, setAuthMode] = useState<AuthMode | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);

  useEffect(() => {
    // Check URL for OAuth error params
    const params = new URLSearchParams(window.location.search);
    const oauthError = params.get("error");
    if (oauthError) {
      const errorMessages: Record<string, string> = {
        oauth_denied: "Google sign-in was cancelled",
        oauth_invalid: "Invalid OAuth response. Please try again.",
        oauth_failed: "Google authentication failed. Please try again.",
        email_not_verified: "Your Google email is not verified",
        not_allowed: "Your email is not in the allowed list. Contact admin.",
      };
      setError(errorMessages[oauthError] || "Authentication failed");
      // Clean up URL
      window.history.replaceState({}, "", "/login");
    }
  }, []);

  useEffect(() => {
    async function checkAuth() {
      try {
        const res = await fetch("/api/auth/me");
        const data = await res.json();

        if (res.ok && data.username) {
          // Already logged in
          window.location.href = "/";
          return;
        }

        // Set auth mode from response (included even in 401)
        const mode = data.authMode || data.mode;
        if (mode) {
          setAuthMode(mode as AuthMode);
          if (mode === "none") {
            window.location.href = "/";
            return;
          }
        }
      } catch {
        // Default to local mode if auth check fails
        setAuthMode("local");
      } finally {
        setCheckingAuth(false);
      }
    }

    checkAuth();
  }, [router, authMode]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const body: Record<string, string> = { password };
      if (authMode === "local") {
        body.username = username;
      }

      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        setError("Invalid credentials");
        setIsSubmitting(false);
        return;
      }

      // Hard redirect to ensure the cookie is sent with the request
      window.location.href = "/";
    } catch {
      setError("Invalid credentials");
      setIsSubmitting(false);
    }
  }

  if (checkingAuth) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#0D0F12]">
        <Loader2 className="h-6 w-6 animate-spin text-[#3B82F6]" />
      </div>
    );
  }

  return (
    <div className="flex h-screen items-center justify-center bg-[#0D0F12] px-4">
      <div className="w-full max-w-[400px]">
        {/* Wordmark */}
        <div className="mb-6 text-center">
          <h1
            className="text-[24px] font-bold text-[#3B82F6]"
            style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
          >
            TerminalX
          </h1>
        </div>

        <Card className="border-[#2A2D3A] bg-[#151820]">
          <CardContent className="pt-6">
            {authMode === "google" ? (
              <div className="flex flex-col gap-4">
                <Button
                  onClick={() => { window.location.href = "/api/auth/google"; }}
                  className="w-full bg-white text-[#1f1f1f] hover:bg-[#f2f2f2] font-medium flex items-center justify-center gap-3"
                >
                  <svg width="18" height="18" viewBox="0 0 48 48">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                  </svg>
                  Sign in with Google
                </Button>

                {error && (
                  <Alert variant="destructive" className="border-[#EF4444]/30 bg-[#EF4444]/10">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="text-[#EF4444]">
                      {error}
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                {authMode === "local" && (
                  <div className="flex flex-col gap-2">
                    <Label htmlFor="username" className="text-[#E4E4E7]">
                      Username
                    </Label>
                    <Input
                      id="username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Enter username"
                      autoComplete="username"
                      className="border-[#2A2D3A] bg-[#0D0F12] text-[#E4E4E7] placeholder:text-[#6B7280]"
                    />
                  </div>
                )}

                <div className="flex flex-col gap-2">
                  <Label htmlFor="password" className="text-[#E4E4E7]">
                    Password
                  </Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    autoComplete="current-password"
                    className="border-[#2A2D3A] bg-[#0D0F12] text-[#E4E4E7] placeholder:text-[#6B7280]"
                  />
                </div>

                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-[#3B82F6] text-white hover:bg-[#2563EB] disabled:opacity-50"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Signing in...
                    </>
                  ) : (
                    "Sign In"
                  )}
                </Button>

                {error && (
                  <Alert variant="destructive" className="border-[#EF4444]/30 bg-[#EF4444]/10">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription className="text-[#EF4444]">
                      {error}
                    </AlertDescription>
                  </Alert>
                )}
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
