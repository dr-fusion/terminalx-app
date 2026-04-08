"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";

export type AuthMode = "none" | "password" | "local" | "google";

export interface AuthUser {
  username: string;
  role: "admin" | "user";
}

interface UseAuthReturn {
  user: AuthUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  authMode: AuthMode;
  logout: () => Promise<void>;
}

export function useAuth(): UseAuthReturn {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authMode, setAuthMode] = useState<AuthMode>("none");
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;

    async function fetchAuth() {
      try {
        const res = await fetch("/api/auth/me");
        if (!res.ok) {
          if (!cancelled) {
            setUser(null);
            setIsLoading(false);
          }
          return;
        }
        const data = await res.json();
        if (!cancelled) {
          setAuthMode(data.authMode ?? data.mode ?? "none");
          if (data.username) {
            setUser({ username: data.username, role: data.role || "user" });
          } else {
            setUser(null);
          }
        }
      } catch {
        if (!cancelled) {
          setUser(null);
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    fetchAuth();
    return () => {
      cancelled = true;
    };
  }, []);

  const logout = useCallback(async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      // ignore
    }
    setUser(null);
    router.push("/login");
  }, [router]);

  return {
    user,
    isLoading,
    isAuthenticated: user !== null,
    authMode,
    logout,
  };
}
