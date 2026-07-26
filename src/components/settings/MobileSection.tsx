"use client";

import { useCallback, useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { Copy, RefreshCw, Smartphone, Trash2 } from "lucide-react";

interface PairingCode {
  code: string;
  expiresAt: number;
}

interface Device {
  id: string;
  name: string;
  createdAt: number;
  lastSeenAt: number;
  revokedAt: number | null;
}

function formatRelative(ms: number): string {
  const diff = Date.now() - ms;
  if (diff < 60_000) return "just now";
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function MobileSection() {
  const [code, setCode] = useState<PairingCode | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [status, setStatus] = useState<string | null>(null);
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [copied, setCopied] = useState(false);

  const loadDevices = useCallback(() => {
    let cancelled = false;
    fetch("/api/auth/devices")
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { devices: Device[] } | null) => {
        if (!cancelled && d) setDevices(d.devices);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    return loadDevices();
  }, [loadDevices]);

  useEffect(() => {
    if (!code) return;
    const tick = () => {
      const left = Math.max(0, Math.floor((code.expiresAt - Date.now()) / 1000));
      setSecondsLeft(left);
      if (left === 0) setCode(null);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [code]);

  // While a code is live, poll devices and detect the new pairing so we can
  // clear the QR and show a "paired" confirmation. Compares against the
  // code's issuance window (expiresAt - TTL) instead of array length to stay
  // correct if the user revokes a device in parallel.
  useEffect(() => {
    if (!code) return;
    const codeStartedAt = code.expiresAt - 120_000;
    const poll = setInterval(async () => {
      try {
        const res = await fetch("/api/auth/devices");
        if (!res.ok) return;
        const data = (await res.json()) as { devices: Device[] };
        setDevices(data.devices);
        const justPaired = data.devices.some(
          (d) => d.createdAt >= codeStartedAt && d.revokedAt === null
        );
        if (justPaired) {
          setCode(null);
          setStatus("paired");
          setTimeout(() => setStatus(null), 2500);
        }
      } catch {
        // ignore
      }
    }, 1500);
    return () => clearInterval(poll);
  }, [code]);

  const generate = async () => {
    setStatus("generating…");
    setCopied(false);
    try {
      const res = await fetch("/api/auth/pairing-codes", { method: "POST" });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        setStatus(body?.error ?? "failed");
        return;
      }
      const data = (await res.json()) as PairingCode;
      setCode(data);
      setStatus(null);
    } catch {
      setStatus("network error");
    }
  };

  const revoke = async (id: string) => {
    const res = await fetch(`/api/auth/devices?id=${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (res.ok) loadDevices();
  };

  // Refresh button — same behavior as initial load
  const handleRefresh = () => {
    loadDevices();
  };

  const copyCode = async () => {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Some environments block clipboard — the raw code is on-screen anyway.
    }
  };

  const qrPayload = code
    ? JSON.stringify({ code: code.code, serverUrl: window.location.origin })
    : null;

  const activeDevices = devices?.filter((d) => d.revokedAt === null) ?? [];
  const revokedDevices = devices?.filter((d) => d.revokedAt !== null) ?? [];

  return (
    <div>
      <div className="flex flex-col items-center gap-2 py-2">
        {qrPayload ? (
          <>
            <div className="rounded bg-white p-3">
              <QRCodeSVG value={qrPayload} size={192} level="M" />
            </div>
            <div className="text-[10px] text-[#899384]">expires in {secondsLeft}s · single use</div>
            <div className="flex items-center gap-2">
              <code className="font-mono text-[10px] text-[#a8b3a6] break-all">{code!.code}</code>
              <button
                onClick={copyCode}
                className="inline-flex items-center gap-1 rounded border border-[#252933] bg-[#07080c] px-1.5 py-0.5 text-[10px] text-[#899384] hover:text-[#e6f0e4]"
                title="copy code"
              >
                <Copy size={10} />
                {copied ? "copied" : "copy"}
              </button>
            </div>
            <button
              onClick={generate}
              className="mt-1 inline-flex items-center gap-1.5 text-[10px] text-[#899384] hover:text-[#e6f0e4]"
            >
              <RefreshCw size={10} /> new code
            </button>
          </>
        ) : (
          <button
            onClick={generate}
            className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10"
          >
            <Smartphone size={12} /> generate pairing code
          </button>
        )}
        {status && <span className="text-[11px] text-[#899384]">{status}</span>}
      </div>

      <p className="mt-2 text-[10px] leading-relaxed text-[#899384]">
        open the TerminalX mobile app, point it at this server, and scan the QR. the paired token
        lasts 24h and can be revoked below.
      </p>

      {devices !== null && (
        <div className="mt-4 border-t border-[#1a1d24] pt-3">
          <div className="mb-2 flex items-baseline justify-between">
            <h3 className="text-[11px] uppercase tracking-wider text-[#899384]">paired devices</h3>
            <button
              onClick={handleRefresh}
              className="text-[10px] text-[#899384] hover:text-[#e6f0e4]"
            >
              refresh
            </button>
          </div>
          {activeDevices.length === 0 && revokedDevices.length === 0 ? (
            <div className="text-[11px] text-[#899384]">no devices paired yet.</div>
          ) : (
            <div className="space-y-1">
              {activeDevices.map((d) => (
                <div
                  key={d.id}
                  className="flex items-center gap-2 rounded border border-[#1a1d24] bg-[#07080c] px-2 py-1.5 text-[11px]"
                >
                  <Smartphone size={12} className="text-[#5ccfe6]" />
                  <span className="min-w-0 flex-1 truncate text-[#e6f0e4]">{d.name}</span>
                  <span className="text-[10px] text-[#899384]">
                    last seen {formatRelative(d.lastSeenAt)}
                  </span>
                  <button
                    onClick={() => revoke(d.id)}
                    className="inline-flex items-center gap-1 rounded border border-[#ff5c5c]/40 px-1.5 py-0.5 text-[10px] text-[#ff5c5c] hover:bg-[#ff5c5c]/10"
                    title="revoke"
                  >
                    <Trash2 size={10} /> revoke
                  </button>
                </div>
              ))}
              {revokedDevices.map((d) => (
                <div
                  key={d.id}
                  className="flex items-center gap-2 rounded border border-[#1a1d24] bg-[#07080c]/40 px-2 py-1.5 text-[11px] opacity-60"
                >
                  <Smartphone size={12} className="text-[#899384]" />
                  <span className="min-w-0 flex-1 truncate text-[#899384] line-through">
                    {d.name}
                  </span>
                  <span className="text-[10px] text-[#899384]">
                    revoked {formatRelative(d.revokedAt!)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
