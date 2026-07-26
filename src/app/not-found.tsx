import Link from "next/link";

export const metadata = {
  title: "Not found · TerminalX",
};

/**
 * Root not-found. Handles any unmatched URL across the app. It renders under the
 * root layout (which provides <html>/<body>), so it only supplies the page body.
 */
export default function NotFound() {
  return (
    <div className="flex min-h-dvh items-center justify-center bg-[#0a0b10] px-4 text-[#e6f0e4]">
      <div className="w-full max-w-md rounded-lg border border-[#1a1d24] bg-[#0f1117] p-6 text-center">
        <p className="text-[13px] uppercase tracking-wider text-[#6b7569]">404</p>
        <h1 className="mt-2 text-lg font-semibold">This page doesn&apos;t exist</h1>
        <p className="mt-2 text-sm leading-6 text-[#a8b3a6]">
          The address you followed isn&apos;t part of TerminalX, or it has moved.
        </p>
        <Link
          href="/dashboard"
          className="mt-5 inline-flex min-h-10 items-center justify-center rounded-md border border-[#00cc6e] bg-[#002a17] px-4 text-sm font-medium text-[#00ff88] transition-colors hover:bg-[#00ff88]/10 focus-visible:ring-2 focus-visible:ring-[#00ff88]"
        >
          Back to dashboard
        </Link>
      </div>
    </div>
  );
}
