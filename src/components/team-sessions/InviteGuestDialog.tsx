"use client";

import { useId, useRef, useState } from "react";
import { Check, Copy, LoaderCircle, UserPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface InviteGuestDialogProps {
  open: boolean;
  isSubmitting: boolean;
  error?: string | null;
  onOpenChange: (open: boolean) => void;
  onCreate: (membershipRole: "member" | "guest", expiresAtMs: number) => Promise<string>;
}

const EXPIRATIONS = [
  { value: "24h", label: "24 hours", durationMs: 24 * 60 * 60 * 1_000 },
  { value: "7d", label: "7 days", durationMs: 7 * 24 * 60 * 60 * 1_000 },
  { value: "30d", label: "30 days", durationMs: 30 * 24 * 60 * 60 * 1_000 },
] as const;

export function InviteGuestDialog({
  open,
  isSubmitting,
  error,
  onOpenChange,
  onCreate,
}: InviteGuestDialogProps) {
  const [role, setRole] = useState<"member" | "guest">("guest");
  const [expiration, setExpiration] = useState<(typeof EXPIRATIONS)[number]["value"]>("7d");
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  const inviteIntentRef = useRef<{
    role: "member" | "guest";
    expiration: (typeof EXPIRATIONS)[number]["value"];
    expiresAtMs: number;
  } | null>(null);
  const roleId = useId();
  const expirationId = useId();

  const close = (nextOpen: boolean) => {
    if (!nextOpen && isSubmitting) return;
    if (!nextOpen) {
      setToken(null);
      setCopied(false);
      setCopyError(null);
      inviteIntentRef.current = null;
    }
    onOpenChange(nextOpen);
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent showCloseButton={false}>
        {token ? (
          <>
            <DialogHeader>
              <DialogTitle>Invitation created</DialogTitle>
              <DialogDescription>
                Share this token through a secure channel. The recipient signs in at Team sessions →
                Join with invite, then pastes it. The token is shown once and can be revoked before
                redemption; Guest Session Shares remain revocable afterward.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2">
              <label htmlFor={`${roleId}-token`} className="text-xs font-medium">
                One-time invitation token
              </label>
              <textarea
                id={`${roleId}-token`}
                readOnly
                rows={4}
                value={token}
                spellCheck={false}
                className="w-full resize-none rounded-md border border-input bg-background p-3 text-xs leading-5 text-foreground focus-visible:ring-2 focus-visible:ring-ring"
                onFocus={(event) => event.currentTarget.select()}
              />
              {copyError ? (
                <p className="text-xs text-destructive" role="alert">
                  {copyError}
                </p>
              ) : null}
            </div>
            <DialogFooter>
              <DialogClose render={<Button type="button" variant="outline" className="min-h-10" />}>
                Done
              </DialogClose>
              <Button
                type="button"
                className="min-h-10"
                onClick={() => {
                  setCopyError(null);
                  void navigator.clipboard
                    .writeText(token)
                    .then(() => setCopied(true))
                    .catch(() =>
                      setCopyError("Could not copy automatically. Select and copy the token.")
                    );
                }}
              >
                {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                {copied ? "Copied" : "Copy token"}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const selected = EXPIRATIONS.find((option) => option.value === expiration);
              if (!selected) return;
              const previous = inviteIntentRef.current;
              const intent =
                previous?.role === role && previous.expiration === expiration
                  ? previous
                  : {
                      role,
                      expiration,
                      expiresAtMs: Date.now() + selected.durationMs,
                    };
              inviteIntentRef.current = intent;
              void onCreate(intent.role, intent.expiresAtMs)
                .then(setToken)
                .catch(() => undefined);
            }}
          >
            <DialogHeader>
              <div className="flex size-10 items-center justify-center rounded-full border border-border bg-background">
                <UserPlus className="size-5 text-primary" aria-hidden="true" />
              </div>
              <DialogTitle>Invite someone to this session</DialogTitle>
              <DialogDescription>
                An invitation verifies Team Membership only. Guests still need an explicit,
                revocable Session Share; members need Project Access before either can join as an
                Observer.
              </DialogDescription>
            </DialogHeader>
            <div className="mt-4 space-y-4">
              <div className="space-y-1.5">
                <label htmlFor={roleId} className="text-xs font-medium">
                  Access type
                </label>
                <select
                  id={roleId}
                  value={role}
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  onChange={(event) => {
                    inviteIntentRef.current = null;
                    setRole(event.target.value as "member" | "guest");
                  }}
                >
                  <option value="guest">Guest · requires session grant</option>
                  <option value="member">Member · requires project access</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label htmlFor={expirationId} className="text-xs font-medium">
                  Invitation expires
                </label>
                <select
                  id={expirationId}
                  value={expiration}
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  onChange={(event) => {
                    inviteIntentRef.current = null;
                    setExpiration(event.target.value as (typeof EXPIRATIONS)[number]["value"]);
                  }}
                >
                  {EXPIRATIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              {error ? (
                <p
                  className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
                  role="alert"
                >
                  {error}
                </p>
              ) : null}
            </div>
            <DialogFooter className="mt-5">
              <DialogClose
                render={
                  <Button
                    type="button"
                    variant="outline"
                    className="min-h-10"
                    disabled={isSubmitting}
                  />
                }
              >
                Cancel
              </DialogClose>
              <Button
                type="submit"
                className="min-h-10"
                disabled={isSubmitting}
                aria-busy={isSubmitting}
              >
                {isSubmitting ? (
                  <LoaderCircle
                    className="animate-spin motion-reduce:animate-none"
                    aria-hidden="true"
                  />
                ) : (
                  <UserPlus aria-hidden="true" />
                )}
                {isSubmitting ? "Creating" : "Create invitation"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
