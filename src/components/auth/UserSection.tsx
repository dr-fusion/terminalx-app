"use client";

import { LogOut, Shield } from "lucide-react";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";

function getInitials(username: string): string {
  return username.slice(0, 2).toUpperCase();
}

export function UserSection() {
  const { user, isLoading, authMode, logout } = useAuth();

  if (authMode === "none" || isLoading) {
    return null;
  }

  if (!user) {
    return null;
  }

  return (
    <div className="border-t border-[#2A2D3A] px-3 py-3">
      <div className="flex items-center gap-2">
        {/* Avatar */}
        <Avatar className="h-8 w-8">
          <AvatarFallback className="bg-[#3B82F6] text-white text-xs font-medium">
            {getInitials(user.username)}
          </AvatarFallback>
        </Avatar>

        {/* User info */}
        <div className="flex flex-1 min-w-0 flex-col">
          <span className="text-[13px] text-[#E4E4E7] font-medium truncate">{user.username}</span>
          <Badge
            variant="secondary"
            className={`w-fit text-[10px] px-1.5 py-0 h-4 ${
              user.role === "admin"
                ? "bg-[#3B82F6]/20 text-[#3B82F6]"
                : "bg-[#6B7280]/20 text-[#6B7280]"
            }`}
          >
            {user.role}
          </Badge>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1">
          {user.role === "admin" && (
            <Link
              href="/admin"
              className="p-1.5 text-[#6B7280] hover:text-[#3B82F6] transition-colors"
              title="Admin panel"
              aria-label="Admin panel"
            >
              <Shield size={14} />
            </Link>
          )}
          <button
            onClick={logout}
            className="p-1.5 text-[#6B7280] hover:text-[#EF4444] transition-colors"
            title="Sign out"
            aria-label="Sign out"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
