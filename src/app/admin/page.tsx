"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Loader2, MoreHorizontal, Plus, ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface User {
  username: string;
  role: "admin" | "user";
  createdAt: string;
}

export default function AdminPage() {
  const router = useRouter();
  const { user, isLoading: authLoading, isAuthenticated } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoadingUsers, setIsLoadingUsers] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<string>("user");
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch("/api/users");
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users ?? data ?? []);
      }
    } catch {
      // ignore
    } finally {
      setIsLoadingUsers(false);
    }
  }, []);

  useEffect(() => {
    if (authLoading) return;
    if (!isAuthenticated || user?.role !== "admin") {
      router.push("/");
      return;
    }
    fetchUsers();
  }, [authLoading, isAuthenticated, user, router, fetchUsers]);

  async function handleCreateUser() {
    setCreateError(null);
    if (!newUsername.trim() || !newPassword.trim()) {
      setCreateError("Username and password are required");
      return;
    }
    setCreateLoading(true);
    try {
      const res = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: newUsername.trim(),
          password: newPassword,
          role: newRole,
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setCreateError(data.error ?? "Failed to create user");
        setCreateLoading(false);
        return;
      }
      setNewUsername("");
      setNewPassword("");
      setNewRole("user");
      setDialogOpen(false);
      fetchUsers();
    } catch {
      setCreateError("Failed to create user");
    } finally {
      setCreateLoading(false);
    }
  }

  async function handleChangeRole(username: string, newRole: "admin" | "user") {
    try {
      await fetch(`/api/users`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, role: newRole }),
      });
      fetchUsers();
    } catch {
      // ignore
    }
  }

  async function handleDeleteUser(username: string) {
    try {
      await fetch(`/api/users`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      fetchUsers();
    } catch {
      // ignore
    }
  }

  if (authLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#0a0b10]">
        <Loader2 className="h-6 w-6 animate-spin text-[#00cc6e]" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0b10] text-[#e6f0e4]">
      <div className="mx-auto max-w-3xl px-6 py-8">
        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="p-1.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
              title="Back to workspace"
              aria-label="Back to workspace"
            >
              <ArrowLeft size={18} />
            </Link>
            <h1 className="text-xl font-semibold text-[#e6f0e4]">User Management</h1>
          </div>

          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger
              render={
                <Button className="bg-[#00cc6e] text-white hover:bg-[#00ff88]">
                  <Plus className="mr-1.5 h-4 w-4" />
                  Add User
                </Button>
              }
            />
            <DialogContent className="border-[#1a1d24] bg-[#0f1117]">
              <DialogHeader>
                <DialogTitle className="text-[#e6f0e4]">Create New User</DialogTitle>
              </DialogHeader>
              <div className="flex flex-col gap-4 pt-2">
                <div className="flex flex-col gap-2">
                  <Label htmlFor="new-username" className="text-[#e6f0e4]">
                    Username
                  </Label>
                  <Input
                    id="new-username"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Enter username"
                    className="border-[#1a1d24] bg-[#0a0b10] text-[#e6f0e4] placeholder:text-[#6b7569]"
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="new-password" className="text-[#e6f0e4]">
                    Password
                  </Label>
                  <Input
                    id="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter password"
                    className="border-[#1a1d24] bg-[#0a0b10] text-[#e6f0e4] placeholder:text-[#6b7569]"
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <Label className="text-[#e6f0e4]">Role</Label>
                  <Select value={newRole} onValueChange={(v) => setNewRole(v ?? "user")}>
                    <SelectTrigger className="w-full border-[#1a1d24] bg-[#0a0b10] text-[#e6f0e4]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-[#1a1d24] bg-[#0f1117]">
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {createError && <p className="text-sm text-[#ff5c5c]">{createError}</p>}
                <Button
                  onClick={handleCreateUser}
                  disabled={createLoading}
                  className="w-full bg-[#00cc6e] text-white hover:bg-[#00ff88]"
                >
                  {createLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    "Create"
                  )}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        {/* Users table */}
        <div className="rounded-lg border border-[#1a1d24] bg-[#0f1117] overflow-hidden">
          {isLoadingUsers ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-5 w-5 animate-spin text-[#6b7569]" />
            </div>
          ) : users.length === 0 ? (
            <div className="py-12 text-center text-[#6b7569]">No users found</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-[#1a1d24] hover:bg-transparent">
                  <TableHead className="text-[#6b7569]">Username</TableHead>
                  <TableHead className="text-[#6b7569]">Role</TableHead>
                  <TableHead className="text-[#6b7569]">Created</TableHead>
                  <TableHead className="text-right text-[#6b7569]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.username} className="border-[#1a1d24] hover:bg-[#14161e]">
                    <TableCell className="text-[#e6f0e4] font-medium">{u.username}</TableCell>
                    <TableCell>
                      <Badge
                        variant="secondary"
                        className={
                          u.role === "admin"
                            ? "bg-[#00cc6e]/20 text-[#00cc6e]"
                            : "bg-[#6b7569]/20 text-[#6b7569]"
                        }
                      >
                        {u.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-[#6b7569]">
                      {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "-"}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger
                          render={
                            <button className="p-1.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors rounded">
                              <MoreHorizontal size={16} />
                            </button>
                          }
                        />
                        <DropdownMenuContent align="end" className="border-[#1a1d24] bg-[#0f1117]">
                          <DropdownMenuItem
                            onClick={() =>
                              handleChangeRole(u.username, u.role === "admin" ? "user" : "admin")
                            }
                          >
                            Change to {u.role === "admin" ? "User" : "Admin"}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator className="bg-[#1a1d24]" />
                          <DropdownMenuItem
                            variant="destructive"
                            onClick={() => handleDeleteUser(u.username)}
                          >
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </div>
    </div>
  );
}
