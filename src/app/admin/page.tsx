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
      <div className="flex h-screen items-center justify-center bg-[#0D0F12]">
        <Loader2 className="h-6 w-6 animate-spin text-[#3B82F6]" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0D0F12] text-[#E4E4E7]">
      <div className="mx-auto max-w-3xl px-6 py-8">
        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="p-1.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
              title="Back to workspace"
              aria-label="Back to workspace"
            >
              <ArrowLeft size={18} />
            </Link>
            <h1 className="text-xl font-semibold text-[#E4E4E7]">User Management</h1>
          </div>

          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger
              render={
                <Button className="bg-[#3B82F6] text-white hover:bg-[#2563EB]">
                  <Plus className="mr-1.5 h-4 w-4" />
                  Add User
                </Button>
              }
            />
            <DialogContent className="border-[#2A2D3A] bg-[#151820]">
              <DialogHeader>
                <DialogTitle className="text-[#E4E4E7]">Create New User</DialogTitle>
              </DialogHeader>
              <div className="flex flex-col gap-4 pt-2">
                <div className="flex flex-col gap-2">
                  <Label htmlFor="new-username" className="text-[#E4E4E7]">
                    Username
                  </Label>
                  <Input
                    id="new-username"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Enter username"
                    className="border-[#2A2D3A] bg-[#0D0F12] text-[#E4E4E7] placeholder:text-[#6B7280]"
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="new-password" className="text-[#E4E4E7]">
                    Password
                  </Label>
                  <Input
                    id="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter password"
                    className="border-[#2A2D3A] bg-[#0D0F12] text-[#E4E4E7] placeholder:text-[#6B7280]"
                  />
                </div>
                <div className="flex flex-col gap-2">
                  <Label className="text-[#E4E4E7]">Role</Label>
                  <Select value={newRole} onValueChange={(v) => setNewRole(v ?? "user")}>
                    <SelectTrigger className="w-full border-[#2A2D3A] bg-[#0D0F12] text-[#E4E4E7]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-[#2A2D3A] bg-[#151820]">
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {createError && <p className="text-sm text-[#EF4444]">{createError}</p>}
                <Button
                  onClick={handleCreateUser}
                  disabled={createLoading}
                  className="w-full bg-[#3B82F6] text-white hover:bg-[#2563EB]"
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
        <div className="rounded-lg border border-[#2A2D3A] bg-[#151820] overflow-hidden">
          {isLoadingUsers ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-5 w-5 animate-spin text-[#6B7280]" />
            </div>
          ) : users.length === 0 ? (
            <div className="py-12 text-center text-[#6B7280]">No users found</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-[#2A2D3A] hover:bg-transparent">
                  <TableHead className="text-[#6B7280]">Username</TableHead>
                  <TableHead className="text-[#6B7280]">Role</TableHead>
                  <TableHead className="text-[#6B7280]">Created</TableHead>
                  <TableHead className="text-right text-[#6B7280]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.username} className="border-[#2A2D3A] hover:bg-[#1C1F2B]">
                    <TableCell className="text-[#E4E4E7] font-medium">{u.username}</TableCell>
                    <TableCell>
                      <Badge
                        variant="secondary"
                        className={
                          u.role === "admin"
                            ? "bg-[#3B82F6]/20 text-[#3B82F6]"
                            : "bg-[#6B7280]/20 text-[#6B7280]"
                        }
                      >
                        {u.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-[#6B7280]">
                      {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "-"}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger
                          render={
                            <button className="p-1.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors rounded">
                              <MoreHorizontal size={16} />
                            </button>
                          }
                        />
                        <DropdownMenuContent align="end" className="border-[#2A2D3A] bg-[#151820]">
                          <DropdownMenuItem
                            onClick={() =>
                              handleChangeRole(u.username, u.role === "admin" ? "user" : "admin")
                            }
                          >
                            Change to {u.role === "admin" ? "User" : "Admin"}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator className="bg-[#2A2D3A]" />
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
