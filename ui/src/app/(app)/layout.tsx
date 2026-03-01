"use client";

import React, { useEffect, useState } from "react";
import { useAppStore } from "@/store";
import { AuthGuard } from "@/components/AuthGuard";
import { Sidebar } from "@/components/Sidebar";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { NotificationBell } from "@/components/NotificationBell";
import { HeaderStatusBar } from "@/components/HeaderStatusBar";
import {
  Search,
  ChevronDown,
  Shield,
  LogOut,
  User,
  Moon,
} from "lucide-react";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { fetchUser, user, performLogout } = useAppStore();
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const handleLogout = async () => {
    // Clear app session + CF Access cookies via API
    await performLogout();
    // Redirect to login page (not CF logout page)
    window.location.href = "/login";
  };

  return (
    <AuthGuard>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Top header bar */}
          <header className="h-12 shrink-0 border-b border-border/40 bg-card/80 backdrop-blur-sm flex items-center gap-4 px-4 lg:px-6">
          {/* Left: breadcrumb / search */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="relative max-w-sm w-full lg:w-64">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search threats, IOCs, CVEs..."
                className="w-full h-8 pl-8 pr-3 rounded-md bg-muted/30 border border-border/40 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/50 focus:bg-muted/50 transition-colors"
              />
              <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[9px] text-muted-foreground/40 border border-border/30 rounded px-1 py-0.5">
                ⌘K
              </kbd>
            </div>
          </div>

          {/* Center: status bar */}
          <div className="hidden lg:flex items-center flex-1 justify-center">
            <HeaderStatusBar />
          </div>
          <div className="flex-1 lg:hidden" />

          {/* Right: actions */}
          <div className="flex items-center gap-2">
            {/* Live indicator */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-green-500/10 text-green-400 text-[10px] font-medium">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
              </span>
              Live
            </div>

            {/* Theme toggle */}
            <button className="p-1.5 rounded-md hover:bg-muted/40 transition-colors text-muted-foreground">
              <Moon className="h-4 w-4" />
            </button>

            {/* Notifications */}
            <NotificationBell />

            {/* User */}
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 pl-2.5 pr-2 py-1 rounded-md hover:bg-muted/40 transition-colors"
              >
                <div className="w-6 h-6 rounded-full bg-gradient-to-br from-primary to-blue-400 flex items-center justify-center">
                  <User className="h-3 w-3 text-white" />
                </div>
                <span className="text-xs font-medium hidden md:block">
                  {user?.name || "Admin"}
                </span>
                <ChevronDown className="h-3 w-3 text-muted-foreground" />
              </button>

              {showUserMenu && (
                <>
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setShowUserMenu(false)}
                  />
                  <div className="absolute right-0 top-full mt-1 w-44 z-50 rounded-lg border border-border/50 bg-popover shadow-xl py-1">
                    <div className="px-3 py-2 border-b border-border/30">
                      <p className="text-xs font-semibold">{user?.name || "Admin"}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {user?.role || "Administrator"}
                      </p>
                    </div>
                    <button className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground transition-colors">
                      <User className="h-3.5 w-3.5" /> Profile
                    </button>
                    <button className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground transition-colors">
                      <Shield className="h-3.5 w-3.5" /> Security
                    </button>
                    <div className="border-t border-border/30 mt-1">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400 hover:bg-red-500/10 transition-colors"
                      >
                        <LogOut className="h-3.5 w-3.5" /> Sign Out
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-auto">
          <ErrorBoundary>{children}</ErrorBoundary>
        </main>
      </div>
    </div>
    </AuthGuard>
  );
}
