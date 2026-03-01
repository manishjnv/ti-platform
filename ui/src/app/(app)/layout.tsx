"use client";

import React, { useEffect, useState, useCallback } from "react";
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
  Sun,
} from "lucide-react";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { fetchUser, user, performLogout } = useAppStore();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  // Theme toggle
  const toggleTheme = useCallback(() => {
    const next = !darkMode;
    setDarkMode(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("theme", next ? "dark" : "light");
  }, [darkMode]);

  // Restore saved theme
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    const preferDark = saved ? saved === "dark" : true;
    setDarkMode(preferDark);
    document.documentElement.classList.toggle("dark", preferDark);
  }, []);


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
            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="p-1.5 rounded-md hover:bg-muted/40 transition-colors text-muted-foreground"
              title={darkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              {darkMode ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
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
                  <div className="absolute right-0 top-full mt-1 w-48 z-50 rounded-xl border border-border bg-[hsl(222,47%,8%)] shadow-2xl py-1 overflow-hidden">
                    <div className="px-3 py-2.5 border-b border-border/30 bg-[hsl(222,47%,10%)]">
                      <p className="text-xs font-semibold">{user?.name || "Admin"}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {user?.role || "Administrator"}
                      </p>
                    </div>
                    <div className="py-1">
                      <button className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground transition-colors">
                        <User className="h-3.5 w-3.5" /> Profile
                      </button>
                      <button className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground transition-colors">
                        <Shield className="h-3.5 w-3.5" /> Security
                      </button>
                    </div>
                    <div className="border-t border-border/30">
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
