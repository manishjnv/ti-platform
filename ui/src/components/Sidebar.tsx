"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/store";
import {
  Shield,
  LayoutDashboard,
  Search,
  List,
  User,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Radio,
  Settings,
  BarChart3,
  Globe,
  Bug,
  Crosshair,
  Share2,
  FileText,
} from "lucide-react";

const NAV_SECTIONS = [
  {
    label: "Overview",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/threats", label: "Threat Feed", icon: AlertTriangle },
    ],
  },
  {
    label: "Investigation",
    items: [
      { href: "/intel", label: "Intel Items", icon: List },
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/investigate", label: "Investigate", icon: Share2 },
      { href: "/techniques", label: "ATT&CK Map", icon: Crosshair },
      { href: "/search", label: "IOC Search", icon: Search },
      { href: "/iocs", label: "IOC Database", icon: Bug },
    ],
  },
  {
    label: "Analytics",
    items: [
      { href: "/analytics", label: "Analytics", icon: BarChart3 },
      { href: "/geo", label: "Geo View", icon: Globe },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/feeds", label: "Feed Status", icon: Radio },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const { sidebarOpen, toggleSidebar, user } = useAppStore();

  return (
    <aside
      className={cn(
        "flex flex-col border-r border-border/50 bg-sidebar transition-all duration-300 ease-in-out shrink-0",
        sidebarOpen ? "w-60" : "w-[60px]"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center border-b border-border/50 px-3 gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 shrink-0">
          <Shield className="h-4 w-4 text-primary" />
        </div>
        {sidebarOpen && (
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight leading-none">IntelWatch</span>
            <span className="text-[10px] text-muted-foreground leading-none mt-0.5">TI Platform</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-2 px-2 space-y-4">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label}>
            {sidebarOpen && (
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 px-2 mb-1">
                {section.label}
              </p>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const active =
                  pathname === item.href || pathname?.startsWith(item.href + "/");
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={!sidebarOpen ? item.label : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-all duration-150",
                      active
                        ? "bg-primary/10 text-primary shadow-sm"
                        : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                    )}
                  >
                    <Icon className={cn("h-4 w-4 shrink-0", active && "text-primary")} />
                    {sidebarOpen && <span className="truncate">{item.label}</span>}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Live Status */}
      <div className="border-t border-border/50 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
          </span>
          {sidebarOpen && (
            <span className="text-xs text-muted-foreground">Live Ingestion Active</span>
          )}
        </div>
      </div>

      {/* User */}
      {user && (
        <div className="border-t border-border/50 px-3 py-2.5">
          <div className="flex items-center gap-2">
            <div className="h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
              <User className="h-3.5 w-3.5 text-primary" />
            </div>
            {sidebarOpen && (
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium truncate">{user.name || user.email}</p>
                <p className="text-[10px] text-muted-foreground capitalize">{user.role}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Toggle */}
      <button
        onClick={toggleSidebar}
        className="flex h-9 items-center justify-center border-t border-border/50 text-muted-foreground/50 hover:text-foreground hover:bg-accent/30 transition-colors"
      >
        {sidebarOpen ? (
          <ChevronLeft className="h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5" />
        )}
      </button>
    </aside>
  );
}
