"use client";

import React, { useEffect } from "react";
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
  Bell,
  X,
  PanelLeftClose,
  PanelLeftOpen,
  Menu,
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
      { href: "/notifications", label: "Notifications", icon: Bell },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

/* ── Desktop Sidebar ─────────────────────────────────── */
function DesktopSidebar() {
  const pathname = usePathname();
  const { sidebarOpen, toggleSidebar, user } = useAppStore();

  return (
    <aside
      className={cn(
        "hidden md:flex flex-col border-r border-border/50 bg-sidebar transition-all duration-300 ease-in-out shrink-0 relative group/sidebar",
        sidebarOpen ? "w-60" : "w-[60px]"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center border-b border-border/50 px-3 gap-2">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 shrink-0">
          <Shield className="h-4 w-4 text-primary" />
        </div>
        {sidebarOpen && (
          <div className="flex flex-col flex-1 min-w-0">
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

      {/* Floating toggle pill — appears on sidebar hover */}
      <button
        onClick={toggleSidebar}
        className={cn(
          "absolute -right-3.5 top-[72px] z-30",
          "w-7 h-7 rounded-full",
          "bg-card border border-border shadow-lg",
          "flex items-center justify-center",
          "text-muted-foreground hover:text-foreground hover:bg-primary/10 hover:border-primary/40",
          "transition-all duration-200",
          "opacity-0 group-hover/sidebar:opacity-100 focus:opacity-100",
          "hover:scale-110"
        )}
        title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
        aria-label={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
      >
        {sidebarOpen ? (
          <ChevronLeft className="h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5" />
        )}
      </button>

      {/* Bottom bar toggle — always visible */}
      <button
        onClick={toggleSidebar}
        className={cn(
          "flex h-9 items-center justify-center gap-2 border-t border-border/50",
          "text-muted-foreground/70 hover:text-foreground hover:bg-accent/30 transition-colors"
        )}
        title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
      >
        {sidebarOpen ? (
          <>
            <PanelLeftClose className="h-3.5 w-3.5" />
            <span className="text-[10px]">Collapse</span>
          </>
        ) : (
          <PanelLeftOpen className="h-3.5 w-3.5" />
        )}
      </button>
    </aside>
  );
}

/* ── Mobile Sidebar (Drawer) ──────────────────────────── */
function MobileSidebar() {
  const pathname = usePathname();
  const { mobileSidebarOpen, setMobileSidebarOpen, user } = useAppStore();

  // Close on route change
  useEffect(() => {
    setMobileSidebarOpen(false);
  }, [pathname, setMobileSidebarOpen]);

  // Lock body scroll when open
  useEffect(() => {
    if (mobileSidebarOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => { document.body.style.overflow = ""; };
  }, [mobileSidebarOpen]);

  return (
    <>
      {/* Backdrop */}
      {mobileSidebarOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
          onClick={() => setMobileSidebarOpen(false)}
        />
      )}

      {/* Drawer */}
      <aside
        className={cn(
          "md:hidden fixed inset-y-0 left-0 z-50 w-72 bg-sidebar border-r border-border/50",
          "flex flex-col shadow-2xl",
          "transition-transform duration-300 ease-in-out",
          mobileSidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {/* Header */}
        <div className="flex h-14 items-center border-b border-border/50 px-4 justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 shrink-0">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold tracking-tight leading-none">IntelWatch</span>
              <span className="text-[10px] text-muted-foreground leading-none mt-0.5">TI Platform</span>
            </div>
          </div>
          <button
            onClick={() => setMobileSidebarOpen(false)}
            className="p-2 rounded-lg hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors"
            aria-label="Close menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-5">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 px-2 mb-1.5">
                {section.label}
              </p>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const active =
                    pathname === item.href || pathname?.startsWith(item.href + "/");
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150",
                        active
                          ? "bg-primary/10 text-primary shadow-sm"
                          : "text-muted-foreground hover:bg-accent/50 hover:text-foreground active:bg-accent"
                      )}
                    >
                      <Icon className={cn("h-4.5 w-4.5 shrink-0", active && "text-primary")} />
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* User section */}
        {user && (
          <div className="border-t border-border/50 px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
                <User className="h-4 w-4 text-primary" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium truncate">{user.name || user.email}</p>
                <p className="text-[11px] text-muted-foreground capitalize">{user.role}</p>
              </div>
            </div>
          </div>
        )}
      </aside>
    </>
  );
}

/* ── Hamburger Button (exported for header use) ──────── */
export function MobileMenuButton() {
  const { setMobileSidebarOpen } = useAppStore();
  return (
    <button
      onClick={() => setMobileSidebarOpen(true)}
      className="md:hidden p-2 -ml-1 rounded-lg hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors"
      aria-label="Open menu"
    >
      <Menu className="h-5 w-5" />
    </button>
  );
}

/* ── Combined Sidebar ─────────────────────────────────── */
export function Sidebar() {
  return (
    <>
      <DesktopSidebar />
      <MobileSidebar />
    </>
  );
}
