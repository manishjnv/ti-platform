"use client";

import React, { useEffect, useState, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import { Bell, Check, CheckCheck, Trash2, AlertTriangle, Radio, GitBranch, Info, X, Loader2 } from "lucide-react";
import { useAppStore } from "@/store";
import type { Notification } from "@/types";
import * as api from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  alert: <AlertTriangle className="h-3.5 w-3.5" />,
  feed_error: <Radio className="h-3.5 w-3.5" />,
  correlation: <GitBranch className="h-3.5 w-3.5" />,
  risk_change: <AlertTriangle className="h-3.5 w-3.5" />,
  system: <Info className="h-3.5 w-3.5" />,
};

const CATEGORY_ACCENT: Record<string, string> = {
  alert: "border-l-orange-500/70",
  feed_error: "border-l-red-500/70",
  correlation: "border-l-purple-500/70",
  risk_change: "border-l-yellow-500/70",
  system: "border-l-blue-500/70",
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export function NotificationBell() {
  const { notifications, unreadCount, notificationsLoading, fetchNotifications, fetchUnreadCount, markRead, markAllRead } = useAppStore();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [animating, setAnimating] = useState(false);
  const bellRef = useRef<HTMLButtonElement>(null);
  const [dropdownPos, setDropdownPos] = useState({ top: 0, right: 0 });

  // Animate open + compute position
  useEffect(() => {
    if (open && bellRef.current) {
      const rect = bellRef.current.getBoundingClientRect();
      setDropdownPos({
        top: rect.bottom + 8,
        right: window.innerWidth - rect.right,
      });
      requestAnimationFrame(() => setAnimating(true));
    } else {
      setAnimating(false);
    }
  }, [open]);

  // Poll unread count every 30 seconds
  useEffect(() => {
    fetchUnreadCount();
    pollRef.current = setInterval(() => {
      fetchUnreadCount();
    }, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchUnreadCount]);

  // Fetch notifications when dropdown opens
  useEffect(() => {
    if (open) {
      fetchNotifications({ unread_only: filter === "unread", limit: 30 });
    }
  }, [open, filter, fetchNotifications]);

  const handleMarkRead = useCallback(
    (id: string) => {
      markRead([id]);
    },
    [markRead]
  );

  const handleMarkAllRead = useCallback(() => {
    markAllRead();
  }, [markAllRead]);

  const handleDelete = useCallback(async (id: string) => {
    try {
      await api.deleteNotification(id);
      fetchNotifications({ unread_only: filter === "unread", limit: 30 });
      fetchUnreadCount();
    } catch {
      // silent
    }
  }, [fetchNotifications, fetchUnreadCount, filter]);

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Bell Button */}
      <button
        ref={bellRef}
        onClick={() => setOpen(!open)}
        className="p-1.5 rounded-md hover:bg-muted/40 transition-colors text-muted-foreground relative"
        aria-label="Notifications"
      >
        <Bell className="h-4 w-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 flex items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white px-1 leading-none">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {/* Portal: render dropdown + backdrop at document.body to escape all stacking contexts */}
      {open && typeof document !== "undefined" && createPortal(
        <>
          {/* Backdrop overlay */}
          <div
            className="fixed inset-0 z-[9998] bg-transparent"
            onClick={() => setOpen(false)}
          />

          {/* Dropdown */}
          <div
            style={{ top: dropdownPos.top, right: dropdownPos.right }}
            className={cn(
              "fixed w-[380px] max-h-[520px] z-[9999] rounded-xl border border-border bg-[hsl(222,47%,8%)] shadow-2xl flex flex-col overflow-hidden transition-all duration-200 origin-top-right",
              animating ? "opacity-100 scale-100 translate-y-0" : "opacity-0 scale-95 -translate-y-1"
            )}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border/30 bg-[hsl(222,47%,10%)]">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold">Notifications</h3>
                {unreadCount > 0 && (
                  <span className="text-[10px] font-medium bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded-full">
                    {unreadCount} new
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1">
                {unreadCount > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    className="text-[10px] text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded hover:bg-muted/40 flex items-center gap-1"
                    title="Mark all read"
                  >
                    <CheckCheck className="h-3 w-3" />
                    Read all
                  </button>
                )}
                <button
                  onClick={() => setOpen(false)}
                  className="p-1 rounded hover:bg-muted/40 text-muted-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Filters */}
            <div className="flex gap-1 px-3 py-2 border-b border-border/20 bg-[hsl(222,47%,9%)]">
              {(["all", "unread"] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={cn(
                    "text-[10px] font-medium px-2.5 py-1 rounded-full transition-colors capitalize",
                    filter === f
                      ? "bg-primary/15 text-primary"
                      : "text-muted-foreground hover:bg-muted/40"
                  )}
                >
                  {f}
                </button>
              ))}
            </div>

            {/* Notification List */}
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              {notificationsLoading ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Loader2 className="h-5 w-5 mb-2 animate-spin opacity-40" />
                  <p className="text-[10px] opacity-50">Loading...</p>
                </div>
              ) : notifications.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Bell className="h-8 w-8 mb-2 opacity-30" />
                  <p className="text-xs">No notifications</p>
                  <p className="text-[10px] opacity-40 mt-0.5">Alerts will appear here when triggered</p>
                </div>
              ) : (
                notifications.map((n) => (
                  <NotificationItem
                    key={n.id}
                    notification={n}
                    onMarkRead={handleMarkRead}
                    onDelete={handleDelete}
                  />
                ))
              )}
            </div>

            {/* Footer */}
            {notifications.length > 0 && (
              <div className="border-t border-border/20 px-4 py-2 flex items-center justify-center bg-[hsl(222,47%,9%)]">
                <a
                  href="/settings"
                  className="text-[10px] text-muted-foreground hover:text-primary transition-colors"
                >
                  Manage notification rules
                </a>
              </div>
            )}
          </div>
        </>,
        document.body
      )}
    </div>
  );
}

function NotificationItem({
  notification: n,
  onMarkRead,
  onDelete,
}: {
  notification: Notification;
  onMarkRead: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const entityUrl = n.entity_type === "intel" && n.entity_id 
    ? `/intel/${n.entity_id}` 
    : null;

  return (
    <div
      className={cn(
        "group flex gap-3 px-4 py-3 border-b border-border/10 border-l-2 transition-colors",
        CATEGORY_ACCENT[n.category] || CATEGORY_ACCENT.system,
        !n.is_read ? "bg-[hsl(222,47%,11%)] hover:bg-[hsl(222,47%,13%)]" : "bg-[hsl(222,47%,8%)] hover:bg-[hsl(222,47%,11%)]"
      )}
    >
      {/* Severity dot + category icon */}
      <div className="flex flex-col items-center gap-1 pt-0.5 shrink-0">
        <div className={cn("w-2 h-2 rounded-full", SEVERITY_COLORS[n.severity] || SEVERITY_COLORS.info)} />
        <span className="text-muted-foreground/60">
          {CATEGORY_ICONS[n.category] || CATEGORY_ICONS.system}
        </span>
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        {entityUrl ? (
          <a href={entityUrl} className="text-xs font-medium leading-snug hover:text-primary transition-colors line-clamp-2 break-words">
            <TruncatedTitle text={n.title} />
          </a>
        ) : (
          <p className="text-xs font-medium leading-snug line-clamp-2 break-words">
            <TruncatedTitle text={n.title} />
          </p>
        )}
        {n.message && <FormattedMessage message={n.message} />}
        <MetadataBadges notification={n} />
        <div className="flex items-center gap-2 mt-1.5">
          <span className="text-[9px] text-muted-foreground/50">{timeAgo(n.created_at)}</span>
          <span className={cn(
            "text-[9px] font-medium px-1.5 py-0.5 rounded capitalize",
            n.severity === "critical" && "bg-red-500/15 text-red-400",
            n.severity === "high" && "bg-orange-500/15 text-orange-400",
            n.severity === "medium" && "bg-yellow-500/15 text-yellow-400",
            n.severity === "low" && "bg-blue-500/15 text-blue-400",
            n.severity === "info" && "bg-gray-500/15 text-gray-400",
          )}>
            {n.severity}
          </span>
          <span className="text-[9px] text-muted-foreground/40 capitalize">{n.category.replace("_", " ")}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
        {!n.is_read && (
          <button
            onClick={() => onMarkRead(n.id)}
            className="p-1 rounded hover:bg-muted/40 text-muted-foreground hover:text-primary"
            title="Mark as read"
          >
            <Check className="h-3 w-3" />
          </button>
        )}
        <button
          onClick={() => onDelete(n.id)}
          className="p-1 rounded hover:bg-muted/40 text-muted-foreground hover:text-red-400"
          title="Delete"
        >
          <Trash2 className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}

/* ── Helper: Truncate long URLs in title text ── */
function TruncatedTitle({ text }: { text: string }) {
  // Shorten URLs longer than 45 chars for display
  const shortened = text.replace(
    /https?:\/\/[^\s]{45,}/g,
    (url) => url.slice(0, 42) + "…"
  );
  return <>{shortened}</>;
}

/* ── Helper: Render pipe-delimited messages as structured chips, or plain text ── */
function FormattedMessage({ message }: { message: string }) {
  // Detect pipe-delimited key:value format (e.g. "Threat: x | Status: y | Reporter: z")
  if (message.includes("|")) {
    const parts = message.split(/\s*\|\s*/).filter(Boolean);
    const kvParts = parts.filter((p) => p.includes(":"));
    if (kvParts.length >= 2) {
      return (
        <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 mt-1">
          {parts.map((part, i) => {
            if (part.includes(":")) {
              const [key, ...vals] = part.split(":");
              const val = vals.join(":").trim();
              return (
                <span key={i} className="text-[10px]">
                  <span className="text-muted-foreground/50">{key.trim()}</span>{" "}
                  <span className="text-muted-foreground">{val}</span>
                </span>
              );
            }
            return (
              <span key={i} className="text-[10px] text-muted-foreground">
                {part}
              </span>
            );
          })}
        </div>
      );
    }
  }

  // Bullet-list messages (batch notifications)
  if (message.includes("\n•") || message.startsWith("•")) {
    const lines = message.split("\n").filter(Boolean);
    return (
      <div className="mt-0.5 space-y-0.5">
        {lines.slice(0, 4).map((line, i) => (
          <p key={i} className="text-[10px] text-muted-foreground leading-snug truncate">
            {line}
          </p>
        ))}
        {lines.length > 4 && (
          <p className="text-[10px] text-muted-foreground/50">+{lines.length - 4} more</p>
        )}
      </div>
    );
  }

  // Default plain text
  return (
    <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2 leading-relaxed whitespace-pre-line break-words">
      {message}
    </p>
  );
}

/* ── Helper: Smart metadata badges from notification metadata ── */
function MetadataBadges({ notification: n }: { notification: Notification }) {
  const meta = n.metadata || {};
  const badges: React.ReactNode[] = [];

  // Risk score
  const riskScore = (meta.risk_score ?? meta.top_risk_score) as number | undefined;
  if (riskScore != null) {
    const s = Number(riskScore);
    const color =
      s >= 90 ? "text-red-400 bg-red-500/10" :
      s >= 70 ? "text-orange-400 bg-orange-500/10" :
      s >= 50 ? "text-yellow-400 bg-yellow-500/10" :
               "text-blue-400 bg-blue-500/10";
    badges.push(
      <span key="risk" className={cn("text-[9px] font-mono tabular-nums px-1.5 py-0.5 rounded-sm", color)}>
        {meta.top_risk_score != null ? "Top " : ""}Risk {s}
      </span>
    );
  }

  // KEV indicator
  if (meta.is_kev) {
    badges.push(
      <span key="kev" className="text-[9px] font-bold px-1.5 py-0.5 rounded-sm bg-red-500/15 text-red-400">
        ⚡ KEV
      </span>
    );
  }

  // Source name
  if (meta.source_name) {
    badges.push(
      <span key="src" className="text-[9px] px-1.5 py-0.5 rounded-sm bg-primary/10 text-primary/80">
        {String(meta.source_name)}
      </span>
    );
  }

  // Feed names (correlation)
  if (meta.feed_names) {
    const feeds = meta.feed_names as string[];
    badges.push(
      <span key="feeds" className="text-[9px] px-1.5 py-0.5 rounded-sm bg-cyan-500/10 text-cyan-400">
        {feeds.join(" · ")}
      </span>
    );
  }

  // CVE tags
  const cveIds = (meta.cve_ids || (meta.cve_id ? [meta.cve_id] : null)) as string[] | null;
  if (cveIds && cveIds.length > 0) {
    cveIds.slice(0, 2).forEach((cve, i) => {
      badges.push(
        <span key={`cve-${i}`} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-violet-500/10 text-violet-400 font-mono">
          {cve}
        </span>
      );
    });
    if (cveIds.length > 2) {
      badges.push(
        <span key="cve-more" className="text-[9px] text-muted-foreground/40">+{cveIds.length - 2}</span>
      );
    }
  }

  // Match count (batch)
  if (meta.match_count != null) {
    badges.push(
      <span key="count" className="text-[9px] px-1.5 py-0.5 rounded-sm bg-muted/30 text-muted-foreground">
        {Number(meta.match_count)} items
      </span>
    );
  }

  // Feed status (feed_error)
  if (meta.status && n.category === "feed_error") {
    const isFailed = meta.status === "failed";
    badges.push(
      <span key="fst" className={cn("text-[9px] px-1.5 py-0.5 rounded-sm font-medium",
        isFailed ? "bg-red-500/10 text-red-400" : "bg-yellow-500/10 text-yellow-400"
      )}>
        {String(meta.status).toUpperCase()}
      </span>
    );
  }

  if (badges.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {badges}
    </div>
  );
}
