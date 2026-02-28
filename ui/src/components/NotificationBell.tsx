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
        "group flex gap-3 px-4 py-3 border-b border-border/10 transition-colors",
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
            {n.title}
          </a>
        ) : (
          <p className="text-xs font-medium leading-snug line-clamp-2 break-words">{n.title}</p>
        )}
        {n.message && (
          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2 leading-relaxed whitespace-pre-line break-all">
            {n.message}
          </p>
        )}
        <div className="flex items-center gap-2 mt-1">
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
