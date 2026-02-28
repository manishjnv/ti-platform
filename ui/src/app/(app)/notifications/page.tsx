"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Bell,
  BellOff,
  CheckCheck,
  Trash2,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  Radio,
  GitMerge,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Eye,
  Filter,
} from "lucide-react";
import Link from "next/link";
import { Pagination } from "@/components/Pagination";

interface Notification {
  id: string;
  title: string;
  message: string;
  severity: string;
  category: string;
  entity_type: string | null;
  entity_id: string | null;
  metadata: Record<string, any>;
  is_read: boolean;
  created_at: string;
  rule_id: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/10 text-gray-400 border-gray-500/30",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  alert: <ShieldAlert className="h-4 w-4" />,
  feed_error: <Radio className="h-4 w-4" />,
  correlation: <GitMerge className="h-4 w-4" />,
  system: <Bell className="h-4 w-4" />,
};

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [total, setTotal] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [stats, setStats] = useState<any>(null);
  const limit = 20;

  const loadNotifications = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(limit),
        offset: String((page - 1) * limit),
      });
      if (unreadOnly) params.set("unread_only", "true");
      if (categoryFilter) params.set("category", categoryFilter);

      const res = await fetch(`/api/v1/notifications?${params}`, {
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.notifications || []);
        setTotal(data.total || 0);
        setUnreadCount(data.unread_count || 0);
      }
    } catch {
      /* silent */
    }
    setLoading(false);
  }, [page, unreadOnly, categoryFilter]);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/notifications/stats", {
        credentials: "include",
      });
      if (res.ok) setStats(await res.json());
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    loadNotifications();
  }, [loadNotifications]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleMarkRead = async (ids: string[]) => {
    try {
      await fetch("/api/v1/notifications/mark-read", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notification_ids: ids }),
      });
      loadNotifications();
    } catch {
      /* silent */
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await fetch("/api/v1/notifications/mark-all-read", {
        method: "POST",
        credentials: "include",
      });
      loadNotifications();
    } catch {
      /* silent */
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/v1/notifications/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      loadNotifications();
    } catch {
      /* silent */
    }
  };

  const handleClearAll = async () => {
    if (!confirm("Clear all notifications? This cannot be undone.")) return;
    try {
      await fetch("/api/v1/notifications", {
        method: "DELETE",
        credentials: "include",
      });
      loadNotifications();
    } catch {
      /* silent */
    }
  };

  const totalPages = Math.ceil(total / limit);

  const formatDate = (iso: string) => {
    const d = new Date(iso);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
    return d.toLocaleDateString();
  };

  const entityLink = (notif: Notification) => {
    if (!notif.entity_type || !notif.entity_id) return null;
    if (notif.entity_type === "intel") return `/intel/${notif.entity_id}`;
    if (notif.entity_type === "feed") return "/feeds";
    if (notif.entity_type === "cve") return `/search?q=${notif.entity_id}`;
    return null;
  };

  const categories = ["alert", "feed_error", "correlation", "system"];

  return (
    <div className="p-6 space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Notifications</h1>
          <p className="text-xs text-muted-foreground mt-1">
            {unreadCount > 0 ? `${unreadCount} unread` : "All caught up"} — {total} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          {unreadCount > 0 && (
            <button
              onClick={handleMarkAllRead}
              className="flex items-center gap-1.5 h-8 px-3 rounded-md text-xs font-medium bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
            >
              <CheckCheck className="h-3.5 w-3.5" />
              Mark All Read
            </button>
          )}
          {total > 0 && (
            <button
              onClick={handleClearAll}
              className="flex items-center gap-1.5 h-8 px-3 rounded-md text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear All
            </button>
          )}
        </div>
      </div>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Unread" value={stats.unread_count} icon={<Bell className="h-4 w-4 text-primary" />} />
          <StatCard label="Last 24h" value={stats.last_24h_total} icon={<AlertTriangle className="h-4 w-4 text-yellow-400" />} />
          <StatCard
            label="Critical (24h)"
            value={stats.by_severity?.critical || 0}
            icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
          />
          <StatCard
            label="Alerts (24h)"
            value={stats.by_category?.alert || 0}
            icon={<ShieldAlert className="h-4 w-4 text-orange-400" />}
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => { setUnreadOnly(!unreadOnly); setPage(1); }}
          className={`flex items-center gap-1.5 h-7 px-3 rounded-full text-[10px] font-medium transition-colors border ${
            unreadOnly
              ? "bg-primary/20 text-primary border-primary/40"
              : "bg-muted/20 text-muted-foreground border-border/30 hover:border-border/50"
          }`}
        >
          {unreadOnly ? <Bell className="h-3 w-3" /> : <BellOff className="h-3 w-3" />}
          {unreadOnly ? "Unread Only" : "All"}
        </button>
        <div className="h-4 border-r border-border/30" />
        <button
          onClick={() => { setCategoryFilter(null); setPage(1); }}
          className={`h-7 px-3 rounded-full text-[10px] font-medium transition-colors border ${
            !categoryFilter
              ? "bg-primary/20 text-primary border-primary/40"
              : "bg-muted/20 text-muted-foreground border-border/30 hover:border-border/50"
          }`}
        >
          All Categories
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => { setCategoryFilter(cat === categoryFilter ? null : cat); setPage(1); }}
            className={`h-7 px-3 rounded-full text-[10px] font-medium transition-colors border capitalize ${
              categoryFilter === cat
                ? "bg-primary/20 text-primary border-primary/40"
                : "bg-muted/20 text-muted-foreground border-border/30 hover:border-border/50"
            }`}
          >
            {cat.replace("_", " ")}
          </button>
        ))}
      </div>

      {/* Notification list */}
      <Card>
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <BellOff className="h-8 w-8 mb-3 opacity-30" />
              <p className="text-sm font-medium">No notifications</p>
              <p className="text-xs mt-1">
                {unreadOnly ? "No unread notifications" : "You're all caught up!"}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/20">
              {notifications.map((notif) => {
                const link = entityLink(notif);
                return (
                  <div
                    key={notif.id}
                    className={`flex items-start gap-3 px-4 py-3.5 hover:bg-muted/5 transition-colors ${
                      !notif.is_read ? "bg-primary/[0.02]" : ""
                    }`}
                  >
                    {/* Severity dot */}
                    <div className="mt-1 shrink-0">
                      <div
                        className={`h-2.5 w-2.5 rounded-full ${
                          !notif.is_read ? "ring-2 ring-primary/20" : ""
                        }`}
                        style={{
                          backgroundColor:
                            notif.severity === "critical"
                              ? "#ef4444"
                              : notif.severity === "high"
                              ? "#f97316"
                              : notif.severity === "medium"
                              ? "#eab308"
                              : notif.severity === "low"
                              ? "#3b82f6"
                              : "#6b7280",
                        }}
                      />
                    </div>

                    {/* Category icon */}
                    <div className="mt-0.5 shrink-0 text-muted-foreground/40">
                      {CATEGORY_ICONS[notif.category] || <Bell className="h-4 w-4" />}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className={`text-xs font-medium truncate ${!notif.is_read ? "text-foreground" : "text-muted-foreground"}`}>
                          {notif.title}
                        </p>
                        <Badge className={`text-[8px] px-1.5 py-0 border ${SEVERITY_COLORS[notif.severity] || SEVERITY_COLORS.info}`}>
                          {notif.severity}
                        </Badge>
                      </div>
                      {notif.message && (
                        <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2 whitespace-pre-wrap">
                          {notif.message}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-1.5">
                        <span className="text-[9px] text-muted-foreground/40">
                          {formatDate(notif.created_at)}
                        </span>
                        <span className="text-[9px] text-muted-foreground/40 capitalize">
                          {notif.category.replace("_", " ")}
                        </span>
                        {notif.metadata?.source_name && (
                          <span className="text-[9px] text-muted-foreground/40">
                            {notif.metadata.source_name}
                          </span>
                        )}
                        {notif.metadata?.risk_score != null && (
                          <span className="text-[9px] text-muted-foreground/40">
                            Risk: {notif.metadata.risk_score}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 shrink-0">
                      {link && (
                        <Link
                          href={link}
                          className="p-1.5 rounded hover:bg-muted/20 text-muted-foreground/40 hover:text-primary transition-colors"
                          title="View entity"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                        </Link>
                      )}
                      {!notif.is_read && (
                        <button
                          onClick={() => handleMarkRead([notif.id])}
                          className="p-1.5 rounded hover:bg-muted/20 text-muted-foreground/40 hover:text-primary transition-colors"
                          title="Mark as read"
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(notif.id)}
                        className="p-1.5 rounded hover:bg-red-500/10 text-muted-foreground/40 hover:text-red-400 transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination page={page} pages={totalPages} onPageChange={setPage} />
      )}
    </div>
  );
}

function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="shrink-0">{icon}</div>
        <div>
          <p className="text-lg font-bold tracking-tight">{value}</p>
          <p className="text-[10px] text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}
