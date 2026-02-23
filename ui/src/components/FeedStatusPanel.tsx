"use client";

import React from "react";
import { cn, formatDate } from "@/lib/utils";
import type { FeedStatus } from "@/types";
import { CheckCircle, XCircle, Loader2, Clock } from "lucide-react";

interface FeedStatusPanelProps {
  feeds: FeedStatus[];
}

const statusConfig = {
  success: { icon: CheckCircle, color: "text-emerald-500", bg: "bg-emerald-500/10" },
  failed: { icon: XCircle, color: "text-red-500", bg: "bg-red-500/10" },
  running: { icon: Loader2, color: "text-blue-500", bg: "bg-blue-500/10" },
  idle: { icon: Clock, color: "text-muted-foreground", bg: "bg-muted/50" },
};

export function FeedStatusPanel({ feeds }: FeedStatusPanelProps) {
  return (
    <div className="space-y-2">
      {feeds.map((feed) => {
        const cfg = statusConfig[feed.status as keyof typeof statusConfig] || statusConfig.idle;
        const Icon = cfg.icon;
        return (
          <div
            key={feed.feed_name}
            className="flex items-center gap-3 rounded-lg border border-border/50 px-3 py-2.5 hover:bg-accent/20 transition-colors"
          >
            <div className={cn("rounded-md p-1.5", cfg.bg)}>
              <Icon
                className={cn("h-3.5 w-3.5", cfg.color, feed.status === "running" && "animate-spin")}
              />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium capitalize leading-none">
                {feed.feed_name.replace(/_/g, " ")}
              </p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {feed.items_stored.toLocaleString()} items stored
                {feed.last_success && ` · Last: ${formatDate(feed.last_success, { relative: true })}`}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full",
                  cfg.bg, cfg.color
                )}
              >
                {feed.status}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
