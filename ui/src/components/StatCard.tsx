"use client";

import React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Tooltip } from "@/components/ui/tooltip";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: { value: number; label: string };
  variant?: "default" | "danger" | "warning" | "success";
  tooltipContent?: React.ReactNode;
  href?: string;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = "default",
  tooltipContent,
  href,
}: StatCardProps) {
  const accentColor = {
    default: "from-primary/5 to-transparent border-primary/20",
    danger: "from-red-500/5 to-transparent border-red-500/20",
    warning: "from-amber-500/5 to-transparent border-amber-500/20",
    success: "from-emerald-500/5 to-transparent border-emerald-500/20",
  }[variant];

  const valueColor = {
    default: "text-foreground",
    danger: "text-red-500",
    warning: "text-amber-500",
    success: "text-emerald-500",
  }[variant];

  const card = (
    <div
      className={cn(
        "rounded-xl border bg-gradient-to-br p-4 transition-all hover:shadow-md",
        accentColor
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            {title}
          </p>
          <p className={cn("text-2xl font-bold tabular-nums", valueColor)}>
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {subtitle && (
            <p className="text-xs text-muted-foreground">{subtitle}</p>
          )}
          {trend && (
            <div className="flex items-center gap-1 pt-0.5">
              <span
                className={cn(
                  "text-xs font-semibold",
                  trend.value > 0 ? "text-red-500" : trend.value < 0 ? "text-emerald-500" : "text-muted-foreground"
                )}
              >
                {trend.value > 0 ? "↑" : trend.value < 0 ? "↓" : "→"}{" "}
                {Math.abs(trend.value)}%
              </span>
              <span className="text-[10px] text-muted-foreground">{trend.label}</span>
            </div>
          )}
        </div>
        {icon && (
          <div className="rounded-lg bg-background/50 p-2 text-muted-foreground/40">
            {icon}
          </div>
        )}
      </div>
    </div>
  );

  if (tooltipContent) {
    return <Tooltip content={tooltipContent} side="bottom">{card}</Tooltip>;
  }
  if (href) {
    return <Link href={href} className="block cursor-pointer">{card}</Link>;
  }
  return card;
}
