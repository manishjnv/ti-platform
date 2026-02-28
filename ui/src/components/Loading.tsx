"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface LoadingProps {
  className?: string;
  text?: string;
}

/**
 * Page-level skeleton loader.
 * Uses animated skeleton placeholders matching typical page layout
 * instead of spinners (per Instruction.md UX Standards).
 */
export function Loading({ className, text = "Loading..." }: LoadingProps) {
  return (
    <div className={cn("p-4 lg:p-6 space-y-5", className)}>
      {/* Header skeleton */}
      <div className="space-y-2">
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-3 w-40" />
      </div>
      {/* Stat cards row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="rounded-lg border p-4 space-y-2">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-7 w-16" />
            <Skeleton className="h-3 w-24" />
          </div>
        ))}
      </div>
      {/* Content area */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border p-4 space-y-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-40 w-full" />
        </div>
        <div className="rounded-lg border p-4 space-y-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>
      {/* List skeleton */}
      <div className="rounded-lg border p-4 space-y-3">
        <Skeleton className="h-4 w-40" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex gap-3 items-center">
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-4 flex-1" />
            <Skeleton className="h-5 w-12" />
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground text-center">{text}</p>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} />;
}

export function IntelCardSkeleton() {
  return (
    <div className="rounded-lg border border-l-4 border-l-muted p-4 space-y-3">
      <div className="flex items-start gap-3">
        <div className="flex-1 space-y-2">
          <div className="flex gap-2">
            <Skeleton className="h-5 w-16" />
            <Skeleton className="h-5 w-20" />
          </div>
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-3 w-3/4" />
        </div>
        <Skeleton className="h-14 w-14 rounded-lg" />
      </div>
      <div className="flex gap-3">
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-3 w-24" />
      </div>
    </div>
  );
}
