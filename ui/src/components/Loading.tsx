"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface LoadingProps {
  className?: string;
  text?: string;
}

export function Loading({ className, text = "Loading..." }: LoadingProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center py-12", className)}>
      <div className="relative">
        <div className="w-12 h-12 rounded-full border-4 border-muted border-t-primary animate-spin" />
      </div>
      <p className="mt-4 text-sm text-muted-foreground">{text}</p>
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
