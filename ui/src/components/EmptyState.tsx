"use client";

import React from "react";
import { cn } from "@/lib/utils";

/**
 * Empty state component for when no data matches filters or no items exist.
 * Per Instruction.md: Never show empty screens — always display guidance text.
 */
interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-12 px-6 text-center",
        className
      )}
    >
      {icon && (
        <div className="w-12 h-12 rounded-full bg-muted/50 flex items-center justify-center mb-4 text-muted-foreground">
          {icon}
        </div>
      )}
      <h3 className="text-sm font-medium text-foreground mb-1">{title}</h3>
      {description && (
        <p className="text-xs text-muted-foreground max-w-md">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
