"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface DataListItem {
  label: string;
  value: number;
  color?: string;
}

interface RankedDataListProps {
  items: DataListItem[];
  maxItems?: number;
  showIndex?: boolean;
  valueLabel?: string;
}

export function RankedDataList({
  items,
  maxItems = 10,
  showIndex = false,
  valueLabel,
}: RankedDataListProps) {
  const sliced = items.slice(0, maxItems);
  const maxVal = Math.max(...sliced.map((i) => i.value), 1);

  return (
    <div className="space-y-1.5">
      {sliced.map((item, idx) => (
        <div key={item.label} className="group">
          <div className="flex items-center justify-between text-xs mb-0.5">
            <div className="flex items-center gap-2 min-w-0 flex-1">
              {showIndex && (
                <span className="text-[10px] font-medium text-muted-foreground/50 w-4 text-right">
                  {idx + 1}
                </span>
              )}
              {item.color && (
                <span
                  className="h-2 w-2 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
              )}
              <span className="text-muted-foreground truncate group-hover:text-foreground transition-colors">
                {item.label}
              </span>
            </div>
            <span className="font-semibold tabular-nums ml-2">
              {item.value.toLocaleString()}
            </span>
          </div>
          {/* Progress bar */}
          <div className="h-1 rounded-full bg-muted/50 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${(item.value / maxVal) * 100}%`,
                backgroundColor: item.color || "hsl(var(--primary))",
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
