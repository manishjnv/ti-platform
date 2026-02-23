"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface ThreatLevelBarProps {
  levels: { label: string; value: number; color: string }[];
}

export function ThreatLevelBar({ levels }: ThreatLevelBarProps) {
  const total = levels.reduce((a, l) => a + l.value, 0);
  if (total === 0) return null;

  return (
    <div className="space-y-2">
      {/* Visual bar */}
      <div className="flex h-10 rounded-lg overflow-hidden gap-0.5">
        {levels.map((level) => {
          const pct = ((level.value / total) * 100).toFixed(0);
          const width = Math.max(Number(pct), 1);
          return (
            <div
              key={level.label}
              className="flex items-center justify-center transition-all"
              style={{
                width: `${width}%`,
                backgroundColor: level.color,
                minWidth: level.value > 0 ? "40px" : "0px",
              }}
            >
              <div className="flex flex-col items-center text-white">
                <span className="text-sm font-bold leading-none">{pct}%</span>
                <span className="text-[9px] font-medium opacity-90 leading-none mt-0.5">
                  {level.label}
                </span>
              </div>
            </div>
          );
        })}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        {levels.map((level) => (
          <div key={level.label} className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: level.color }}
            />
            <span>{level.label}: {level.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
