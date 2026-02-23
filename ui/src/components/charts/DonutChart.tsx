"use client";

import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface DonutItem {
  name: string;
  value: number;
  color: string;
}

interface DonutChartProps {
  data: DonutItem[];
  centerLabel?: string;
  centerValue?: string | number;
  height?: number;
  showLegend?: boolean;
  innerRadius?: number;
  outerRadius?: number;
}

export function DonutChart({
  data,
  centerLabel,
  centerValue,
  height = 200,
  showLegend = true,
  innerRadius = 55,
  outerRadius = 80,
}: DonutChartProps) {
  const total = data.reduce((acc, d) => acc + d.value, 0);

  return (
    <div className="flex flex-col items-center">
      <div style={{ width: "100%", height }} className="relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={innerRadius}
              outerRadius={outerRadius}
              paddingAngle={2}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "12px",
              }}
              formatter={(value: number, name: string) => [
                `${value.toLocaleString()} (${total > 0 ? ((value / total) * 100).toFixed(1) : 0}%)`,
                name,
              ]}
            />
          </PieChart>
        </ResponsiveContainer>
        {(centerValue !== undefined || centerLabel) && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-bold">
              {typeof centerValue === "number" ? centerValue.toLocaleString() : centerValue}
            </span>
            {centerLabel && (
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">
                {centerLabel}
              </span>
            )}
          </div>
        )}
      </div>
      {showLegend && (
        <div className="mt-3 space-y-1.5 w-full">
          {data.map((item) => (
            <div key={item.name} className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className="h-2.5 w-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-muted-foreground truncate">{item.name}</span>
              </div>
              <span className="font-medium tabular-nums ml-2">{item.value.toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
