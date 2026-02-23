"use client";

import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface HBarItem {
  name: string;
  value: number;
  color?: string;
}

interface HorizontalBarChartProps {
  data: HBarItem[];
  height?: number;
  barColor?: string;
  showValues?: boolean;
  maxBars?: number;
}

export function HorizontalBarChart({
  data,
  height,
  barColor = "hsl(var(--primary))",
  showValues = true,
  maxBars = 10,
}: HorizontalBarChartProps) {
  const sliced = data.slice(0, maxBars);
  const computedHeight = height || Math.max(sliced.length * 36, 120);

  return (
    <ResponsiveContainer width="100%" height={computedHeight}>
      <BarChart
        data={sliced}
        layout="vertical"
        margin={{ top: 0, right: showValues ? 40 : 10, left: 0, bottom: 0 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="hsl(var(--border))"
          horizontal={false}
        />
        <XAxis
          type="number"
          tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          width={90}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "hsl(var(--card))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "8px",
            fontSize: "12px",
          }}
          cursor={{ fill: "hsl(var(--accent))", fillOpacity: 0.3 }}
        />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18}>
          {sliced.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color || barColor} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
