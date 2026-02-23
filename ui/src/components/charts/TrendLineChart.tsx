"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface TrendSeries {
  key: string;
  label: string;
  color: string;
}

interface TrendLineChartProps {
  data: Record<string, string | number>[];
  series: TrendSeries[];
  xKey: string;
  height?: number;
  showGrid?: boolean;
  showLegend?: boolean;
  areaFill?: boolean;
}

export function TrendLineChart({
  data,
  series,
  xKey,
  height = 250,
  showGrid = true,
  showLegend = true,
  areaFill = true,
}: TrendLineChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -15, bottom: 0 }}>
        {showGrid && (
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="hsl(var(--border))"
            vertical={false}
          />
        )}
        <XAxis
          dataKey={xKey}
          tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
          tickLine={false}
          axisLine={{ stroke: "hsl(var(--border))" }}
        />
        <YAxis
          tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "hsl(var(--card))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "8px",
            fontSize: "12px",
          }}
        />
        {showLegend && (
          <Legend
            verticalAlign="bottom"
            wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
          />
        )}
        {series.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stroke={s.color}
            strokeWidth={2}
            fill={areaFill ? s.color : "transparent"}
            fillOpacity={areaFill ? 0.1 : 0}
            dot={false}
            activeDot={{ r: 4, strokeWidth: 0 }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
