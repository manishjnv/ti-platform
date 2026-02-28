"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import type { GraphNode, GraphEdge, GraphResponse } from "@/types";

/* ── colour palettes by node type ─────────────────────── */
const NODE_COLORS: Record<string, string> = {
  intel: "#3b82f6",
  ioc: "#f97316",
  technique: "#8b5cf6",
  cve: "#ef4444",
};

const SEVERITY_RING: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
  unknown: "#6b7280",
};

const EDGE_COLORS: Record<string, string> = {
  shares_ioc: "#f97316",
  shares_cve: "#ef4444",
  shares_technique: "#8b5cf6",
  indicates: "#3b82f6",
  uses: "#10b981",
  exploits: "#dc2626",
  co_occurs: "#6b7280",
  "related-to": "#6b7280",
};

/* ── simple force simulation (no D3 dependency) ───────── */
interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number;
  fy?: number;
  isCenter?: boolean;
}

function initialLayout(nodes: GraphNode[], center: string, width: number, height: number): SimNode[] {
  const cx = width / 2;
  const cy = height / 2;
  return nodes.map((n, i) => {
    const isCenter = n.id === center;
    const angle = (2 * Math.PI * i) / nodes.length;
    const r = isCenter ? 0 : 140 + Math.random() * 80;
    return {
      ...n,
      x: isCenter ? cx : cx + r * Math.cos(angle),
      y: isCenter ? cy : cy + r * Math.sin(angle),
      vx: 0,
      vy: 0,
      isCenter,
    };
  });
}

function simulate(nodes: SimNode[], edges: GraphEdge[], iterations = 80) {
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const repulsion = 3500;
  const attraction = 0.005;
  const damping = 0.85;

  for (let iter = 0; iter < iterations; iter++) {
    // repulsion between all node pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = repulsion / (dist * dist);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        if (!a.isCenter) { a.vx += dx; a.vy += dy; }
        if (!b.isCenter) { b.vx -= dx; b.vy -= dy; }
      }
    }

    // attraction along edges
    for (const e of edges) {
      const s = nodeMap.get(e.source);
      const t = nodeMap.get(e.target);
      if (!s || !t) continue;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const fx = dx * attraction;
      const fy = dy * attraction;
      if (!s.isCenter) { s.vx += fx; s.vy += fy; }
      if (!t.isCenter) { t.vx -= fx; t.vy -= fy; }
    }

    // apply velocities
    for (const n of nodes) {
      if (n.isCenter) continue;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
    }
  }
}

/* ── component ────────────────────────────────────────── */
interface Props {
  data: GraphResponse;
  width?: number;
  height?: number;
  onNodeClick?: (node: GraphNode) => void;
  className?: string;
}

export function GraphExplorer({ data, width = 800, height = 560, onNodeClick, className }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [nodes, setNodes] = useState<SimNode[]>([]);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const [dragNode, setDragNode] = useState<string | null>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });

  /* Run layout when data changes */
  useEffect(() => {
    if (!data.nodes.length) { setNodes([]); return; }
    const sim = initialLayout(data.nodes, data.center, width, height);
    simulate(sim, data.edges);
    setNodes(sim);
    setTransform({ x: 0, y: 0, k: 1 });
  }, [data, width, height]);

  /* Drag handlers */
  const handleMouseDown = useCallback((id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    setDragNode(id);
  }, []);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!dragNode || !svgRef.current) return;
      const svg = svgRef.current;
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgP = pt.matrixTransform(svg.getScreenCTM()?.inverse());
      setNodes((prev) =>
        prev.map((n) =>
          n.id === dragNode ? { ...n, x: (svgP.x - transform.x) / transform.k, y: (svgP.y - transform.y) / transform.k } : n
        )
      );
    },
    [dragNode, transform]
  );

  const handleMouseUp = useCallback(() => setDragNode(null), []);

  /* Zoom via wheel */
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    setTransform((t) => ({ ...t, k: Math.min(3, Math.max(0.3, t.k * factor)) }));
  }, []);

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  return (
    <div className={cn("relative select-none", className)}>
      {/* Legend */}
      <div className="absolute top-2 left-2 z-10 bg-background/90 border border-border/50 rounded-lg p-2 text-xs space-y-1">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full inline-block" style={{ background: color }} />
            <span className="capitalize text-muted-foreground">{type}</span>
          </div>
        ))}
      </div>

      {/* Stats */}
      <div className="absolute top-2 right-2 z-10 bg-background/90 border border-border/50 rounded-lg px-3 py-1.5 text-xs text-muted-foreground">
        {data.total_nodes} nodes · {data.total_edges} edges
      </div>

      <svg
        ref={svgRef}
        width={width}
        height={height}
        className="bg-background rounded-lg border border-border/30"
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {/* Edges */}
          {data.edges.map((edge) => {
            const s = nodeMap.get(edge.source);
            const t = nodeMap.get(edge.target);
            if (!s || !t) return null;
            const isHovered = hoveredEdge === edge.id ||
              hoveredNode === edge.source ||
              hoveredNode === edge.target;
            const color = EDGE_COLORS[edge.type] || "#6b7280";
            return (
              <g key={edge.id}>
                <line
                  x1={s.x}
                  y1={s.y}
                  x2={t.x}
                  y2={t.y}
                  stroke={color}
                  strokeWidth={isHovered ? 2.5 : 1.5}
                  strokeOpacity={hoveredNode && !isHovered ? 0.15 : isHovered ? 0.9 : 0.4}
                  onMouseEnter={() => setHoveredEdge(edge.id)}
                  onMouseLeave={() => setHoveredEdge(null)}
                  className="cursor-pointer"
                />
                {isHovered && (
                  <text
                    x={(s.x + t.x) / 2}
                    y={(s.y + t.y) / 2 - 6}
                    fontSize={10}
                    fill={color}
                    textAnchor="middle"
                    className="pointer-events-none"
                  >
                    {edge.type.replace(/_/g, " ")} ({edge.confidence}%)
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const color = NODE_COLORS[node.type] || "#6b7280";
            const ring = node.severity ? SEVERITY_RING[node.severity] : undefined;
            const r = node.isCenter ? 20 : node.type === "intel" ? 16 : 12;
            const isHovered = hoveredNode === node.id;
            const dimmed = hoveredNode !== null && !isHovered &&
              !data.edges.some(
                (e) =>
                  (e.source === hoveredNode && e.target === node.id) ||
                  (e.target === hoveredNode && e.source === node.id)
              );
            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onMouseDown={handleMouseDown(node.id)}
                onClick={() => onNodeClick?.(node)}
                className="cursor-pointer"
                opacity={dimmed ? 0.2 : 1}
              >
                {/* Severity ring */}
                {ring && (
                  <circle r={r + 3} fill="none" stroke={ring} strokeWidth={2} strokeOpacity={0.6} />
                )}
                {/* Main circle */}
                <circle
                  r={r}
                  fill={color}
                  fillOpacity={isHovered ? 1 : 0.85}
                  stroke={isHovered ? "#fff" : "none"}
                  strokeWidth={2}
                />
                {/* Type icon letter */}
                <text
                  y={1}
                  fontSize={r * 0.7}
                  fill="#fff"
                  textAnchor="middle"
                  dominantBaseline="central"
                  className="pointer-events-none font-bold"
                >
                  {node.type[0].toUpperCase()}
                </text>
                {/* Label */}
                <text
                  y={r + 14}
                  fontSize={10}
                  fill="currentColor"
                  textAnchor="middle"
                  className="pointer-events-none fill-foreground"
                >
                  {node.label.length > 28 ? node.label.slice(0, 26) + "…" : node.label}
                </text>
                {/* Risk score badge */}
                {node.risk_score != null && node.risk_score > 0 && (
                  <>
                    <rect
                      x={r - 2}
                      y={-r - 4}
                      width={22}
                      height={14}
                      rx={4}
                      fill={node.risk_score >= 80 ? "#dc2626" : node.risk_score >= 50 ? "#f97316" : "#6b7280"}
                    />
                    <text
                      x={r + 9}
                      y={-r + 5}
                      fontSize={8}
                      fill="#fff"
                      textAnchor="middle"
                      dominantBaseline="central"
                      className="pointer-events-none font-medium"
                    >
                      {node.risk_score}
                    </text>
                  </>
                )}
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
