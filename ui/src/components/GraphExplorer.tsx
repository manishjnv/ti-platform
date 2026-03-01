"use client";

import React, { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { cn } from "@/lib/utils";
import type { GraphNode, GraphEdge, GraphResponse } from "@/types";

/* ── Cyber-theme colour palettes ──────────────────────── */
const NODE_COLORS: Record<string, { fill: string; glow: string; icon: string }> = {
  intel: { fill: "#3b82f6", glow: "#60a5fa", icon: "I" },
  ioc: { fill: "#f97316", glow: "#fb923c", icon: "!" },
  technique: { fill: "#8b5cf6", glow: "#a78bfa", icon: "T" },
  cve: { fill: "#ef4444", glow: "#f87171", icon: "C" },
};

const SEVERITY_RING: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
  unknown: "#374151",
};

const EDGE_COLORS: Record<string, string> = {
  "shares-ioc": "#f97316",
  shares_ioc: "#f97316",
  "shares-cve": "#ef4444",
  shares_cve: "#ef4444",
  "shares-technique": "#8b5cf6",
  shares_technique: "#8b5cf6",
  indicates: "#3b82f6",
  uses: "#10b981",
  exploits: "#dc2626",
  "co-occurs": "#6b7280",
  co_occurs: "#6b7280",
  "related-to": "#06b6d4",
};

/* ── force-directed simulation ────────────────────────── */
interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  isCenter?: boolean;
}

function initialLayout(
  nodes: GraphNode[],
  center: string,
  width: number,
  height: number,
): SimNode[] {
  const cx = width / 2;
  const cy = height / 2;
  const byType: Record<string, GraphNode[]> = {};
  nodes.forEach((n) => {
    (byType[n.type] ??= []).push(n);
  });
  const types = Object.keys(byType);

  return nodes.map((n) => {
    const isCenter = n.id === center;
    if (isCenter) return { ...n, x: cx, y: cy, vx: 0, vy: 0, isCenter };

    const ti = types.indexOf(n.type);
    const group = byType[n.type];
    const gi = group.indexOf(n);
    const sectorAngle = (2 * Math.PI) / Math.max(types.length, 1);
    const baseAngle = ti * sectorAngle;
    const spread = sectorAngle * 0.8;
    const angle = baseAngle + (gi / Math.max(group.length, 1)) * spread;
    const r = 120 + Math.random() * 100 + gi * 3;
    return {
      ...n,
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      vx: 0,
      vy: 0,
      isCenter: false,
    };
  });
}

function simulate(nodes: SimNode[], edges: GraphEdge[], iterations = 120) {
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const repulsion = 5000;
  const attraction = 0.004;
  const centerGravity = 0.002;
  const damping = 0.88;

  for (let iter = 0; iter < iterations; iter++) {
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

    const cx = nodes.reduce((s, n) => s + n.x, 0) / nodes.length;
    const cy = nodes.reduce((s, n) => s + n.y, 0) / nodes.length;
    for (const n of nodes) {
      if (n.isCenter) continue;
      n.vx -= (n.x - cx) * centerGravity;
      n.vy -= (n.y - cy) * centerGravity;
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
  onNodeSelect?: (node: GraphNode | null) => void;
  selectedNodeId?: string | null;
  className?: string;
}

export function GraphExplorer({
  data,
  width = 800,
  height = 640,
  onNodeClick,
  onNodeSelect,
  selectedNodeId,
  className,
}: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [nodes, setNodes] = useState<SimNode[]>([]);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const [dragNode, setDragNode] = useState<string | null>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const [animTick, setAnimTick] = useState(0);

  // Animated particle tick
  useEffect(() => {
    const interval = setInterval(() => setAnimTick((t) => (t + 1) % 1000), 50);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!data.nodes.length) { setNodes([]); return; }
    const w = isFullscreen ? (typeof window !== "undefined" ? window.innerWidth : 1200) : width;
    const h = isFullscreen ? (typeof window !== "undefined" ? window.innerHeight - 60 : 800) : height;
    const sim = initialLayout(data.nodes, data.center, w, h);
    simulate(sim, data.edges);
    setNodes(sim);
    setTransform({ x: 0, y: 0, k: 1 });
  }, [data, width, height, isFullscreen]);

  // ESC to exit fullscreen
  useEffect(() => {
    if (!isFullscreen) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setIsFullscreen(false); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [isFullscreen]);

  const handleMouseDown = useCallback(
    (id: string) => (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragNode(id);
    },
    [],
  );

  const handleBgMouseDown = useCallback((e: React.MouseEvent) => {
    if (dragNode) return;
    setPanStart({ x: e.clientX, y: e.clientY, tx: transform.x, ty: transform.y });
  }, [dragNode, transform]);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (panStart && !dragNode) {
        setTransform((t) => ({
          ...t,
          x: panStart.tx + (e.clientX - panStart.x),
          y: panStart.ty + (e.clientY - panStart.y),
        }));
        return;
      }
      if (!dragNode || !svgRef.current) return;
      const svg = svgRef.current;
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgP = pt.matrixTransform(svg.getScreenCTM()?.inverse());
      setNodes((prev) =>
        prev.map((n) =>
          n.id === dragNode
            ? { ...n, x: (svgP.x - transform.x) / transform.k, y: (svgP.y - transform.y) / transform.k }
            : n,
        ),
      );
    },
    [dragNode, transform, panStart],
  );

  const handleMouseUp = useCallback(() => {
    setDragNode(null);
    setPanStart(null);
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    setTransform((t) => ({
      ...t,
      k: Math.min(4, Math.max(0.15, t.k * factor)),
    }));
  }, []);

  const zoomIn = () => setTransform((t) => ({ ...t, k: Math.min(4, t.k * 1.3) }));
  const zoomOut = () => setTransform((t) => ({ ...t, k: Math.max(0.15, t.k / 1.3) }));
  const resetView = () => setTransform({ x: 0, y: 0, k: 1 });
  const toggleFullscreen = useCallback(() => setIsFullscreen((f) => !f), []);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const connectedTo = useMemo(() => {
    const active = hoveredNode || selectedNodeId;
    if (!active) return new Set<string>();
    const s = new Set<string>();
    data.edges.forEach((e) => {
      if (e.source === active) s.add(e.target);
      if (e.target === active) s.add(e.source);
    });
    return s;
  }, [hoveredNode, selectedNodeId, data.edges]);

  const activeNode = hoveredNode || selectedNodeId;

  const svgW = isFullscreen ? "100vw" : width;
  const svgH = isFullscreen ? "calc(100vh - 60px)" : height;

  return (
    <div
      className={cn(
        "relative select-none overflow-hidden",
        isFullscreen && "fixed inset-0 z-50 bg-[#0a0e1a]",
        className,
      )}
    >
      {/* SVG defs for glow effects & gradients */}
      <svg width={0} height={0} className="absolute">
        <defs>
          <filter id="glow-blue" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-strong" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="node-shadow" x="-50%" y="-50%" width="200%" height="200%">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#000" floodOpacity="0.5" />
          </filter>
          {Object.entries(NODE_COLORS).map(([type, c]) => (
            <React.Fragment key={type}>
              <radialGradient id={`grad-${type}`} cx="35%" cy="35%">
                <stop offset="0%" stopColor={c.glow} stopOpacity="1" />
                <stop offset="70%" stopColor={c.fill} stopOpacity="0.95" />
                <stop offset="100%" stopColor={c.fill} stopOpacity="0.8" />
              </radialGradient>
              <radialGradient id={`grad-${type}-active`} cx="35%" cy="35%">
                <stop offset="0%" stopColor="#ffffff" stopOpacity="0.4" />
                <stop offset="40%" stopColor={c.glow} stopOpacity="1" />
                <stop offset="100%" stopColor={c.fill} stopOpacity="0.9" />
              </radialGradient>
            </React.Fragment>
          ))}
          <pattern id="cyber-grid" x="0" y="0" width="40" height="40" patternUnits="userSpaceOnUse">
            <line x1="40" y1="0" x2="40" y2="40" stroke="#1e293b" strokeWidth="0.5" strokeOpacity="0.3" />
            <line x1="0" y1="40" x2="40" y2="40" stroke="#1e293b" strokeWidth="0.5" strokeOpacity="0.3" />
          </pattern>
          <radialGradient id="center-ambient">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
        </defs>
      </svg>

      {/* Top-left: Legend */}
      <div className="absolute top-3 left-3 z-20 bg-[#0f172a]/90 backdrop-blur-sm border border-[#1e293b] rounded-xl px-3 py-2 text-[11px] flex items-center gap-3">
        {Object.entries(NODE_COLORS).map(([type, c]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full inline-block ring-1 ring-white/10"
              style={{ background: c.fill, boxShadow: `0 0 6px ${c.glow}` }}
            />
            <span className="capitalize text-slate-400">{type}</span>
          </div>
        ))}
      </div>

      {/* Top-right: Controls */}
      <div className="absolute top-3 right-3 z-20 flex items-center gap-1.5">
        <div className="bg-[#0f172a]/90 backdrop-blur-sm border border-[#1e293b] rounded-xl px-2.5 py-1 text-[11px] text-slate-400 mr-1">
          {data.total_nodes} nodes · {data.total_edges} edges
        </div>
        {[
          { label: "+", action: zoomIn, title: "Zoom in" },
          { label: "−", action: zoomOut, title: "Zoom out" },
        ].map((btn) => (
          <button
            key={btn.title}
            onClick={btn.action}
            className="w-8 h-8 rounded-lg bg-[#0f172a]/90 border border-[#1e293b] text-slate-300 hover:text-white hover:border-blue-500/50 flex items-center justify-center transition-all text-sm"
            title={btn.title}
          >
            {btn.label}
          </button>
        ))}
        <button
          onClick={resetView}
          className="w-8 h-8 rounded-lg bg-[#0f172a]/90 border border-[#1e293b] text-slate-300 hover:text-white hover:border-blue-500/50 flex items-center justify-center transition-all"
          title="Reset view"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
            <path d="M3 3v5h5" />
          </svg>
        </button>
        <button
          onClick={toggleFullscreen}
          className="w-8 h-8 rounded-lg bg-[#0f172a]/90 border border-[#1e293b] text-slate-300 hover:text-white hover:border-blue-500/50 flex items-center justify-center transition-all"
          title={isFullscreen ? "Exit fullscreen (Esc)" : "Fullscreen"}
        >
          {isFullscreen ? (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3" />
            </svg>
          ) : (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3" />
            </svg>
          )}
        </button>
      </div>

      {/* Zoom indicator */}
      {transform.k !== 1 && (
        <div className="absolute bottom-3 right-3 z-20 bg-[#0f172a]/80 backdrop-blur-sm border border-[#1e293b] rounded-lg px-2 py-1 text-[10px] text-slate-500">
          {Math.round(transform.k * 100)}%
        </div>
      )}

      {/* Main SVG */}
      <svg
        ref={svgRef}
        width={svgW}
        height={svgH}
        className="rounded-xl"
        style={{ background: "linear-gradient(135deg, #0a0e1a 0%, #0f172a 50%, #0a101f 100%)" }}
        onMouseDown={handleBgMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <rect width="100%" height="100%" fill="url(#cyber-grid)" opacity={0.6} />
        <circle cx="50%" cy="50%" r="300" fill="url(#center-ambient)" opacity={0.12} />

        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {/* Edges */}
          {data.edges.map((edge) => {
            const s = nodeMap.get(edge.source);
            const t = nodeMap.get(edge.target);
            if (!s || !t) return null;
            const isActive =
              hoveredEdge === edge.id ||
              activeNode === edge.source ||
              activeNode === edge.target;
            const isSelected =
              selectedNodeId === edge.source || selectedNodeId === edge.target;
            const color = EDGE_COLORS[edge.type] || "#475569";
            const dimmed = activeNode && !isActive;

            // Animated particle
            const particleT = ((animTick * 3 + parseInt(edge.id.slice(-4), 16)) % 200) / 200;
            const px = s.x + (t.x - s.x) * particleT;
            const py = s.y + (t.y - s.y) * particleT;

            return (
              <g key={edge.id}>
                {(isActive || isSelected) && (
                  <line
                    x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                    stroke={color}
                    strokeWidth={4}
                    strokeOpacity={0.25}
                    filter="url(#glow-blue)"
                    className="pointer-events-none"
                  />
                )}
                <line
                  x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke={color}
                  strokeWidth={isActive ? 2 : 1}
                  strokeOpacity={dimmed ? 0.05 : isActive ? 0.8 : 0.2}
                  strokeDasharray={edge.type.includes("co") ? "4 4" : "none"}
                  onMouseEnter={() => setHoveredEdge(edge.id)}
                  onMouseLeave={() => setHoveredEdge(null)}
                  className="cursor-pointer"
                />
                {isActive && (
                  <circle
                    cx={px} cy={py} r={2.5}
                    fill={color}
                    opacity={0.9}
                    filter="url(#glow-blue)"
                    className="pointer-events-none"
                  />
                )}
                {isActive && hoveredEdge === edge.id && (
                  <g>
                    <rect
                      x={(s.x + t.x) / 2 - 55}
                      y={(s.y + t.y) / 2 - 19}
                      width={110}
                      height={22}
                      rx={6}
                      fill="#0f172a"
                      fillOpacity={0.92}
                      stroke={color}
                      strokeWidth={0.5}
                      className="pointer-events-none"
                    />
                    <text
                      x={(s.x + t.x) / 2}
                      y={(s.y + t.y) / 2 - 5}
                      fontSize={9}
                      fill={color}
                      textAnchor="middle"
                      className="pointer-events-none"
                      fontFamily="monospace"
                    >
                      {edge.type.replace(/[_-]/g, " ")} · {edge.confidence}%
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const colorSet = NODE_COLORS[node.type] || { fill: "#475569", glow: "#64748b", icon: "?" };
            const ring = node.severity ? SEVERITY_RING[node.severity] : undefined;
            const r = node.isCenter ? 22 : node.type === "intel" ? 17 : 13;
            const isHovered = hoveredNode === node.id;
            const isSelected = selectedNodeId === node.id;
            const isHighlighted = isHovered || isSelected;
            const isConnected = connectedTo.has(node.id);
            const dimmed = activeNode !== null && !isHighlighted && !isConnected && node.id !== activeNode;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onMouseDown={handleMouseDown(node.id)}
                onClick={(e) => {
                  e.stopPropagation();
                  onNodeSelect?.(node);
                }}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  onNodeClick?.(node);
                }}
                className="cursor-pointer"
                opacity={dimmed ? 0.12 : 1}
                style={{ transition: "opacity 0.3s ease" }}
              >
                {/* Pulse ring for center/selected */}
                {(node.isCenter || isSelected) && (
                  <circle
                    r={r + 12}
                    fill="none"
                    stroke={colorSet.glow}
                    strokeWidth={1}
                    strokeOpacity={0.3}
                    className="animate-pulse"
                  />
                )}
                {/* Ambient glow */}
                <circle
                  r={r + 6}
                  fill={colorSet.glow}
                  fillOpacity={isHighlighted ? 0.2 : 0.08}
                  className="pointer-events-none"
                />
                {/* Severity ring */}
                {ring && (
                  <circle
                    r={r + 3}
                    fill="none"
                    stroke={ring}
                    strokeWidth={2}
                    strokeOpacity={0.7}
                    strokeDasharray={node.severity === "critical" ? "none" : "3 2"}
                  />
                )}
                {/* 3D gradient node */}
                <circle
                  r={r}
                  fill={`url(#grad-${node.type}${isHighlighted ? "-active" : ""})`}
                  stroke={isHighlighted ? "#ffffff" : colorSet.glow}
                  strokeWidth={isHighlighted ? 2 : 0.5}
                  strokeOpacity={isHighlighted ? 0.9 : 0.3}
                  filter="url(#node-shadow)"
                />
                {/* Specular highlight */}
                <ellipse
                  cx={-r * 0.2}
                  cy={-r * 0.25}
                  rx={r * 0.45}
                  ry={r * 0.3}
                  fill="white"
                  fillOpacity={0.12}
                  className="pointer-events-none"
                />
                {/* Type icon */}
                <text
                  y={1}
                  fontSize={r * 0.65}
                  fill="#fff"
                  textAnchor="middle"
                  dominantBaseline="central"
                  className="pointer-events-none"
                  fontWeight="700"
                  style={{ textShadow: `0 0 8px ${colorSet.glow}` }}
                >
                  {colorSet.icon}
                </text>
                {/* Label */}
                <text
                  y={r + 15}
                  fontSize={9.5}
                  fill="#94a3b8"
                  textAnchor="middle"
                  className="pointer-events-none"
                  fontFamily="system-ui, sans-serif"
                >
                  {node.label.length > 32 ? node.label.slice(0, 30) + "…" : node.label}
                </text>
                {/* Risk score badge */}
                {node.risk_score != null && node.risk_score > 0 && (
                  <g transform={`translate(${r - 1},${-r - 2})`}>
                    <rect
                      width={24}
                      height={14}
                      rx={7}
                      fill={
                        node.risk_score >= 80 ? "#dc2626" : node.risk_score >= 50 ? "#f97316" : "#475569"
                      }
                      stroke="#0f172a"
                      strokeWidth={1}
                    />
                    <text
                      x={12} y={8}
                      fontSize={8}
                      fill="#fff"
                      textAnchor="middle"
                      dominantBaseline="central"
                      className="pointer-events-none font-medium"
                    >
                      {node.risk_score}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* Hints */}
      <div className="absolute bottom-3 left-3 z-20 text-[10px] text-slate-600 flex items-center gap-3">
        <span>Click: select · Double-click: open · Drag: move · Scroll: zoom · Drag bg: pan</span>
      </div>
    </div>
  );
}
