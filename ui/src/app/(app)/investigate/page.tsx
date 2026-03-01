"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Loading } from "@/components/Loading";
import { GraphExplorer } from "@/components/GraphExplorer";
import { cn, severityColor } from "@/lib/utils";
import * as api from "@/lib/api";
import type {
  GraphResponse,
  GraphStatsResponse,
  GraphNode,
  GraphEdge,
} from "@/types";
import {
  Search,
  Share2,
  Shield,
  Layers,
  RefreshCw,
  Minus,
  Plus,
  Info,
  ExternalLink,
  X,
  BarChart3,
  AlertTriangle,
  Target,
  Crosshair,
  Bug,
  ChevronRight,
  Activity,
} from "lucide-react";

/* ── Node type metadata ─────────────────────────────── */
const NODE_TYPE_META: Record<string, { label: string; color: string; icon: React.ElementType; desc: string }> = {
  intel: { label: "Intel Item", color: "#3b82f6", icon: Shield, desc: "Threat intelligence item from feeds" },
  ioc: { label: "Indicator of Compromise", color: "#f97316", icon: AlertTriangle, desc: "IP, URL, hash, or domain indicator" },
  technique: { label: "ATT&CK Technique", color: "#8b5cf6", icon: Target, desc: "MITRE ATT&CK technique or sub-technique" },
  cve: { label: "CVE", color: "#ef4444", icon: Bug, desc: "Common Vulnerability and Exposure" },
};

export default function InvestigatePage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [query, setQuery] = useState(searchParams?.get("id") || "");
  const [entityType, setEntityType] = useState(searchParams?.get("type") || "intel");
  const [depth, setDepth] = useState(Number(searchParams?.get("depth")) || 2);
  const [graphData, setGraphData] = useState<GraphResponse | null>(null);
  const [stats, setStats] = useState<GraphStatsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    api.getGraphStats().then(setStats).catch(() => {});
  }, []);

  useEffect(() => {
    const id = searchParams?.get("id");
    const type = searchParams?.get("type") || "intel";
    if (id) {
      setQuery(id);
      setEntityType(type);
      explore(id, type, depth);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const explore = useCallback(
    async (id?: string, type?: string, d?: number) => {
      const entityId = id || query.trim();
      if (!entityId) return;
      setLoading(true);
      setError(null);
      setSelectedNode(null);
      try {
        const data = await api.getGraphExplore({
          entity_id: entityId,
          entity_type: type || entityType,
          depth: d || depth,
          limit: 100,
        });
        setGraphData(data);
      } catch (err: any) {
        setError(err.message || "Failed to load graph");
        setGraphData(null);
      } finally {
        setLoading(false);
      }
    },
    [query, entityType, depth]
  );

  /* Double-click: navigate to entity detail */
  const handleNodeClick = useCallback(
    (node: GraphNode) => {
      const rawId = node.id.includes(":") ? node.id.split(":", 2)[1] : node.id;
      if (node.type === "intel") {
        router.push(`/intel/${rawId}`);
      } else if (node.type === "technique") {
        router.push(`/attack-map?technique=${rawId}`);
      } else {
        // Re-explore centered on this node
        setQuery(rawId);
        setEntityType(node.type);
        explore(rawId, node.type, depth);
      }
    },
    [router, explore, depth]
  );

  /* Single click: select node and show detail panel */
  const handleNodeSelect = useCallback((node: GraphNode | null) => {
    setSelectedNode(node);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    explore();
  };

  /* Compute connected edges for selected node */
  const selectedEdges = graphData && selectedNode
    ? graphData.edges.filter(
        (e) => e.source === selectedNode.id || e.target === selectedNode.id,
      )
    : [];
  const selectedConnections = graphData && selectedNode
    ? graphData.nodes.filter(
        (n) =>
          n.id !== selectedNode.id &&
          selectedEdges.some((e) => e.source === n.id || e.target === n.id),
      )
    : [];

  return (
    <div className="p-4 md:p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Share2 className="h-5 w-5 text-primary" />
            Investigate — Relationship Graph
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Explore connections between intel items, IOCs, CVEs and ATT&CK techniques
          </p>
        </div>
        {stats && (
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Layers className="h-3.5 w-3.5" />
              {stats.total_relationships.toLocaleString()} relationships
            </span>
            <span>avg {stats.avg_confidence}% confidence</span>
          </div>
        )}
      </div>

      {/* Search Bar */}
      <Card className="border-border/50">
        <CardContent className="py-4">
          <form onSubmit={handleSubmit} className="flex flex-wrap items-center gap-2 md:gap-3">
            <div className="flex-1 min-w-[200px] relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Intel ID, IOC, CVE-ID, or technique…"
                className="pl-9"
              />
            </div>
            <select
              value={entityType}
              onChange={(e) => setEntityType(e.target.value)}
              className="h-10 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="intel">Intel Item</option>
              <option value="ioc">IOC</option>
              <option value="technique">Technique</option>
              <option value="cve">CVE</option>
            </select>
            <div className="flex items-center gap-1 border border-input rounded-md px-2 h-10">
              <button
                type="button"
                onClick={() => setDepth((d) => Math.max(1, d - 1))}
                className="p-0.5 hover:text-primary"
              >
                <Minus className="h-3.5 w-3.5" />
              </button>
              <span className="text-sm w-14 text-center">{depth} hop{depth > 1 ? "s" : ""}</span>
              <button
                type="button"
                onClick={() => setDepth((d) => Math.min(3, d + 1))}
                className="p-0.5 hover:text-primary"
              >
                <Plus className="h-3.5 w-3.5" />
              </button>
            </div>
            <Button type="submit" disabled={loading || !query.trim()} className="w-full sm:w-auto">
              {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : "Explore"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Main content */}
      {loading ? (
        <Loading text="Querying relationship graph…" />
      ) : error ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <Shield className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">{error}</p>
          </CardContent>
        </Card>
      ) : graphData ? (
        <div className="flex flex-col lg:flex-row gap-4">
          {/* Graph area */}
          <div className="flex-1 min-w-0 transition-all">
            <Card className="border-border/30 overflow-hidden">
              <CardContent className="p-0">
                <GraphExplorer
                  data={graphData}
                  height={560}
                  onNodeClick={handleNodeClick}
                  onNodeSelect={handleNodeSelect}
                  selectedNodeId={selectedNode?.id}
                />
              </CardContent>
            </Card>
          </div>

          {/* Node detail panel */}
          {selectedNode && (
            <NodeDetailPanel
              node={selectedNode}
              edges={selectedEdges}
              connections={selectedConnections}
              allNodes={graphData.nodes}
              onClose={() => setSelectedNode(null)}
              onNavigate={(node) => {
                const rawId = node.id.includes(":") ? node.id.split(":", 2)[1] : node.id;
                if (node.type === "intel") {
                  router.push(`/intel/${rawId}`);
                } else if (node.type === "technique") {
                  router.push(`/attack-map?technique=${rawId}`);
                } else {
                  setQuery(rawId);
                  setEntityType(node.type);
                  explore(rawId, node.type, depth);
                }
              }}
              onExplore={(node) => {
                const rawId = node.id.includes(":") ? node.id.split(":", 2)[1] : node.id;
                setQuery(rawId);
                setEntityType(node.type);
                explore(rawId, node.type, depth);
              }}
            />
          )}
        </div>
      ) : (
        <Card className="border-border/30">
          <CardContent className="py-20 text-center text-muted-foreground">
            <div
              className="mx-auto mb-6 w-20 h-20 rounded-full flex items-center justify-center"
              style={{ background: "linear-gradient(135deg, rgba(59,130,246,0.15), rgba(139,92,246,0.15))" }}
            >
              <Share2 className="h-9 w-9 text-primary/50" />
            </div>
            <p className="font-semibold text-foreground">Start Investigating</p>
            <p className="text-sm mt-1.5 max-w-md mx-auto">
              Enter an intel item ID, IOC value, CVE ID, or ATT&CK technique to explore
              its relationship graph and discover hidden connections.
            </p>
            {stats && stats.total_relationships > 0 && (
              <div className="mt-6 flex items-center justify-center gap-6 text-xs">
                <div className="flex items-center gap-1.5">
                  <Activity className="h-3.5 w-3.5 text-blue-500" />
                  <span>{stats.total_relationships.toLocaleString()} relationships</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <BarChart3 className="h-3.5 w-3.5 text-purple-500" />
                  <span>{stats.avg_confidence}% avg confidence</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ── Node Detail Panel ────────────────────────────────── */
interface NodeDetailPanelProps {
  node: GraphNode;
  edges: GraphEdge[];
  connections: GraphNode[];
  allNodes: GraphNode[];
  onClose: () => void;
  onNavigate: (node: GraphNode) => void;
  onExplore: (node: GraphNode) => void;
}

function NodeDetailPanel({
  node,
  edges,
  connections,
  allNodes,
  onClose,
  onNavigate,
  onExplore,
}: NodeDetailPanelProps) {
  const meta = NODE_TYPE_META[node.type] || {
    label: node.type,
    color: "#6b7280",
    icon: Shield,
    desc: "Entity",
  };
  const Icon = meta.icon;
  const rawId = node.id.includes(":") ? node.id.split(":", 2)[1] : node.id;

  // Group connections by type
  const connByType: Record<string, GraphNode[]> = {};
  connections.forEach((c) => {
    (connByType[c.type] ??= []).push(c);
  });

  return (
    <div className="w-full lg:w-[320px] shrink-0 space-y-3 animate-in slide-in-from-right-4 duration-300">
      {/* Header card */}
      <Card className="border-border/30 overflow-hidden">
        <div className="h-1.5" style={{ background: `linear-gradient(90deg, ${meta.color}, ${meta.color}88)` }} />
        <CardContent className="pt-4 pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <div
                className="w-9 h-9 rounded-lg flex items-center justify-center"
                style={{ background: `${meta.color}20` }}
              >
                <Icon className="h-4.5 w-4.5" style={{ color: meta.color }} />
              </div>
              <div>
                <Badge
                  variant="outline"
                  className="text-[10px] mb-0.5"
                  style={{ borderColor: `${meta.color}40`, color: meta.color }}
                >
                  {meta.label}
                </Badge>
                <p className="text-[10px] text-muted-foreground">{meta.desc}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-md hover:bg-muted/50 text-muted-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <h3 className="font-semibold text-sm mt-3 leading-snug">{node.label}</h3>
          <p className="text-[10px] text-muted-foreground font-mono mt-1 break-all">{rawId}</p>

          {/* Properties */}
          <div className="flex flex-wrap gap-1.5 mt-3">
            {node.severity && (
              <Badge variant="outline" className={cn("text-[10px]", severityColor(node.severity))}>
                {node.severity}
              </Badge>
            )}
            {node.risk_score != null && node.risk_score > 0 && (
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px]",
                  node.risk_score >= 80 ? "text-red-500 border-red-500/30" :
                  node.risk_score >= 50 ? "text-orange-500 border-orange-500/30" :
                  "text-muted-foreground"
                )}
              >
                Risk: {node.risk_score}
              </Badge>
            )}
            {node.source && (
              <Badge variant="secondary" className="text-[10px]">{node.source}</Badge>
            )}
            {node.tactic && (
              <Badge variant="secondary" className="text-[10px] capitalize">{node.tactic}</Badge>
            )}
            {node.ioc_type && (
              <Badge variant="secondary" className="text-[10px]">{node.ioc_type}</Badge>
            )}
            {node.feed_type && (
              <Badge variant="secondary" className="text-[10px]">{node.feed_type}</Badge>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex gap-2 mt-4">
            {node.type === "intel" && (
              <Button
                size="sm"
                variant="default"
                className="flex-1 h-8 text-xs"
                onClick={() => onNavigate(node)}
              >
                <ExternalLink className="h-3 w-3 mr-1" /> View Details
              </Button>
            )}
            {node.type === "technique" && (
              <Button
                size="sm"
                variant="default"
                className="flex-1 h-8 text-xs"
                onClick={() => onNavigate(node)}
              >
                <Target className="h-3 w-3 mr-1" /> ATT&CK Map
              </Button>
            )}
            <Button
              size="sm"
              variant="outline"
              className="flex-1 h-8 text-xs"
              onClick={() => onExplore(node)}
            >
              <Crosshair className="h-3 w-3 mr-1" /> Re-center
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Connections */}
      <Card className="border-border/30">
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs flex items-center gap-1.5 text-muted-foreground">
            <Activity className="h-3.5 w-3.5" />
            {edges.length} Connections
          </CardTitle>
        </CardHeader>
        <CardContent className="px-3 pb-3 max-h-[360px] overflow-y-auto">
          {Object.entries(connByType).map(([type, items]) => {
            const typeMeta = NODE_TYPE_META[type];
            return (
              <div key={type} className="mb-3 last:mb-0">
                <div className="flex items-center gap-1.5 mb-1.5 px-1">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ background: typeMeta?.color || "#6b7280" }}
                  />
                  <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">
                    {typeMeta?.label || type} ({items.length})
                  </span>
                </div>
                <div className="space-y-0.5">
                  {items.slice(0, 15).map((conn) => {
                    const edge = edges.find(
                      (e) =>
                        (e.source === node.id && e.target === conn.id) ||
                        (e.target === node.id && e.source === conn.id),
                    );
                    return (
                      <button
                        key={conn.id}
                        onClick={() => onExplore(conn)}
                        className="w-full text-left p-2 rounded-md hover:bg-muted/30 transition-colors group flex items-center gap-2"
                      >
                        <div
                          className="w-6 h-6 rounded-md flex items-center justify-center shrink-0 text-[10px] font-bold text-white"
                          style={{ background: typeMeta?.color || "#6b7280" }}
                        >
                          {type[0].toUpperCase()}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] font-medium truncate group-hover:text-foreground text-muted-foreground">
                            {conn.label}
                          </p>
                          {edge && (
                            <p className="text-[9px] text-muted-foreground/60">
                              {edge.type.replace(/[_-]/g, " ")} · {edge.confidence}%
                            </p>
                          )}
                        </div>
                        <ChevronRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-muted-foreground shrink-0" />
                      </button>
                    );
                  })}
                  {items.length > 15 && (
                    <p className="text-[10px] text-muted-foreground/50 px-2 py-1">
                      +{items.length - 15} more
                    </p>
                  )}
                </div>
              </div>
            );
          })}
          {edges.length === 0 && (
            <p className="text-[11px] text-muted-foreground/50 text-center py-4">
              No connections found for this entity
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
