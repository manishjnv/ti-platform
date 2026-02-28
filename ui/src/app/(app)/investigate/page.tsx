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
} from "lucide-react";

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

  /* Load stats on mount */
  useEffect(() => {
    api.getGraphStats().then(setStats).catch(() => {});
  }, []);

  /* Auto-load if URL has params */
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

  const handleNodeClick = useCallback(
    (node: GraphNode) => {
      if (node.type === "intel") {
        router.push(`/intel/${node.id}`);
      } else {
        setQuery(node.id);
        setEntityType(node.type);
        explore(node.id, node.type, depth);
      }
    },
    [router, explore, depth]
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    explore();
  };

  return (
    <div className="p-6 space-y-6">
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
      <Card>
        <CardContent className="py-4">
          <form onSubmit={handleSubmit} className="flex items-center gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter an intel item ID, IOC value, or CVE ID…"
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
              <span className="text-sm w-14 text-center">{depth} hops</span>
              <button
                type="button"
                onClick={() => setDepth((d) => Math.min(3, d + 1))}
                className="p-0.5 hover:text-primary"
              >
                <Plus className="h-3.5 w-3.5" />
              </button>
            </div>
            <Button type="submit" disabled={loading || !query.trim()}>
              {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : "Explore"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Graph or Empty State */}
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
        <div className="space-y-4">
          <Card>
            <CardContent className="p-0 overflow-hidden">
              <GraphExplorer
                data={graphData}
                width={1100}
                height={600}
                onNodeClick={handleNodeClick}
              />
            </CardContent>
          </Card>

          {/* Edge details table */}
          {graphData.edges.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Info className="h-4 w-4" /> Relationship Details
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-muted-foreground text-left">
                        <th className="py-2 px-3 font-medium">Source</th>
                        <th className="py-2 px-3 font-medium">Relationship</th>
                        <th className="py-2 px-3 font-medium">Target</th>
                        <th className="py-2 px-3 font-medium text-right">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {graphData.edges.slice(0, 50).map((edge) => {
                        const sNode = graphData.nodes.find((n) => n.id === edge.source);
                        const tNode = graphData.nodes.find((n) => n.id === edge.target);
                        return (
                          <tr key={edge.id} className="border-b border-border/20 hover:bg-muted/20">
                            <td className="py-1.5 px-3">
                              <span className="text-xs">{sNode?.label || edge.source}</span>
                              <Badge variant="outline" className="ml-1 text-[9px]">
                                {sNode?.type || "?"}
                              </Badge>
                            </td>
                            <td className="py-1.5 px-3">
                              <Badge variant="secondary" className="text-[10px]">
                                {edge.type.replace(/_/g, " ")}
                              </Badge>
                            </td>
                            <td className="py-1.5 px-3">
                              <span className="text-xs">{tNode?.label || edge.target}</span>
                              <Badge variant="outline" className="ml-1 text-[9px]">
                                {tNode?.type || "?"}
                              </Badge>
                            </td>
                            <td className="py-1.5 px-3 text-right">
                              <span
                                className={cn(
                                  "font-medium text-xs",
                                  edge.confidence >= 75
                                    ? "text-green-500"
                                    : edge.confidence >= 50
                                    ? "text-yellow-500"
                                    : "text-muted-foreground"
                                )}
                              >
                                {edge.confidence}%
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      ) : (
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            <Share2 className="h-14 w-14 mx-auto mb-4 opacity-20" />
            <p className="font-medium">Start by entering an entity ID above</p>
            <p className="text-sm mt-1">
              Search for an intel item, IOC, CVE, or ATT&CK technique to explore its relationship graph.
            </p>
            {stats && stats.total_relationships > 0 && (
              <p className="text-xs mt-4 text-muted-foreground/60">
                {stats.total_relationships.toLocaleString()} relationships discovered across your intel corpus
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
