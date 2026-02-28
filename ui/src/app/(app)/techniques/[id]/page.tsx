"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import {
  Shield, ExternalLink, ArrowLeft, Crosshair, AlertTriangle,
  BookOpen, Server, Layers, FileText, ChevronRight,
} from "lucide-react";
import * as api from "@/lib/api";
import type { AttackTechnique, IntelItem } from "@/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
  unknown: "#6b7280",
};

export default function TechniqueDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [technique, setTechnique] = useState<AttackTechnique | null>(null);
  const [intelItems, setIntelItems] = useState<IntelItem[]>([]);
  const [subtechniques, setSubtechniques] = useState<AttackTechnique[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    api
      .getAttackTechniqueDetail(id)
      .then((data) => {
        setTechnique(data.technique);
        setIntelItems(data.intel_items || []);
        setSubtechniques(data.subtechniques || []);
      })
      .catch(() => setError("Technique not found"))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <Loading text="Loading technique detail..." />;
  if (error || !technique) {
    return (
      <div className="p-6 text-center">
        <Shield className="h-12 w-12 mx-auto mb-3 text-muted-foreground/30" />
        <p className="text-muted-foreground">{error || "Technique not found"}</p>
        <button onClick={() => router.back()} className="mt-3 text-xs text-primary hover:underline">
          Go back
        </button>
      </div>
    );
  }

  const hasDetection = technique.detection && technique.detection.trim().length > 0;

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Back + Header */}
      <div className="flex items-start gap-3">
        <button
          onClick={() => router.back()}
          className="p-1.5 rounded-lg hover:bg-muted/40 shrink-0 mt-0.5"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="font-mono text-xs shrink-0">
              {technique.id}
            </Badge>
            <h1 className="text-xl font-bold tracking-tight">{technique.name}</h1>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge variant="secondary" className="text-[10px] capitalize">
              {technique.tactic_label}
            </Badge>
            {technique.is_subtechnique && technique.parent_id && (
              <Link
                href={`/techniques/${technique.parent_id}`}
                className="text-[10px] text-primary hover:underline"
              >
                Parent: {technique.parent_id}
              </Link>
            )}
            {technique.url && (
              <a
                href={technique.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-muted-foreground hover:text-primary flex items-center gap-0.5"
              >
                <ExternalLink className="h-3 w-3" /> MITRE ATT&CK
              </a>
            )}
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10">
              <Crosshair className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <p className="text-lg font-bold">{intelItems.length}</p>
              <p className="text-[10px] text-muted-foreground">Intel Hits</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10">
              <Layers className="h-4 w-4 text-purple-400" />
            </div>
            <div>
              <p className="text-lg font-bold">{subtechniques.length}</p>
              <p className="text-[10px] text-muted-foreground">Sub-techniques</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <Server className="h-4 w-4 text-green-400" />
            </div>
            <div>
              <p className="text-lg font-bold">{technique.platforms.length}</p>
              <p className="text-[10px] text-muted-foreground">Platforms</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10">
              <BookOpen className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-lg font-bold">{technique.data_sources.length}</p>
              <p className="text-[10px] text-muted-foreground">Data Sources</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Description */}
      {technique.description && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
              <FileText className="h-3.5 w-3.5" />
              Description
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <p className="text-xs text-muted-foreground leading-relaxed whitespace-pre-wrap">
              {technique.description}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Detection */}
      {hasDetection && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-semibold flex items-center gap-1.5 text-green-400">
              <Shield className="h-3.5 w-3.5" />
              Detection Guidance
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <p className="text-xs text-muted-foreground leading-relaxed whitespace-pre-wrap">
              {technique.detection}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Platforms & Data Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {technique.platforms.length > 0 && (
          <Card>
            <CardHeader className="pb-2 pt-3 px-4">
              <CardTitle className="text-xs font-semibold">Platforms</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <div className="flex flex-wrap gap-1.5">
                {technique.platforms.map((p) => (
                  <Badge key={p} variant="outline" className="text-[10px]">{p}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
        {technique.data_sources.length > 0 && (
          <Card>
            <CardHeader className="pb-2 pt-3 px-4">
              <CardTitle className="text-xs font-semibold">Data Sources</CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <div className="flex flex-wrap gap-1.5">
                {technique.data_sources.map((ds) => (
                  <Badge key={ds} variant="secondary" className="text-[10px]">{ds}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Sub-techniques */}
      {subtechniques.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-purple-400" />
              Sub-techniques ({subtechniques.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-1">
            {subtechniques.map((sub) => (
              <Link
                key={sub.id}
                href={`/techniques/${sub.id}`}
                className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-muted/20 transition-colors group"
              >
                <Badge variant="outline" className="font-mono text-[10px] shrink-0">{sub.id}</Badge>
                <span className="text-xs flex-1 truncate">{sub.name}</span>
                {sub.intel_count > 0 && (
                  <Badge variant="default" className="text-[10px]">{sub.intel_count} hits</Badge>
                )}
                <ChevronRight className="h-3 w-3 text-muted-foreground group-hover:text-foreground" />
              </Link>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Linked Intel Items */}
      {intelItems.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-semibold flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
              Related Intel ({intelItems.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/40">
                    <th className="text-left py-2 px-4 text-muted-foreground font-medium">Title</th>
                    <th className="text-left py-2 px-4 text-muted-foreground font-medium">Severity</th>
                    <th className="text-left py-2 px-4 text-muted-foreground font-medium">Risk</th>
                    <th className="text-left py-2 px-4 text-muted-foreground font-medium">Source</th>
                    <th className="text-left py-2 px-4 text-muted-foreground font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {intelItems.map((item) => {
                    const sevCol = SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.unknown;
                    return (
                      <tr key={item.id} className="border-b border-border/20 hover:bg-muted/20">
                        <td className="py-2 px-4 max-w-[300px]">
                          <Link
                            href={`/intel/${item.id}`}
                            className="text-primary hover:underline truncate block"
                          >
                            {item.title}
                          </Link>
                        </td>
                        <td className="py-2 px-4">
                          <Badge
                            variant="outline"
                            className="text-[10px]"
                            style={{ borderColor: sevCol, color: sevCol }}
                          >
                            {item.severity}
                          </Badge>
                        </td>
                        <td className="py-2 px-4">
                          <span className="font-semibold" style={{ color: sevCol }}>
                            {item.risk_score}
                          </span>
                        </td>
                        <td className="py-2 px-4 text-muted-foreground">{item.source_name}</td>
                        <td className="py-2 px-4 text-muted-foreground">
                          {item.ingested_at ? new Date(item.ingested_at).toLocaleDateString() : "—"}
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

      {intelItems.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center">
            <Shield className="h-8 w-8 mx-auto mb-2 text-muted-foreground/30" />
            <p className="text-xs text-muted-foreground">No intel items linked to this technique yet</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
