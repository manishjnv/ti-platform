"use client";

import React, { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { cn } from "@/lib/utils";
import * as api from "@/lib/api";
import type { DetectionRule, DetectionCoverage } from "@/types";
import {
  ShieldCheck,
  RefreshCw,
  Loader2,
  Search,
  Copy,
  Check,
  Filter,
  FileCode,
  Crosshair,
  Zap,
} from "lucide-react";

const RULE_TYPE_COLORS: Record<string, string> = {
  yara: "#ef4444",
  sigma: "#a855f7",
  kql: "#3b82f6",
  snort: "#f97316",
  suricata: "#14b8a6",
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10",
  high: "text-orange-400 bg-orange-500/10",
  medium: "text-yellow-400 bg-yellow-500/10",
  low: "text-green-400 bg-green-500/10",
};

export default function DetectionsPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [coverage, setCoverage] = useState<DetectionCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [typeFilter, setTypeFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r, c] = await Promise.all([
        api.getDetectionRules({
          rule_type: typeFilter || undefined,
          severity: sevFilter || undefined,
          limit: 100,
        }),
        api.getDetectionCoverage(),
      ]);
      setRules(r);
      setCoverage(c);
    } catch (e) {
      console.error("Failed to load detection rules", e);
    }
    setLoading(false);
  }, [typeFilter, sevFilter]);

  useEffect(() => { load(); }, [load]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await api.syncDetectionRules();
      load();
    } catch (e) {
      console.error("Sync failed", e);
    }
    setSyncing(false);
  };

  const copyRule = (id: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const filtered = rules.filter((r) =>
    !searchTerm || r.name.toLowerCase().includes(searchTerm.toLowerCase()) || r.campaign_name?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading && rules.length === 0) return <Loading text="Loading detection rules..." />;

  return (
    <div className="p-4 md:p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            Detection Rules
          </h1>
          <p className="text-sm text-muted-foreground">
            Auto-generated detection rules from cyber news intelligence
          </p>
        </div>
        <button
          onClick={handleSync}
          disabled={syncing}
          className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {syncing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          Sync from News
        </button>
      </div>

      {/* Coverage Stats */}
      {coverage && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{coverage.total_rules}</div>
              <div className="text-xs text-muted-foreground">Total Rules</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold text-primary">{coverage.techniques_covered}</div>
              <div className="text-xs text-muted-foreground">Techniques Covered</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{coverage.campaigns_covered}</div>
              <div className="text-xs text-muted-foreground">Campaigns Covered</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="flex gap-2">
                {[
                  { type: "yara", count: coverage.yara_count },
                  { type: "kql", count: coverage.kql_count },
                  { type: "sigma", count: coverage.sigma_count },
                ].filter(t => t.count > 0).map(({ type, count }) => (
                  <Badge key={type} variant="outline" className="text-[10px]" style={{ color: RULE_TYPE_COLORS[type] || "#6b7280" }}>
                    {type.toUpperCase()}: {count}
                  </Badge>
                ))}
              </div>
              <div className="text-xs text-muted-foreground mt-1">By Type</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search rules or campaigns..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full h-8 pl-8 pr-3 rounded-md bg-muted/30 border border-border/40 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
          />
        </div>
        <div className="flex gap-1">
          {["", "yara", "sigma", "kql", "snort"].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                "text-[10px] px-2.5 py-1 rounded-full border transition-colors",
                typeFilter === t
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border/40 text-muted-foreground hover:bg-muted/30"
              )}
            >
              {t ? t.toUpperCase() : "All Types"}
            </button>
          ))}
        </div>
        <div className="flex gap-1">
          {["", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setSevFilter(s)}
              className={cn(
                "text-[10px] px-2.5 py-1 rounded-full border transition-colors capitalize",
                sevFilter === s
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border/40 text-muted-foreground hover:bg-muted/30"
              )}
            >
              {s || "All Severity"}
            </button>
          ))}
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center text-muted-foreground">
              <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No detection rules found. Click &ldquo;Sync from News&rdquo; to generate rules.</p>
            </CardContent>
          </Card>
        ) : (
          filtered.map((rule) => (
            <Card key={rule.id} className="border-l-2" style={{ borderLeftColor: RULE_TYPE_COLORS[rule.rule_type] || "#6b7280" }}>
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/20"
                onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
              >
                <FileCode className="h-4 w-4 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium">{rule.name}</span>
                    <Badge variant="outline" className="text-[9px]" style={{ color: RULE_TYPE_COLORS[rule.rule_type] }}>
                      {rule.rule_type.toUpperCase()}
                    </Badge>
                    {rule.severity && (
                      <span className={cn("text-[9px] px-1.5 py-0.5 rounded font-medium", SEV_COLORS[rule.severity])}>
                        {rule.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground">
                    {rule.campaign_name && (
                      <span className="text-violet-400">{rule.campaign_name}</span>
                    )}
                    {rule.technique_ids.length > 0 && (
                      <span className="font-mono">{rule.technique_ids.slice(0, 3).join(", ")}</span>
                    )}
                    {rule.cve_ids.length > 0 && (
                      <span className="text-primary font-mono">{rule.cve_ids.slice(0, 2).join(", ")}</span>
                    )}
                    {rule.quality_score != null && (
                      <span>Quality: {rule.quality_score}%</span>
                    )}
                  </div>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); copyRule(rule.id, rule.content); }}
                  className="p-1.5 rounded hover:bg-muted/40"
                  title="Copy rule"
                >
                  {copiedId === rule.id ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
                </button>
              </div>
              {expandedId === rule.id && (
                <div className="px-4 pb-3 pt-1 border-t border-border/20">
                  <pre className="text-xs bg-muted/30 rounded-md p-3 overflow-x-auto max-h-64 overflow-y-auto font-mono leading-relaxed">
                    {rule.content}
                  </pre>
                </div>
              )}
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
