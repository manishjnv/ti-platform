"use client";

import React, { useEffect, useState, useCallback } from "react";
import { X, ExternalLink, Shield, AlertTriangle, Bug, Globe, Building2, Tag, Zap, ChevronRight, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import * as api from "@/lib/api";
import type { InsightDetail, InsightDetailItem } from "@/types";
import Link from "next/link";
import { StructuredIntelCards } from "@/components/StructuredIntelCards";

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-green-500/15 text-green-400 border-green-500/20",
  info: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  unknown: "bg-muted text-muted-foreground border-border",
};

interface InsightDetailModalProps {
  open: boolean;
  onClose: () => void;
  type: string; // product | threat_actor | ransomware | malware | cve
  name: string;
}

export function InsightDetailModal({ open, onClose, type, name }: InsightDetailModalProps) {
  const [data, setData] = useState<InsightDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDetail = useCallback(async () => {
    if (!name || !type) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.getInsightDetail(type, name);
      setData(res);
    } catch (e: any) {
      setError(e.message || "Failed to load detail");
    } finally {
      setLoading(false);
    }
  }, [type, name]);

  useEffect(() => {
    if (open) {
      fetchDetail();
    } else {
      setData(null);
    }
  }, [open, fetchDetail]);

  // Close on Escape
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (open) window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;

  const s = data?.summary;
  const items = data?.items ?? [];

  const typeLabel =
    type === "product" ? "Product" :
    type === "threat_actor" ? "Threat Actor" :
    type === "ransomware" ? "Ransomware" :
    type === "malware" ? "Malware" :
    type === "cve" ? "CVE" : "Entity";

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-8 pb-8">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-background border rounded-xl shadow-2xl flex flex-col overflow-hidden mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b bg-card">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
              {typeLabel} Detail
            </p>
            <h2 className="text-lg font-bold capitalize mt-0.5">
              {name.replace(/_/g, " ")}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-accent transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-sm text-muted-foreground">Loading details...</span>
            </div>
          )}

          {error && (
            <div className="text-center py-8 text-red-400 text-sm">{error}</div>
          )}

          {!loading && !error && s && (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <SummaryCard label="Total Intel" value={s.total_items} icon={<Shield className="h-4 w-4" />} />
                <SummaryCard label="Avg Risk" value={s.avg_risk} icon={<AlertTriangle className="h-4 w-4" />}
                  className={s.avg_risk >= 70 ? "text-red-400" : s.avg_risk >= 40 ? "text-orange-400" : "text-green-400"} />
                <SummaryCard label="Exploits" value={s.exploit_count} icon={<Bug className="h-4 w-4" />}
                  className={s.exploit_count > 0 ? "text-red-400" : ""} />
                <SummaryCard label="CVEs" value={s.top_cves.length} icon={<Zap className="h-4 w-4" />} />
              </div>

              {/* Severity Distribution */}
              {Object.keys(s.severity_distribution).length > 0 && (
                <div>
                  <SectionTitle text="Severity Distribution" />
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(s.severity_distribution)
                      .sort((a, b) => b[1] - a[1])
                      .map(([sev, count]) => (
                        <span key={sev} className={cn("text-xs px-2.5 py-1 rounded-md font-medium border", SEV_COLORS[sev] || SEV_COLORS.unknown)}>
                          {sev.charAt(0).toUpperCase() + sev.slice(1)}: {count}
                        </span>
                      ))}
                  </div>
                </div>
              )}

              {/* Unified Structured Intel Cards */}
              <StructuredIntelCards
                data={{
                  threatActors: type === "threat_actor" ? [name] : undefined,
                  affectedProducts: s.top_products.map((p) => p.name),
                  knownBreaches: type === "ransomware"
                    ? `${name} ransomware — ${s.total_items} associated intel items with average risk ${s.avg_risk}`
                    : null,
                  keyFindings: [
                    `${s.total_items} intelligence item${s.total_items !== 1 ? "s" : ""} linked to this entity`,
                    ...(s.avg_risk >= 70 ? [`High average risk score: ${s.avg_risk}`] : []),
                    ...(s.exploit_count > 0 ? [`${s.exploit_count} exploit${s.exploit_count !== 1 ? "s" : ""} associated`] : []),
                    ...(s.top_cves.length > 0 ? [`${s.top_cves.length} related CVE${s.top_cves.length !== 1 ? "s" : ""}: ${s.top_cves.slice(0, 3).map(c => c.name).join(", ")}`] : []),
                    ...(s.top_regions.length > 0 ? [`Targets regions: ${s.top_regions.slice(0, 3).map(r => r.name).join(", ")}`] : []),
                    ...(s.top_industries.length > 0 ? [`Targets industries: ${s.top_industries.slice(0, 3).map(i => i.name).join(", ")}`] : []),
                  ],
                }}
                variant="full"
              />

              {/* Top CVEs */}
              {s.top_cves.length > 0 && (
                <div>
                  <SectionTitle text="Related CVEs" />
                  <div className="flex flex-wrap gap-1.5">
                    {s.top_cves.map((c) => (
                      <Link
                        key={c.name}
                        href={`/search?q=${encodeURIComponent(c.name)}`}
                        className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
                      >
                        {c.name}
                        <span className="text-muted-foreground">({c.count})</span>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {/* Regions & Industries row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {s.top_regions.length > 0 && (
                  <div>
                    <SectionTitle text="Targeted Regions" icon={<Globe className="h-3.5 w-3.5" />} />
                    <div className="flex flex-wrap gap-1.5">
                      {s.top_regions.map((r) => (
                        <span key={r.name} className="text-[11px] px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-400">
                          {r.name} <span className="text-muted-foreground">({r.count})</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {s.top_industries.length > 0 && (
                  <div>
                    <SectionTitle text="Targeted Industries" icon={<Building2 className="h-3.5 w-3.5" />} />
                    <div className="flex flex-wrap gap-1.5">
                      {s.top_industries.map((ind) => (
                        <span key={ind.name} className="text-[11px] px-2 py-1 rounded-md bg-blue-500/10 text-blue-400">
                          {ind.name} <span className="text-muted-foreground">({ind.count})</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Top Products (useful for TA/ransomware/malware) */}
              {type !== "product" && s.top_products.length > 0 && (
                <div>
                  <SectionTitle text="Affected Products" />
                  <div className="flex flex-wrap gap-1.5">
                    {s.top_products.map((p) => (
                      <span key={p.name} className="text-[11px] px-2 py-1 rounded-md bg-violet-500/10 text-violet-400">
                        {p.name} <span className="text-muted-foreground">({p.count})</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags / TTPs */}
              {s.top_tags.length > 0 && (
                <div>
                  <SectionTitle text="Tags / TTPs" icon={<Tag className="h-3.5 w-3.5" />} />
                  <div className="flex flex-wrap gap-1.5">
                    {s.top_tags.map((t) => (
                      <span key={t.name} className="text-[11px] px-2 py-1 rounded-md bg-muted text-muted-foreground">
                        {t.name.replace(/_/g, " ")} <span className="opacity-60">({t.count})</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent Intel Items */}
              <div>
                <SectionTitle text={`Recent Intel (${items.length})`} />
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {items.map((item) => (
                    <IntelItemRow key={item.id} item={item} />
                  ))}
                </div>
              </div>
            </>
          )}

          {!loading && !error && data && items.length === 0 && (
            <div className="text-center py-12 text-muted-foreground text-sm">
              No detailed data found for this entity.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ═══ View-All Modal ═══ */

interface ViewAllModalProps {
  open: boolean;
  onClose: () => void;
  type: string; // threat_actor | ransomware | malware
  title: string;
  onSelect: (name: string) => void;
}

export function ViewAllModal({ open, onClose, type, title, onSelect }: ViewAllModalProps) {
  const [entities, setEntities] = useState<import("@/types").AllInsightEntity[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) { setEntities([]); return; }
    setLoading(true);
    api.getAllInsights(type)
      .then((d) => setEntities(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [open, type]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (open) window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-8 pb-8">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-3xl max-h-[85vh] bg-background border rounded-xl shadow-2xl flex flex-col overflow-hidden mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b bg-card">
          <h2 className="text-lg font-bold">{title}</h2>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-accent transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}
          {!loading && entities.length === 0 && (
            <div className="text-center py-12 text-muted-foreground text-sm">No data found.</div>
          )}
          {!loading && entities.map((ent) => (
            <button
              key={ent.name}
              onClick={() => { onSelect(ent.name); onClose(); }}
              className="w-full flex items-start gap-3 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors text-left group"
            >
              <span className={cn(
                "flex items-center justify-center h-9 w-9 rounded-md text-xs font-bold shrink-0",
                ent.avg_risk >= 70 ? "bg-red-500/15 text-red-400" :
                ent.avg_risk >= 40 ? "bg-orange-500/15 text-orange-400" :
                "bg-green-500/15 text-green-400"
              )}>
                {Math.round(ent.avg_risk)}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold capitalize group-hover:text-primary transition-colors">
                    {ent.name.replace(/_/g, " ")}
                  </span>
                  <span className="text-[10px] text-muted-foreground">{ent.count} intel items</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {ent.cves.slice(0, 3).map((c) => (
                    <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono">{c}</span>
                  ))}
                  {ent.industries.slice(0, 2).map((ind) => (
                    <span key={ind} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400">{ind}</span>
                  ))}
                  {ent.regions.slice(0, 2).map((r) => (
                    <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">{r}</span>
                  ))}
                </div>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-primary shrink-0 mt-2" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}


/* ═══ Sub-components ═══ */

function SummaryCard({ label, value, icon, className }: {
  label: string; value: number; icon: React.ReactNode; className?: string;
}) {
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg border bg-card">
      <span className="text-muted-foreground">{icon}</span>
      <div>
        <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
        <p className={cn("text-lg font-bold", className)}>{typeof value === "number" && !Number.isInteger(value) ? value.toFixed(1) : value}</p>
      </div>
    </div>
  );
}

function SectionTitle({ text, icon }: { text: string; icon?: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 mb-2">
      {icon && <span className="text-muted-foreground">{icon}</span>}
      <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{text}</h3>
    </div>
  );
}

function IntelItemRow({ item }: { item: InsightDetailItem }) {
  return (
    <Link
      href={`/intel/${item.id}`}
      className="flex items-start gap-3 p-3 rounded-lg border bg-card/50 hover:bg-accent/40 transition-colors group"
    >
      <span className={cn(
        "flex items-center justify-center h-8 w-8 rounded-md text-xs font-bold shrink-0 mt-0.5",
        item.risk_score >= 80 ? "bg-red-500/15 text-red-400" :
        item.risk_score >= 60 ? "bg-orange-500/15 text-orange-400" :
        item.risk_score >= 40 ? "bg-yellow-500/15 text-yellow-400" :
        "bg-green-500/15 text-green-400"
      )}>
        {item.risk_score}
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium line-clamp-1 group-hover:text-primary transition-colors">
          {item.title}
        </p>
        <div className="flex items-center gap-2 mt-0.5 text-[10px] text-muted-foreground">
          <Badge variant={item.severity as any} className="text-[9px] px-1 py-0 h-4">
            {item.severity.toUpperCase()}
          </Badge>
          <span>{item.source_name}</span>
          <span>{item.feed_type.replace(/_/g, " ")}</span>
          {item.exploit_available && <span className="text-red-400 font-medium">Exploit</span>}
          {item.is_kev && <span className="text-red-400 font-medium">KEV</span>}
          {item.published_at && (
            <span>{new Date(item.published_at).toLocaleDateString()}</span>
          )}
        </div>
        {item.cve_ids.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {item.cve_ids.slice(0, 4).map((c) => (
              <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-primary/10 text-primary">{c}</span>
            ))}
            {item.cve_ids.length > 4 && <span className="text-[10px] text-muted-foreground">+{item.cve_ids.length - 4}</span>}
          </div>
        )}
      </div>
      <ExternalLink className="h-3.5 w-3.5 text-muted-foreground/30 group-hover:text-primary shrink-0 mt-1" />
    </Link>
  );
}
