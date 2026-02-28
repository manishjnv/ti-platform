"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loading } from "@/components/Loading";
import { ATTACKMatrix } from "@/components/ATTACKMatrix";
import { cn } from "@/lib/utils";
import * as api from "@/lib/api";
import type {
  AttackMatrixResponse,
  AttackTechniqueListResponse,
  AttackTechnique,
} from "@/types";
import {
  Shield,
  Search,
  Grid3X3,
  List,
  ExternalLink,
  ChevronRight,
  Eye,
  X,
  Loader2,
  Zap,
  AlertTriangle,
} from "lucide-react";
import type { IntelItem } from "@/types";

export default function TechniquesPage() {
  const [matrixData, setMatrixData] = useState<AttackMatrixResponse | null>(null);
  const [listData, setListData] = useState<AttackTechniqueListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string>("");
  const [view, setView] = useState<"matrix" | "list">("matrix");

  // Technique detail modal state (for list view)
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailTech, setDetailTech] = useState<{ id: string; name: string } | null>(null);
  const [detailData, setDetailData] = useState<{
    technique: any;
    intel_items: IntelItem[];
    subtechniques: any[];
    intel_count: number;
  } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const openTechDetail = useCallback(async (techId: string, techName: string) => {
    setDetailTech({ id: techId, name: techName });
    setDetailOpen(true);
    setDetailLoading(true);
    setDetailData(null);
    try {
      const data = await api.getAttackTechniqueDetail(techId);
      setDetailData(data);
    } catch (e) {
      console.error("Failed to fetch technique detail:", e);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeDetail = useCallback(() => {
    setDetailOpen(false);
    setDetailTech(null);
    setDetailData(null);
  }, []);

  const fetchMatrix = useCallback(async () => {
    try {
      const data = await api.getAttackMatrix();
      setMatrixData(data);
    } catch (e) {
      console.error("Failed to load ATT&CK matrix:", e);
    }
  }, []);

  const fetchList = useCallback(async () => {
    try {
      const data = await api.getAttackTechniques({
        tactic: selectedTactic || undefined,
        search: searchTerm || undefined,
        page_size: 200,
      });
      setListData(data);
    } catch (e) {
      console.error("Failed to load techniques:", e);
    }
  }, [selectedTactic, searchTerm]);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchMatrix(), fetchList()]).finally(() => setLoading(false));
  }, [fetchMatrix, fetchList]);

  if (loading && !matrixData) return <Loading text="Loading MITRE ATT&CK data..." />;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            MITRE ATT&CK
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enterprise technique coverage mapped to your threat intelligence
          </p>
        </div>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-muted-foreground hover:text-primary flex items-center gap-1"
        >
          <ExternalLink className="h-3 w-3" /> ATT&CK Framework
        </a>
      </div>

      {/* Stats Cards */}
      {matrixData && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card
            className="cursor-pointer hover:shadow-md hover:border-primary/30 transition-all"
            onClick={() => setView("list")}
          >
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{matrixData.total_techniques}</div>
              <div className="text-xs text-muted-foreground">Total Techniques</div>
            </CardContent>
          </Card>
          <Card
            className="cursor-pointer hover:shadow-md hover:border-primary/30 transition-all"
            onClick={() => { setView("list"); setSearchTerm(""); setSelectedTactic(""); }}
          >
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold text-primary">{matrixData.total_mapped}</div>
              <div className="text-xs text-muted-foreground">With Intel Hits</div>
            </CardContent>
          </Card>
          <Card
            className="cursor-pointer hover:shadow-md hover:border-primary/30 transition-all"
            onClick={() => setView("list")}
          >
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{matrixData.tactics.length}</div>
              <div className="text-xs text-muted-foreground">Tactics Covered</div>
            </CardContent>
          </Card>
          <Card
            className="cursor-pointer hover:shadow-md hover:border-primary/30 transition-all"
            onClick={() => setView("list")}
          >
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold text-orange-400">
                {matrixData.total_techniques > 0
                  ? ((matrixData.total_mapped / matrixData.total_techniques) * 100).toFixed(1)
                  : 0}%
              </div>
              <div className="text-xs text-muted-foreground">Coverage</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* View Toggle + Search */}
      <div className="flex items-center gap-3 flex-wrap">
        <Tabs value={view} onValueChange={(v) => setView(v as "matrix" | "list")}>
          <TabsList>
            <TabsTrigger value="matrix" className="gap-1.5">
              <Grid3X3 className="h-3.5 w-3.5" /> Matrix
            </TabsTrigger>
            <TabsTrigger value="list" className="gap-1.5">
              <List className="h-3.5 w-3.5" /> List
            </TabsTrigger>
          </TabsList>
        </Tabs>

        {view === "list" && (
          <>
            <div className="relative max-w-xs flex-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search techniques..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full h-8 pl-8 pr-3 rounded-md bg-muted/30 border border-border/40 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
              />
            </div>

            {listData?.tactics && (
              <div className="flex gap-1 flex-wrap">
                <button
                  onClick={() => setSelectedTactic("")}
                  className={cn(
                    "text-[10px] px-2 py-1 rounded-full border transition-colors",
                    !selectedTactic
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border/40 text-muted-foreground hover:bg-muted/30"
                  )}
                >
                  All
                </button>
                {listData.tactics.map((t) => (
                  <button
                    key={t}
                    onClick={() => setSelectedTactic(t === selectedTactic ? "" : t)}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded-full border transition-colors",
                      t === selectedTactic
                        ? "bg-primary text-primary-foreground border-primary"
                        : "border-border/40 text-muted-foreground hover:bg-muted/30"
                    )}
                  >
                    {t.replace(/-/g, " ")}
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* Matrix View */}
      {view === "matrix" && matrixData && <ATTACKMatrix data={matrixData} />}

      {/* List View */}
      {view === "list" && listData && (
        <div className="space-y-1">
          {listData.techniques.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No techniques found. Run the ATT&CK sync job first.</p>
              </CardContent>
            </Card>
          ) : (
            listData.techniques.map((tech) => (
              <TechniqueRow key={tech.id} technique={tech} onViewDetail={openTechDetail} />
            ))
          )}
        </div>
      )}
      {/* Technique Detail Modal (for list view) */}
      {detailOpen && detailTech && (
        <TechniqueDetailModal
          tech={detailTech}
          data={detailData}
          loading={detailLoading}
          onClose={closeDetail}
          onViewSub={(id, name) => openTechDetail(id, name)}
        />
      )}
    </div>
  );
}

const RISK_BG = (score: number) =>
  score >= 80 ? "bg-red-500/15 text-red-400" :
  score >= 60 ? "bg-orange-500/15 text-orange-400" :
  score >= 40 ? "bg-yellow-500/15 text-yellow-400" :
  "bg-green-500/15 text-green-400";

function TechniqueDetailModal({
  tech,
  data,
  loading,
  onClose,
  onViewSub,
}: {
  tech: { id: string; name: string };
  data: { technique: any; intel_items: IntelItem[]; subtechniques: any[]; intel_count: number } | null;
  loading: boolean;
  onClose: () => void;
  onViewSub: (id: string, name: string) => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-xl bg-background border-l border-border shadow-2xl overflow-y-auto animate-in slide-in-from-right-full duration-200">
        {/* Header */}
        <div className="sticky top-0 bg-background/95 backdrop-blur border-b border-border z-10 px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 min-w-0">
              <Badge variant="outline" className="font-mono text-xs shrink-0">{tech.id}</Badge>
              <h2 className="text-sm font-semibold truncate">{tech.name}</h2>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-md hover:bg-muted transition-colors shrink-0">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="flex items-center gap-3 mt-2">
            <a
              href={`https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline inline-flex items-center gap-1 text-[10px] ml-auto"
            >
              <ExternalLink className="h-3 w-3" /> MITRE ATT&CK
            </a>
          </div>
        </div>

        {/* Content */}
        <div className="px-5 py-4 space-y-5">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
              <span className="ml-2 text-sm text-muted-foreground">Loading technique data...</span>
            </div>
          ) : data ? (
            <>
              {data.technique?.description && (
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Description</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {data.technique.description.slice(0, 500)}
                    {data.technique.description.length > 500 && "..."}
                  </p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                {data.technique?.platforms?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Platforms</h3>
                    <div className="flex flex-wrap gap-1">
                      {data.technique.platforms.map((p: string) => (
                        <Badge key={p} variant="outline" className="text-[10px]">{p}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {data.technique?.data_sources?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Data Sources</h3>
                    <div className="flex flex-wrap gap-1">
                      {data.technique.data_sources.slice(0, 6).map((ds: string) => (
                        <Badge key={ds} variant="secondary" className="text-[10px]">{ds}</Badge>
                      ))}
                      {data.technique.data_sources.length > 6 && (
                        <span className="text-[10px] text-muted-foreground">+{data.technique.data_sources.length - 6}</span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {data.technique?.detection && (
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Detection</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {data.technique.detection.slice(0, 400)}
                    {data.technique.detection.length > 400 && "..."}
                  </p>
                </div>
              )}

              {data.subtechniques?.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
                    Sub-techniques ({data.subtechniques.length})
                  </h3>
                  <div className="space-y-1">
                    {data.subtechniques.map((sub: any) => (
                      <button
                        key={sub.id}
                        onClick={() => onViewSub(sub.id, sub.name)}
                        className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded border border-border/30 hover:bg-muted/20 text-left transition-colors group"
                      >
                        <Badge variant="outline" className="font-mono text-[9px] shrink-0">{sub.id}</Badge>
                        <span className="text-xs truncate group-hover:text-primary transition-colors">{sub.name}</span>
                        {sub.intel_count > 0 && (
                          <Badge variant="default" className="text-[9px] ml-auto shrink-0">
                            {sub.intel_count} hit{sub.intel_count !== 1 ? "s" : ""}
                          </Badge>
                        )}
                        <ChevronRight className="h-3 w-3 text-muted-foreground/30 group-hover:text-primary shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  Linked Intel Items ({data.intel_count})
                </h3>
                {data.intel_items.length > 0 ? (
                  <div className="space-y-1.5">
                    {data.intel_items.map((item: IntelItem) => (
                      <Link
                        key={item.id}
                        href={`/intel/${item.id}`}
                        className="block p-2.5 rounded-lg border border-border/30 hover:bg-muted/20 hover:border-primary/30 transition-all group"
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className={cn("inline-flex items-center justify-center h-6 w-8 rounded text-[10px] font-bold", RISK_BG(item.risk_score))}>
                            {item.risk_score}
                          </span>
                          <Badge variant={item.severity as any} className="text-[9px] px-1 py-0">
                            {item.severity?.toUpperCase()}
                          </Badge>
                          {item.is_kev && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">KEV</span>
                          )}
                          {item.exploit_available && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/15 text-orange-400 font-semibold">
                              <Zap className="h-2.5 w-2.5 inline" /> Exploit
                            </span>
                          )}
                          <span className="text-[10px] text-muted-foreground ml-auto shrink-0">{item.source_name}</span>
                        </div>
                        <p className="text-xs font-medium line-clamp-2 group-hover:text-primary transition-colors">{item.title}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-[10px] text-muted-foreground capitalize">{item.feed_type?.replace(/_/g, " ")}</span>
                          {item.cve_ids?.length > 0 && (
                            <span className="text-[10px] font-mono text-primary">{item.cve_ids[0]}</span>
                          )}
                          {(item.cve_ids?.length ?? 0) > 1 && (
                            <span className="text-[10px] text-muted-foreground">+{item.cve_ids.length - 1}</span>
                          )}
                          {item.published_at && (
                            <span className="text-[10px] text-muted-foreground ml-auto">
                              {new Date(item.published_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                            </span>
                          )}
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-8 w-8 mx-auto mb-2 opacity-20" />
                    <p className="text-xs">No intel items linked to this technique yet.</p>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-16 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-xs">Failed to load technique details.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function TechniqueRow({ technique: t, onViewDetail }: { technique: AttackTechnique; onViewDetail: (id: string, name: string) => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={cn(
        "rounded-md border border-border/30 transition-colors",
        t.intel_count > 0 ? "bg-card" : "bg-card/50"
      )}
    >
      <div
        className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-muted/20"
        onClick={() => setExpanded(!expanded)}
      >
        <ChevronRight
          className={cn(
            "h-3.5 w-3.5 text-muted-foreground transition-transform",
            expanded && "rotate-90"
          )}
        />
        <Badge variant="outline" className="font-mono text-[10px] shrink-0">
          {t.id}
        </Badge>
        <span className="text-sm font-medium flex-1 truncate">{t.name}</span>
        <Badge
          variant="secondary"
          className="text-[10px] shrink-0 capitalize"
        >
          {t.tactic_label}
        </Badge>
        {t.intel_count > 0 && (
          <Badge variant="default" className="text-[10px] shrink-0">
            {t.intel_count} hit{t.intel_count !== 1 ? "s" : ""}
          </Badge>
        )}
        {t.platforms.length > 0 && (
          <div className="hidden lg:flex gap-1">
            {t.platforms.slice(0, 3).map((p) => (
              <Badge key={p} variant="outline" className="text-[9px]">
                {p}
              </Badge>
            ))}
          </div>
        )}
        <button
          className="p-1 rounded hover:bg-primary/10 transition-colors"
          title="View detail"
          onClick={(e) => { e.stopPropagation(); onViewDetail(t.id, t.name); }}
        >
          <Eye className="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
        </button>
      </div>

      {expanded && (
        <div className="px-3 pb-3 pt-1 border-t border-border/20">
          <p className="text-xs text-muted-foreground leading-relaxed line-clamp-4">
            {t.description || "No description available."}
          </p>
          <div className="flex items-center gap-3 mt-2">
            {t.url && (
              <a
                href={t.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-primary hover:underline flex items-center gap-1"
              >
                <ExternalLink className="h-3 w-3" /> MITRE ATT&CK
              </a>
            )}
            {t.data_sources.length > 0 && (
              <span className="text-[10px] text-muted-foreground">
                Data sources: {t.data_sources.slice(0, 3).join(", ")}
                {t.data_sources.length > 3 && ` +${t.data_sources.length - 3}`}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
