"use client";

import React, { useEffect, useState, useCallback } from "react";
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
} from "lucide-react";

export default function TechniquesPage() {
  const [matrixData, setMatrixData] = useState<AttackMatrixResponse | null>(null);
  const [listData, setListData] = useState<AttackTechniqueListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string>("");
  const [view, setView] = useState<"matrix" | "list">("matrix");

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
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{matrixData.total_techniques}</div>
              <div className="text-xs text-muted-foreground">Total Techniques</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold text-primary">{matrixData.total_mapped}</div>
              <div className="text-xs text-muted-foreground">With Intel Hits</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-3">
              <div className="text-2xl font-bold">{matrixData.tactics.length}</div>
              <div className="text-xs text-muted-foreground">Tactics Covered</div>
            </CardContent>
          </Card>
          <Card>
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
              <TechniqueRow key={tech.id} technique={tech} />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function TechniqueRow({ technique: t }: { technique: AttackTechnique }) {
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
