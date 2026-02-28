"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAppStore } from "@/store";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loading } from "@/components/Loading";
import {
  cn,
  formatDate,
  severityColor,
  riskColor,
  riskBg,
} from "@/lib/utils";
import {
  ArrowLeft,
  ExternalLink,
  Shield,
  Clock,
  AlertTriangle,
  Tag,
  Globe,
  Lock,
  Zap,
  Cpu,
  FileText,
  TrendingUp,
  Crosshair,
} from "lucide-react";
import type { IntelAttackLink, RelatedIntelItem } from "@/types";
import * as api from "@/lib/api";

export default function IntelDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { selectedItem: item, selectedLoading, fetchItem, clearSelectedItem } = useAppStore();
  const id = params?.id as string;
  const [attackLinks, setAttackLinks] = useState<IntelAttackLink[]>([]);
  const [attackLoading, setAttackLoading] = useState(false);
  const [relatedItems, setRelatedItems] = useState<RelatedIntelItem[]>([]);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [addingToReport, setAddingToReport] = useState(false);
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const [userReports, setUserReports] = useState<{ id: string; title: string }[]>([]);
  const [reportActionMsg, setReportActionMsg] = useState<string | null>(null);

  useEffect(() => {
    if (id) fetchItem(id);
    return () => clearSelectedItem();
  }, [id, fetchItem, clearSelectedItem]);

  useEffect(() => {
    if (!id) return;
    setAttackLoading(true);
    api.getIntelAttackLinks(id)
      .then(setAttackLinks)
      .catch(() => setAttackLinks([]))
      .finally(() => setAttackLoading(false));

    setRelatedLoading(true);
    api.getRelatedIntel(id)
      .then(setRelatedItems)
      .catch(() => setRelatedItems([]))
      .finally(() => setRelatedLoading(false));
  }, [id]);

  if (selectedLoading) return <Loading text="Loading intel item..." />;
  if (!item)
    return (
      <div className="p-6 text-center text-muted-foreground">
        Intel item not found
      </div>
    );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Back button + Actions */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" onClick={() => router.back()} className="gap-2">
          <ArrowLeft className="h-4 w-4" /> Back
        </Button>
        <div className="relative">
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              if (!reportMenuOpen) {
                try {
                  const data = await api.getReports({ page: 1, page_size: 20, status: "draft" });
                  setUserReports(data.reports.map((r) => ({ id: r.id, title: r.title })));
                } catch { setUserReports([]); }
              }
              setReportMenuOpen(!reportMenuOpen);
            }}
          >
            <FileText className="h-3.5 w-3.5 mr-1" />
            Add to Report
          </Button>
          {reportMenuOpen && (
            <div className="absolute right-0 top-full mt-1 w-64 border rounded-lg bg-popover shadow-lg z-50 p-1 max-h-60 overflow-y-auto">
              {userReports.length === 0 ? (
                <p className="text-xs text-muted-foreground p-2">No draft reports. Create one first.</p>
              ) : (
                userReports.map((r) => (
                  <button
                    key={r.id}
                    className="w-full text-left px-3 py-1.5 text-sm rounded hover:bg-accent/50 truncate"
                    onClick={async () => {
                      setAddingToReport(true);
                      setReportMenuOpen(false);
                      try {
                        await api.addReportItem(r.id, {
                          item_type: "intel",
                          item_id: item!.id,
                          item_title: item!.title,
                          item_metadata: {
                            severity: item!.severity,
                            risk_score: item!.risk_score,
                            source_name: item!.source_name,
                            feed_type: item!.feed_type,
                            cve_ids: item!.cve_ids,
                          },
                        });
                        setReportActionMsg(`Added to "${r.title}"`);
                      } catch {
                        setReportActionMsg("Already linked or error");
                      }
                      setAddingToReport(false);
                      setTimeout(() => setReportActionMsg(null), 3000);
                    }}
                  >
                    {r.title}
                  </button>
                ))
              )}
            </div>
          )}
          {reportActionMsg && (
            <div className="absolute right-0 top-full mt-1 px-3 py-1.5 rounded-md bg-primary/10 text-primary text-xs whitespace-nowrap z-50">
              {reportActionMsg}
            </div>
          )}
        </div>
      </div>

      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <Badge variant={item.severity as any} className="text-sm">
              {item.severity.toUpperCase()}
            </Badge>
            {item.is_kev && (
              <Badge variant="destructive" className="gap-1">
                <AlertTriangle className="h-3 w-3" /> KEV
              </Badge>
            )}
            {item.exploit_available && (
              <Badge variant="outline" className="text-orange-500 border-orange-500 gap-1">
                <Zap className="h-3 w-3" /> Exploit Available
              </Badge>
            )}
            <Badge variant="outline">{item.feed_type}</Badge>
            <Badge variant="outline">{item.asset_type}</Badge>
            <Badge variant="outline">{item.tlp}</Badge>
          </div>
          <h1 className="text-xl font-bold leading-tight">{item.title}</h1>
        </div>

        <div
          className={cn(
            "flex flex-col items-center justify-center rounded-xl p-4 min-w-[80px]",
            riskBg(item.risk_score)
          )}
        >
          <span className={cn("text-4xl font-bold", riskColor(item.risk_score))}>
            {item.risk_score}
          </span>
          <span className="text-xs text-muted-foreground mt-1">RISK SCORE</span>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="attack" className="gap-1">
            <Crosshair className="h-3 w-3" /> ATT&CK
            {attackLinks.length > 0 && (
              <Badge variant="secondary" className="text-[9px] ml-1 px-1 py-0">
                {attackLinks.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="related">
            Related Intel
            {relatedItems.length > 0 && (
              <Badge variant="secondary" className="text-[9px] ml-1 px-1 py-0">
                {relatedItems.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 mt-4">
          {/* AI Summary */}
          {item.ai_summary && (
            <Card className="border-purple-500/30 bg-purple-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-purple-400" /> AI Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{item.ai_summary}</p>
                {item.ai_summary_at && (
                  <p className="text-xs text-muted-foreground mt-2">
                    Generated {formatDate(item.ai_summary_at, { relative: true })}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Description */}
          {item.description && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileText className="h-4 w-4" /> Description
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm whitespace-pre-wrap">{item.description}</p>
              </CardContent>
            </Card>
          )}

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Source Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="Source" value={item.source_name} icon={Shield} />
                <Row label="Reliability" value={`${item.source_reliability}/100`} icon={TrendingUp} />
                <Row label="Confidence" value={`${item.confidence}%`} icon={Shield} />
                <Row label="Reference" value={item.source_ref || "N/A"} icon={FileText} />
                {item.source_url && (
                  <div>
                    <a
                      href={item.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center gap-1 text-sm"
                    >
                      <ExternalLink className="h-3 w-3" /> View Source
                    </a>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Timestamps</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="Published" value={formatDate(item.published_at)} icon={Clock} />
                <Row label="First Seen" value={formatDate(item.published_at)} icon={Clock} />
                <Row label="Ingested" value={formatDate(item.ingested_at)} icon={Clock} />
                <Row label="Updated" value={formatDate(item.updated_at)} icon={Clock} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Classification</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <Row label="TLP" value={item.tlp} icon={Lock} />
                <Row label="Asset Type" value={item.asset_type} icon={Cpu} />
                <Row label="Feed Type" value={item.feed_type} icon={FileText} />
                <Row label="Related IOCs" value={String(item.related_ioc_count)} icon={AlertTriangle} />
                {item.exploitability_score != null && (
                  <Row label="CVSS Score" value={String(item.exploitability_score)} icon={Zap} />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Context</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                {item.cve_ids.length > 0 && (
                  <div>
                    <span className="text-muted-foreground block mb-1">CVE IDs</span>
                    <div className="flex flex-wrap gap-1">
                      {item.cve_ids.map((cve) => (
                        <Badge key={cve} variant="secondary">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {cve}
                          </a>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {item.tags.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Tag className="h-3 w-3" /> Tags
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {item.tags.map((tag) => (
                        <Badge key={tag} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {item.geo.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Globe className="h-3 w-3" /> Geo
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {item.geo.map((g) => (
                        <Badge key={g} variant="outline" className="text-xs">
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {item.affected_products.length > 0 && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1 mb-1">
                      <Cpu className="h-3 w-3" /> Affected Products
                    </span>
                    <ul className="list-disc list-inside text-muted-foreground text-xs space-y-0.5">
                      {item.affected_products.map((p) => (
                        <li key={p} className="truncate">{p}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="attack" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-primary" /> MITRE ATT&CK Techniques
              </CardTitle>
            </CardHeader>
            <CardContent>
              {attackLoading ? (
                <div className="text-center py-4 text-sm text-muted-foreground">Loading...</div>
              ) : attackLinks.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No ATT&CK techniques mapped to this item yet.</p>
                  <p className="text-xs mt-1">Auto-mapping runs periodically based on text analysis.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {attackLinks.map((link) => (
                    <div
                      key={link.technique_id}
                      className="flex items-center gap-3 rounded-md border border-border/30 px-3 py-2 hover:bg-muted/20 transition-colors"
                    >
                      <Badge variant="outline" className="font-mono text-[10px] shrink-0">
                        {link.technique_id}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium">{link.technique_name}</span>
                        <span className="text-xs text-muted-foreground ml-2">
                          {link.tactic_label}
                        </span>
                      </div>
                      <Badge variant="secondary" className="text-[9px] shrink-0">
                        {link.mapping_type}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        {link.confidence}% conf
                      </Badge>
                      {link.url && (
                        <a
                          href={link.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-primary"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline" className="mt-4">
          <Card>
            <CardContent className="py-8">
              <div className="relative border-l-2 border-muted pl-6 space-y-6 ml-4">
                {item.published_at && (
                  <TimelineEvent
                    date={item.published_at}
                    title="Published"
                    description={`Published by ${item.source_name}`}
                  />
                )}
                <TimelineEvent
                  date={item.ingested_at}
                  title="Ingested"
                  description="First seen by TI Platform"
                />
                {item.ai_summary_at && (
                  <TimelineEvent
                    date={item.ai_summary_at}
                    title="AI Summary Generated"
                    description="Analyzed by AI model"
                  />
                )}
                <TimelineEvent
                  date={item.updated_at}
                  title="Last Updated"
                  description="Most recent update"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="related" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" /> Related Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent>
              {relatedLoading ? (
                <div className="text-center py-4 text-sm text-muted-foreground">Loading…</div>
              ) : relatedItems.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No related intelligence found yet.</p>
                  <p className="text-xs mt-1">
                    Relationships are built automatically based on shared IOCs, CVEs and ATT&CK techniques.
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {relatedItems.map((rel) => (
                    <a
                      key={rel.id}
                      href={`/intel/${rel.id}`}
                      className="flex items-center gap-3 rounded-md border border-border/30 px-3 py-2 hover:bg-muted/20 transition-colors"
                    >
                      <Badge variant={rel.severity as any} className="text-[10px] shrink-0">
                        {rel.severity.toUpperCase()}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium truncate block">{rel.title}</span>
                        <span className="text-xs text-muted-foreground">
                          {rel.source_name} · {rel.feed_type}
                        </span>
                      </div>
                      <Badge variant="secondary" className="text-[9px] shrink-0">
                        {rel.relationship_type.replace(/_/g, " ")}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] shrink-0">
                        {rel.confidence}% conf
                      </Badge>
                      <span className="text-xs text-muted-foreground font-medium shrink-0">
                        {rel.risk_score}
                      </span>
                    </a>
                  ))}
                  <div className="pt-2 text-center">
                    <a
                      href={`/investigate?id=${id}&type=intel`}
                      className="text-xs text-primary hover:underline"
                    >
                      View full relationship graph →
                    </a>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Row({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground flex items-center gap-1">
        <Icon className="h-3 w-3" /> {label}
      </span>
      <span className="font-medium text-right">{value}</span>
    </div>
  );
}

function TimelineEvent({
  date,
  title,
  description,
}: {
  date: string;
  title: string;
  description: string;
}) {
  return (
    <div className="relative">
      <div className="absolute -left-[29px] top-1 h-3 w-3 rounded-full border-2 border-primary bg-background" />
      <div>
        <p className="text-sm font-medium">{title}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{formatDate(date)}</p>
      </div>
    </div>
  );
}
