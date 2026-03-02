"use client";

import React, { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import {
  ArrowLeft,
  ExternalLink,
  Clock,
  Sparkles,
  Shield,
  AlertTriangle,
  Bug,
  Globe,
  Cloud,
  Factory,
  FlaskConical,
  Wrench,
  Scale,
  Tag,
  Crosshair,
  Users,
  Calendar,
  ChevronRight,
  Eye,
  ShieldCheck,
  Target,
  Zap,
  Lightbulb,
  CheckCircle2,
  FileText,
  Download,
  BookOpen,
  TriangleAlert,
  Swords,
  Layers,
  Radio,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import * as api from "@/lib/api";
import type { NewsItem, NewsCategory } from "@/types";

const CATEGORY_META: Record<
  NewsCategory,
  { label: string; icon: React.ElementType; color: string; bg: string; border: string }
> = {
  active_threats: { label: "Active Threats", icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  exploited_vulnerabilities: { label: "Exploited Vulnerabilities", icon: Bug, color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  ransomware_breaches: { label: "Ransomware & Breaches", icon: Shield, color: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/30" },
  nation_state: { label: "Nation-State Activity", icon: Globe, color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30" },
  cloud_identity: { label: "Cloud & Identity", icon: Cloud, color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/30" },
  ot_ics: { label: "OT / ICS", icon: Factory, color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30" },
  security_research: { label: "Security Research", icon: FlaskConical, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  tools_technology: { label: "Tools & Technology", icon: Wrench, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30" },
  policy_regulation: { label: "Policy & Regulation", icon: Scale, color: "text-teal-400", bg: "bg-teal-500/10", border: "border-teal-500/30" },
};

const PRIORITY_META: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" },
  high: { label: "HIGH", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  medium: { label: "MEDIUM", color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30" },
  low: { label: "LOW", color: "text-green-400", bg: "bg-green-500/10 border-green-500/30" },
};

function formatDate(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function relevanceColor(score: number) {
  if (score >= 80) return "text-red-400 border-red-500/30 bg-red-500/10";
  if (score >= 60) return "text-orange-400 border-orange-500/30 bg-orange-500/10";
  if (score >= 40) return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
  return "text-green-400 border-green-500/30 bg-green-500/10";
}

function confidenceColor(conf: string) {
  if (conf === "high") return "text-green-400 border-green-500/30";
  if (conf === "medium") return "text-yellow-400 border-yellow-500/30";
  return "text-red-400 border-red-500/30";
}

// ── Section component ────────────────────────────────────
function Section({
  icon: Icon,
  title,
  children,
  className,
  accent,
}: {
  icon: React.ElementType;
  title: string;
  children: React.ReactNode;
  className?: string;
  accent?: string;
}) {
  return (
    <Card className={cn("card-3d", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Icon className={cn("h-4 w-4", accent || "text-muted-foreground")} />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

// ── Tag list helper ──────────────────────────────────────
function TagList({
  items,
  color = "border-border/50 text-muted-foreground",
  href,
}: {
  items: string[];
  color?: string;
  href?: (item: string) => string;
}) {
  if (!items.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) =>
        href ? (
          <Link key={item} href={href(item)}>
            <Badge variant="outline" className={cn("text-[10px] h-5 px-1.5 cursor-pointer hover:bg-accent/30", color)}>
              {item}
            </Badge>
          </Link>
        ) : (
          <Badge key={item} variant="outline" className={cn("text-[10px] h-5 px-1.5", color)}>
            {item}
          </Badge>
        )
      )}
    </div>
  );
}

// ── Prose paragraph ──────────────────────────────────────
function Prose({ text, className }: { text: string; className?: string }) {
  return <p className={cn("text-sm leading-relaxed text-muted-foreground", className)}>{text}</p>;
}

// ── Main Detail Page ─────────────────────────────────────
export default function NewsDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [item, setItem] = useState<NewsItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);

  useEffect(() => {
    const id = params.id as string;
    if (!id) return;
    setLoading(true);
    api
      .getNewsItem(id)
      .then(setItem)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [params.id]);

  const handleDownloadReport = async () => {
    if (!item) return;
    setReportLoading(true);
    try {
      await api.downloadNewsReport(item.id);
    } catch {
      // silently fail
    } finally {
      setReportLoading(false);
    }
  };

  if (loading) return <Loading />;
  if (!item) {
    return (
      <div className="text-center py-20">
        <p className="text-muted-foreground">News item not found.</p>
        <Link href="/news" className="text-primary text-sm hover:underline mt-2 inline-block">
          ← Back to Cyber News
        </Link>
      </div>
    );
  }

  const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
  const CatIcon = meta.icon;
  const priority = PRIORITY_META[item.recommended_priority] || PRIORITY_META.medium;

  const hasIOCs =
    (item.ioc_summary?.domains?.length || 0) +
      (item.ioc_summary?.ips?.length || 0) +
      (item.ioc_summary?.hashes?.length || 0) +
      (item.ioc_summary?.urls?.length || 0) >
    0;

  const hasThreatLandscape =
    item.threat_actors.length > 0 ||
    item.malware_families.length > 0 ||
    item.cves.length > 0 ||
    item.vulnerable_products.length > 0;

  const hasTargeting =
    item.targeted_sectors.length > 0 ||
    item.targeted_regions.length > 0 ||
    item.impacted_assets.length > 0;

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      {/* Back link */}
      <button
        onClick={() => router.back()}
        className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to Cyber News
      </button>

      {/* ── Headline Strip ─────────────────────────────── */}
      <Card className={cn("card-3d border-l-4", meta.border)}>
        <CardContent className="pt-5 pb-4">
          <div className="flex items-start gap-3">
            <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center shrink-0", meta.bg)}>
              <CatIcon className={cn("h-5 w-5", meta.color)} />
            </div>
            <div className="flex-1 min-w-0">
              <h1 className="text-lg font-bold leading-snug">{item.headline}</h1>
              <div className="flex items-center gap-3 mt-2 flex-wrap text-[11px] text-muted-foreground">
                <span className="font-medium">{item.source}</span>
                <span className="text-muted-foreground/40">•</span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDate(item.published_at)}
                  <span className="text-muted-foreground/50">({timeAgo(item.published_at)})</span>
                </span>
                {item.ai_enriched && (
                  <>
                    <span className="text-muted-foreground/40">•</span>
                    <span className="flex items-center gap-1 text-yellow-400">
                      <Sparkles className="h-3 w-3" /> AI Enriched
                    </span>
                  </>
                )}
              </div>
              {/* Badges + Actions row */}
              <div className="flex items-center gap-2 mt-3 flex-wrap">
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", meta.border, meta.color)}>
                  {meta.label}
                </Badge>
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border font-semibold", priority.bg, priority.color)}>
                  {priority.label}
                </Badge>
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", relevanceColor(item.relevance_score))}>
                  Relevance: {item.relevance_score}
                </Badge>
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", confidenceColor(item.confidence))}>
                  {item.confidence} confidence
                </Badge>

                <div className="flex items-center gap-2 ml-auto">
                  <button
                    onClick={handleDownloadReport}
                    disabled={reportLoading}
                    className="flex items-center gap-1.5 text-[10px] font-medium px-3 py-1.5 rounded-md border border-primary/30 bg-primary/5 text-primary hover:bg-primary/10 transition-colors disabled:opacity-50"
                  >
                    {reportLoading ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Download className="h-3 w-3" />
                    )}
                    Generate Report
                  </button>
                  <a
                    href={item.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-[10px] font-medium px-3 py-1.5 rounded-md border border-border/50 text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
                  >
                    Source <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── Executive Summary ──────────────────────────── */}
      {item.summary && (
        <Card className="card-3d">
          <CardHeader className="pb-1">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-400" /> Executive Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Prose text={item.summary} />
          </CardContent>
        </Card>
      )}

      {/* ── Intelligence Brief ─────────────────────────── */}
      {item.executive_brief && (
        <Section icon={BookOpen} title="Intelligence Brief" accent="text-indigo-400">
          <Prose text={item.executive_brief} />
        </Section>
      )}

      {/* ── Key Insights row: Risk Assessment + Attack Narrative ── */}
      {(item.risk_assessment || item.attack_narrative) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {item.risk_assessment && (
            <Section icon={TriangleAlert} title="Risk Assessment" accent="text-red-400">
              <Prose text={item.risk_assessment} />
            </Section>
          )}
          {item.attack_narrative && (
            <Section icon={Swords} title="Attack Narrative" accent="text-orange-400">
              <Prose text={item.attack_narrative} />
            </Section>
          )}
        </div>
      )}

      {/* ── Why It Matters ─────────────────────────────── */}
      {item.why_it_matters.length > 0 && (
        <Section icon={Lightbulb} title="Key Takeaways" accent="text-yellow-400">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {item.why_it_matters.map((point, i) => (
              <div key={i} className="rounded-lg border border-yellow-500/10 bg-yellow-500/5 p-3">
                <div className="flex items-start gap-2">
                  <span className="text-[10px] font-bold text-yellow-400 bg-yellow-500/10 rounded px-1.5 py-0.5 shrink-0">{i + 1}</span>
                  <p className="text-xs leading-relaxed text-muted-foreground">{point}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Threat Landscape (combined card) ───────────── */}
      {hasThreatLandscape && (
        <Section icon={Users} title="Threat Landscape" accent="text-purple-400">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {item.threat_actors.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Users className="h-3 w-3" /> Threat Actors
                </p>
                <TagList items={item.threat_actors} color="border-purple-500/30 text-purple-400" />
              </div>
            )}
            {item.malware_families.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Bug className="h-3 w-3" /> Malware / Tools
                </p>
                <TagList items={item.malware_families} color="border-red-500/30 text-red-400" />
              </div>
            )}
            {item.cves.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <ShieldCheck className="h-3 w-3" /> CVEs
                </p>
                <TagList
                  items={item.cves}
                  color="border-orange-500/30 text-orange-400"
                  href={(cve) => `/search?q=${encodeURIComponent(cve)}`}
                />
              </div>
            )}
            {item.vulnerable_products.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Target className="h-3 w-3" /> Affected Products
                </p>
                <TagList items={item.vulnerable_products} color="border-amber-500/30 text-amber-400" />
              </div>
            )}
          </div>
          {item.campaign_name && (
            <div className="mt-3 pt-3 border-t border-border/30">
              <p className="text-xs text-muted-foreground">
                <span className="font-medium text-foreground/80">Campaign:</span> {item.campaign_name}
              </p>
            </div>
          )}
        </Section>
      )}

      {/* ── MITRE ATT&CK + Post-Exploitation ───────────── */}
      {(item.tactics_techniques.length > 0 || item.post_exploitation.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {item.tactics_techniques.length > 0 && (
            <Section icon={Crosshair} title="MITRE ATT&CK" accent="text-blue-400">
              <div className="space-y-1.5">
                {item.tactics_techniques.map((t, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-blue-400 shrink-0" />
                    {t.match(/^T\d/) ? (
                      <Link
                        href={`/techniques?search=${encodeURIComponent(t.split(" - ")[0] || t)}`}
                        className="text-xs text-blue-400 hover:underline"
                      >
                        {t}
                      </Link>
                    ) : (
                      <span className="text-xs text-muted-foreground">{t}</span>
                    )}
                  </div>
                ))}
              </div>
              {item.initial_access_vector && (
                <div className="mt-3 pt-2 border-t border-border/30">
                  <p className="text-[11px] text-muted-foreground">
                    <span className="font-medium text-foreground/80">Initial Access:</span> {item.initial_access_vector}
                  </p>
                </div>
              )}
            </Section>
          )}
          {item.post_exploitation.length > 0 && (
            <Section icon={Zap} title="Post-Exploitation" accent="text-orange-400">
              <ul className="space-y-1.5">
                {item.post_exploitation.map((pe, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <ChevronRight className="h-3 w-3 text-orange-400/60 shrink-0 mt-0.5" />
                    {pe}
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* ── Targeting ──────────────────────────────────── */}
      {hasTargeting && (
        <Section icon={Globe} title="Targeting" accent="text-emerald-400">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {item.targeted_sectors.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Layers className="h-3 w-3" /> Sectors
                </p>
                <TagList items={item.targeted_sectors} color="border-emerald-500/30 text-emerald-400" />
              </div>
            )}
            {item.targeted_regions.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Globe className="h-3 w-3" /> Regions
                </p>
                <TagList items={item.targeted_regions} color="border-sky-500/30 text-sky-400" />
              </div>
            )}
            {item.impacted_assets.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
                  <Target className="h-3 w-3" /> Impacted Assets
                </p>
                <TagList items={item.impacted_assets} color="border-amber-500/30 text-amber-400" />
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── IOC Summary ────────────────────────────────── */}
      {hasIOCs && (
        <Section icon={Eye} title="Indicators of Compromise" accent="text-red-400">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {item.ioc_summary?.domains && item.ioc_summary.domains.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">Domains</p>
                <TagList items={item.ioc_summary.domains} color="border-blue-500/30 text-blue-400" />
              </div>
            )}
            {item.ioc_summary?.ips && item.ioc_summary.ips.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">IPs</p>
                <TagList
                  items={item.ioc_summary.ips}
                  color="border-sky-500/30 text-sky-400"
                  href={(ip) => `/search?q=${encodeURIComponent(ip)}`}
                />
              </div>
            )}
            {item.ioc_summary?.hashes && item.ioc_summary.hashes.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">Hashes</p>
                <div className="space-y-0.5">
                  {item.ioc_summary.hashes.map((h) => (
                    <p key={h} className="text-[10px] font-mono text-muted-foreground break-all">{h}</p>
                  ))}
                </div>
              </div>
            )}
            {item.ioc_summary?.urls && item.ioc_summary.urls.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">URLs</p>
                <div className="space-y-0.5">
                  {item.ioc_summary.urls.map((u) => (
                    <p key={u} className="text-[10px] font-mono text-muted-foreground break-all">{u}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── Timeline ───────────────────────────────────── */}
      {item.timeline.length > 0 && (
        <Section icon={Calendar} title="Timeline" accent="text-indigo-400">
          <div className="relative pl-4 space-y-3">
            <div className="absolute left-[7px] top-1 bottom-1 w-px bg-indigo-500/20" />
            {item.timeline.map((ev, i) => (
              <div key={i} className="relative flex items-start gap-3">
                <div className="absolute left-[-12px] top-1 h-2.5 w-2.5 rounded-full border-2 border-indigo-400 bg-background" />
                <div>
                  {ev.date && (
                    <p className="text-[10px] font-medium text-indigo-400">{ev.date}</p>
                  )}
                  <p className="text-xs text-muted-foreground">{ev.event}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Detection & Mitigation (always side-by-side) ── */}
      {(item.detection_opportunities.length > 0 || item.mitigation_recommendations.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {item.detection_opportunities.length > 0 && (
            <Section icon={Radio} title="Detection Opportunities" accent="text-blue-400">
              <ul className="space-y-2">
                {item.detection_opportunities.map((det, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <div className="flex items-center justify-center h-4 w-4 rounded-full bg-blue-500/10 shrink-0 mt-0.5">
                      <Eye className="h-2.5 w-2.5 text-blue-400" />
                    </div>
                    {det}
                  </li>
                ))}
              </ul>
            </Section>
          )}
          {item.mitigation_recommendations.length > 0 && (
            <Section icon={CheckCircle2} title="Mitigation Recommendations" accent="text-green-400">
              <ul className="space-y-2">
                {item.mitigation_recommendations.map((mit, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <div className="flex items-center justify-center h-4 w-4 rounded-full bg-green-500/10 shrink-0 mt-0.5">
                      <CheckCircle2 className="h-2.5 w-2.5 text-green-400" />
                    </div>
                    {mit}
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* ── Tags ───────────────────────────────────────── */}
      {item.tags.length > 0 && (
        <Card className="card-3d">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <Tag className="h-3.5 w-3.5 text-muted-foreground/50" />
              <TagList
                items={item.tags}
                href={(tag) => `/news?tag=${encodeURIComponent(tag)}`}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Not enriched notice ────────────────────────── */}
      {!item.ai_enriched && (
        <Card className="card-3d border border-yellow-500/20">
          <CardContent className="pt-4 pb-3 flex items-center gap-3">
            <Sparkles className="h-5 w-5 text-yellow-400" />
            <div>
              <p className="text-sm font-medium text-yellow-400">AI Enrichment Pending</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                This article is queued for AI analysis. Structured intelligence sections will appear once enrichment completes.
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
