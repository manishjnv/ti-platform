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
}: {
  icon: React.ElementType;
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("card-3d", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
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
  if (!items.length) return <p className="text-xs text-muted-foreground/50 italic">None identified</p>;
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

// ── Main Detail Page ─────────────────────────────────────
export default function NewsDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [item, setItem] = useState<NewsItem | null>(null);
  const [loading, setLoading] = useState(true);

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

  const hasIOCs =
    (item.ioc_summary?.domains?.length || 0) +
      (item.ioc_summary?.ips?.length || 0) +
      (item.ioc_summary?.hashes?.length || 0) +
      (item.ioc_summary?.urls?.length || 0) >
    0;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
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
                      <Sparkles className="h-3 w-3" />
                      AI Enriched
                    </span>
                  </>
                )}
              </div>
              {/* Badges row */}
              <div className="flex items-center gap-2 mt-3 flex-wrap">
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", meta.border, meta.color)}>
                  {meta.label}
                </Badge>
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", relevanceColor(item.relevance_score))}>
                  Relevance: {item.relevance_score}
                </Badge>
                <Badge variant="outline" className={cn("text-[10px] h-5 px-2 border", confidenceColor(item.confidence))}>
                  {item.confidence} confidence
                </Badge>
                <a
                  href={item.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-primary flex items-center gap-1 hover:underline ml-auto"
                >
                  Source <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── Summary ────────────────────────────────────── */}
      {item.summary && (
        <Card className="card-3d">
          <CardContent className="pt-4 pb-3">
            <p className="text-sm leading-relaxed text-muted-foreground">{item.summary}</p>
          </CardContent>
        </Card>
      )}

      {/* ── Why It Matters ─────────────────────────────── */}
      {item.why_it_matters.length > 0 && (
        <Section icon={Lightbulb} title="Why It Matters">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {item.why_it_matters.map((point, i) => (
              <div key={i} className="rounded-lg border border-border/50 bg-card/30 p-3">
                <p className="text-xs leading-relaxed text-muted-foreground">{point}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Two-column grid ────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Threat Actors */}
        <Section icon={Users} title="Threat Actors">
          <TagList items={item.threat_actors} color="border-purple-500/30 text-purple-400" />
        </Section>

        {/* Malware Families */}
        <Section icon={Bug} title="Malware Families">
          <TagList items={item.malware_families} color="border-red-500/30 text-red-400" />
        </Section>

        {/* CVEs */}
        <Section icon={ShieldCheck} title="CVEs">
          <TagList
            items={item.cves}
            color="border-orange-500/30 text-orange-400"
            href={(cve) => `/search?q=${encodeURIComponent(cve)}`}
          />
        </Section>

        {/* Vulnerable Products */}
        <Section icon={Target} title="Vulnerable Products">
          <TagList items={item.vulnerable_products} color="border-amber-500/30 text-amber-400" />
        </Section>

        {/* MITRE ATT&CK */}
        <Section icon={Crosshair} title="MITRE ATT&CK Techniques">
          <TagList
            items={item.tactics_techniques}
            color="border-blue-500/30 text-blue-400"
            href={(t) => `/techniques?search=${encodeURIComponent(t)}`}
          />
          {item.initial_access_vector && (
            <p className="text-[11px] text-muted-foreground mt-2">
              <span className="font-medium">Initial Access:</span> {item.initial_access_vector}
            </p>
          )}
        </Section>

        {/* Targeted Sectors & Regions */}
        <Section icon={Globe} title="Targeting">
          <div className="space-y-2">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">Sectors</p>
              <TagList items={item.targeted_sectors} />
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">Regions</p>
              <TagList items={item.targeted_regions} />
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1">Impacted Assets</p>
              <TagList items={item.impacted_assets} />
            </div>
          </div>
        </Section>
      </div>

      {/* ── Post-Exploitation ──────────────────────────── */}
      {item.post_exploitation.length > 0 && (
        <Section icon={Zap} title="Post-Exploitation Activity">
          <ul className="space-y-1">
            {item.post_exploitation.map((pe, i) => (
              <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                <ChevronRight className="h-3 w-3 text-muted-foreground/40 shrink-0 mt-0.5" />
                {pe}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* ── IOC Summary ────────────────────────────────── */}
      {hasIOCs && (
        <Section icon={Eye} title="IOC Summary">
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
        <Section icon={Calendar} title="Timeline">
          <div className="relative pl-4 space-y-3">
            <div className="absolute left-[7px] top-1 bottom-1 w-px bg-border/50" />
            {item.timeline.map((ev, i) => (
              <div key={i} className="relative flex items-start gap-3">
                <div className="absolute left-[-12px] top-1 h-2.5 w-2.5 rounded-full border-2 border-primary bg-background" />
                <div>
                  {ev.date && (
                    <p className="text-[10px] font-medium text-muted-foreground/70">{ev.date}</p>
                  )}
                  <p className="text-xs text-muted-foreground">{ev.event}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Detection & Mitigation (side by side) ──────── */}
      {(item.detection_opportunities.length > 0 || item.mitigation_recommendations.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {item.detection_opportunities.length > 0 && (
            <Section icon={Eye} title="Detection Opportunities">
              <ul className="space-y-1.5">
                {item.detection_opportunities.map((det, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <Crosshair className="h-3 w-3 text-blue-400 shrink-0 mt-0.5" />
                    {det}
                  </li>
                ))}
              </ul>
            </Section>
          )}
          {item.mitigation_recommendations.length > 0 && (
            <Section icon={CheckCircle2} title="Mitigation Recommendations">
              <ul className="space-y-1.5">
                {item.mitigation_recommendations.map((mit, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <CheckCircle2 className="h-3 w-3 text-green-400 shrink-0 mt-0.5" />
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
        <Section icon={Tag} title="Tags">
          <TagList
            items={item.tags}
            href={(tag) => `/news?tag=${encodeURIComponent(tag)}`}
          />
        </Section>
      )}
    </div>
  );
}
