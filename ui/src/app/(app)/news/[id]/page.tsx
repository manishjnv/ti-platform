"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import IOCSearchPopup from "@/components/IOCSearchPopup";
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
  Newspaper,
  Tag,
  Crosshair,
  Users,
  Calendar,
  ChevronRight,
  ChevronDown,
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
  FileDown,
  FileCode,
  FileType2,
  Copy,
  Check,
  Link2,
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
  general_news: { label: "General News", icon: Newspaper, color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30" },
  geopolitical_cyber: { label: "Geopolitical Cyber", icon: Globe, color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/30" },
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

// ── Keyword highlighting (clickable → IOC search) ────────
const HIGHLIGHT_RULES: { pattern: RegExp; style: string; searchable: boolean }[] = [
  // AI-bolded key intelligence terms (**term**) — highest priority
  { pattern: /\*\*([^*]{2,60})\*\*/g, style: "font-semibold text-cyan-300 bg-cyan-500/10 px-0.5 rounded", searchable: false },
  // CVE IDs
  { pattern: /\bCVE-\d{4}-\d{4,}\b/g, style: "font-semibold text-orange-400 bg-orange-500/10 px-1 rounded cursor-pointer hover:bg-orange-500/20 transition-colors", searchable: true },
  // MITRE ATT&CK IDs
  { pattern: /\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b/g, style: "font-semibold text-blue-400 bg-blue-500/10 px-1 rounded cursor-pointer hover:bg-blue-500/20 transition-colors", searchable: true },
  // IP addresses
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, style: "font-mono text-sky-400 bg-sky-500/10 px-1 rounded text-[11px] cursor-pointer hover:bg-sky-500/20 transition-colors", searchable: true },
  // SHA-256 / SHA-1 / MD5 hashes
  { pattern: /\b[a-f0-9]{64}\b/gi, style: "font-mono text-purple-400 bg-purple-500/10 px-1 rounded text-[10px] cursor-pointer hover:bg-purple-500/20 transition-colors", searchable: true },
  { pattern: /\b[a-f0-9]{40}\b/gi, style: "font-mono text-purple-400 bg-purple-500/10 px-1 rounded text-[10px] cursor-pointer hover:bg-purple-500/20 transition-colors", searchable: true },
  { pattern: /\b[a-f0-9]{32}\b/gi, style: "font-mono text-purple-400 bg-purple-500/10 px-1 rounded text-[10px] cursor-pointer hover:bg-purple-500/20 transition-colors", searchable: true },
  // Data quantities (170GB, 2.3 million records, $4.5M, etc.)
  { pattern: /\b\d+(?:\.\d+)?\s*(?:GB|TB|MB|PB|KB|million|billion|thousand)\b/gi, style: "font-semibold text-red-400 bg-red-500/10 px-0.5 rounded", searchable: false },
  { pattern: /\$\d+(?:\.\d+)?\s*(?:M|B|K|million|billion)?\b/gi, style: "font-semibold text-red-400 bg-red-500/10 px-0.5 rounded", searchable: false },
  // Threat actor names (APT groups, known actors)
  { pattern: /\b(APT\d+|UNC\d+|UAT-\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|Turla|Sandworm|Kimsuky|ScarCruft|Volt Typhoon|Storm-\d+|Midnight Blizzard|Scattered Spider)\b/gi, style: "font-semibold text-purple-400 bg-purple-500/10 px-1 rounded cursor-pointer hover:bg-purple-500/20 transition-colors", searchable: true },
  // Version numbers (e.g., v2.1.3, 10.0.1)
  { pattern: /\bv?\d+\.\d+(?:\.\d+)+\b/g, style: "font-mono text-teal-400 bg-teal-500/10 px-1 rounded text-[11px]", searchable: false },
  // File paths (Unix/Windows)
  { pattern: /(?:\/[\w.-]+){2,}|[A-Z]:\\(?:[\w.-]+\\)+[\w.-]+/g, style: "font-mono text-amber-300 bg-amber-500/10 px-1 rounded text-[11px] cursor-pointer hover:bg-amber-500/20 transition-colors", searchable: true },
  // Dates (YYYY-MM-DD)
  { pattern: /\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g, style: "text-indigo-400 font-medium", searchable: false },
  // CVSS scores (e.g., 9.8/10, CVSS 7.5)
  { pattern: /\b(?:CVSS[:\s]*)?\d{1,2}\.\d\/10\b/gi, style: "font-semibold text-red-400 bg-red-500/10 px-1 rounded", searchable: false },
  // Action verbs — green highlight
  { pattern: /\b(patch|update|upgrade|block|disable|revoke|rotate|deploy|scan|isolate|remediate|mitigat(?:e|ion)|harden|restrict|enforce|audit|verify|review|monitor|detect|enable|contained|restored|recovered|neutralized)\b/gi, style: "font-medium text-green-400", searchable: false },
  // Threat/severity terms — amber/red for urgency
  { pattern: /\b(zero[- ]day|critical|exploit(?:ed|ation|s)?|ransom(?:ware)?|malware|backdoor|RCE|remote code execution|privilege escalation|data (?:breach|exfiltration|leak|wiper)|supply[- ]chain|APT|brute[- ]force|phishing|trojan|rootkit|C2|command[- ]and[- ]control|lateral movement|data wiper|credential[- ]stuffing|wiper)\b/gi, style: "font-medium text-amber-400", searchable: false },
  // Quoted terms (product names, etc.)
  { pattern: /"([^"]{2,40})"/g, style: "font-medium text-foreground/90 cursor-pointer hover:text-primary transition-colors", searchable: true },
];

function highlightText(
  text: string,
  onKeywordClick?: (kw: string) => void,
): React.ReactNode[] {
  const allMatches: { start: number; end: number; text: string; displayText: string; style: string; searchable: boolean }[] = [];
  for (const rule of HIGHLIGHT_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      // For **bold** markers: use capture group as display text (strip asterisks)
      const isBoldMarker = m[0].startsWith("**") && m[0].endsWith("**");
      const displayText = isBoldMarker && m[1] ? m[1] : m[0];
      allMatches.push({ start: m.index, end: m.index + m[0].length, text: m[0], displayText, style: rule.style, searchable: rule.searchable });
    }
  }
  allMatches.sort((a, b) => a.start - b.start);
  // Deduplicate: limit same keyword to max 2 highlights
  const kwCount = new Map<string, number>();
  const filtered: typeof allMatches = [];
  let lastEnd = 0;
  for (const m of allMatches) {
    if (m.start >= lastEnd) {
      const key = m.text.toLowerCase();
      const count = kwCount.get(key) || 0;
      if (count < 2) {
        filtered.push(m);
        kwCount.set(key, count + 1);
      }
      lastEnd = m.end;
    }
  }
  const nodes: React.ReactNode[] = [];
  let cursor = 0;
  for (let i = 0; i < filtered.length; i++) {
    const m = filtered[i];
    if (cursor < m.start) nodes.push(text.slice(cursor, m.start));
    if (m.searchable && onKeywordClick) {
      // Strip surrounding quotes for search
      const searchTerm = m.displayText.replace(/^"|"$/g, "");
      nodes.push(
        <button
          key={`h-${i}`}
          type="button"
          onClick={(e) => { e.stopPropagation(); onKeywordClick(searchTerm); }}
          className={cn(m.style, "inline")}
          title={`Search IOC: ${searchTerm}`}
        >
          {m.displayText}
        </button>,
      );
    } else {
      nodes.push(<span key={`h-${i}`} className={m.style}>{m.displayText}</span>);
    }
    cursor = m.end;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes.length > 0 ? nodes : [text];
}

// ── Prose paragraph with keyword highlighting ────────────
function Prose({ text, className, onKeywordClick }: { text: string; className?: string; onKeywordClick?: (kw: string) => void }) {
  return <p className={cn("text-sm leading-relaxed text-muted-foreground", className)}>{highlightText(text, onKeywordClick)}</p>;
}

// ── Actionable bullet with pointer + highlight ───────────
function ActionBullet({
  text,
  icon: Icon,
  accent = "text-muted-foreground",
  accentBg = "bg-muted/50",
  onKeywordClick,
}: {
  text: string;
  icon: React.ElementType;
  accent?: string;
  accentBg?: string;
  onKeywordClick?: (kw: string) => void;
}) {
  return (
    <li className="text-xs leading-relaxed text-muted-foreground flex items-start gap-2.5 group">
      <div className={cn("flex items-center justify-center h-5 w-5 rounded-md shrink-0 mt-0.5 transition-colors", accentBg, "group-hover:scale-110")}>
        <Icon className={cn("h-3 w-3", accent)} />
      </div>
      <span>{highlightText(text, onKeywordClick)}</span>
    </li>
  );
}

// ── Report Format Dropdown ───────────────────────────────
function ReportDropdown({
  onDownload,
  loading,
}: {
  onDownload: (format: "pdf" | "html" | "markdown") => void;
  loading: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const formats = [
    { key: "pdf" as const, label: "PDF Report", icon: FileDown, desc: "Professional styled PDF" },
    { key: "html" as const, label: "HTML Report", icon: FileCode, desc: "Self-contained HTML file" },
    { key: "markdown" as const, label: "Markdown", icon: FileType2, desc: "Plain text markdown" },
  ];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        disabled={loading}
        className="flex items-center gap-1.5 text-[10px] font-medium px-3 py-1.5 rounded-md border border-primary/30 bg-primary/5 text-primary hover:bg-primary/10 transition-colors disabled:opacity-50"
      >
        {loading ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <Download className="h-3 w-3" />
        )}
        Report
        <ChevronDown className={cn("h-3 w-3 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-52 bg-[#0c0c14] border border-border/50 rounded-lg shadow-xl z-40 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
          {formats.map((f) => (
            <button
              key={f.key}
              onClick={() => { setOpen(false); onDownload(f.key); }}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-accent/10 transition-colors"
            >
              <f.icon className="h-3.5 w-3.5 text-primary/60 shrink-0" />
              <div>
                <p className="text-[11px] font-medium text-foreground/90">{f.label}</p>
                <p className="text-[9px] text-muted-foreground/60">{f.desc}</p>
              </div>
            </button>
          ))}
        </div>
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
  const [reportLoading, setReportLoading] = useState(false);
  const [iocKeyword, setIocKeyword] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const handleKeywordClick = useCallback((kw: string) => {
    setIocKeyword(kw);
  }, []);

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

  const handleDownloadReport = async (format: "pdf" | "html" | "markdown" = "pdf") => {
    if (!item) return;
    setReportLoading(true);
    try {
      await api.downloadNewsReport(item.id, format);
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
    <div className="space-y-5 px-4 md:px-6 lg:px-8 pb-6">
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

                {/* Key intel keyword tags */}
                {item.cves?.slice(0, 3).map((cve) => (
                  <Badge key={cve} variant="outline" className="text-[10px] h-5 px-2 border border-orange-500/30 text-orange-400 bg-orange-500/5 font-mono">
                    {cve}
                  </Badge>
                ))}
                {item.threat_actors?.slice(0, 2).map((actor) => (
                  <Badge key={actor} variant="outline" className="text-[10px] h-5 px-2 border border-purple-500/30 text-purple-400 bg-purple-500/5">
                    {actor}
                  </Badge>
                ))}
                {item.malware_families?.slice(0, 2).map((mw) => (
                  <Badge key={mw} variant="outline" className="text-[10px] h-5 px-2 border border-rose-500/30 text-rose-400 bg-rose-500/5">
                    {mw}
                  </Badge>
                ))}
                {item.vulnerable_products?.slice(0, 2).map((vp) => (
                  <Badge key={vp} variant="outline" className="text-[10px] h-5 px-2 border border-cyan-500/30 text-cyan-400 bg-cyan-500/5 font-mono">
                    {vp}
                  </Badge>
                ))}
                {item.initial_access_vector && (
                  <Badge variant="outline" className="text-[10px] h-5 px-2 border border-amber-500/30 text-amber-400 bg-amber-500/5">
                    {item.initial_access_vector}
                  </Badge>
                )}

                <div className="flex items-center gap-2 ml-auto">
                  <ReportDropdown onDownload={handleDownloadReport} loading={reportLoading} />
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
            <Prose text={item.summary} onKeywordClick={handleKeywordClick} />
          </CardContent>
        </Card>
      )}

      {/* ── Intelligence Brief ─────────────────────────── */}
      {item.executive_brief && (
        <Section icon={BookOpen} title="Intelligence Brief" accent="text-indigo-400">
          <Prose text={item.executive_brief} onKeywordClick={handleKeywordClick} />
        </Section>
      )}

      {/* ── Key Insights row: Risk Assessment + Attack Narrative ── */}
      {(item.risk_assessment || item.attack_narrative) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {item.risk_assessment && (
            <Section icon={TriangleAlert} title="Risk Assessment" accent="text-red-400">
              <Prose text={item.risk_assessment} onKeywordClick={handleKeywordClick} />
            </Section>
          )}
          {item.attack_narrative && (
            <Section icon={Swords} title="Attack Narrative" accent="text-orange-400">
              <Prose text={item.attack_narrative} onKeywordClick={handleKeywordClick} />
            </Section>
          )}
        </div>
      )}

      {/* ── Why It Matters ─────────────────────────────── */}
      {item.why_it_matters.length > 0 && (
        <Section icon={Lightbulb} title="Key Takeaways" accent="text-yellow-400">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
            {item.why_it_matters.map((point, i) => (
              <div key={i} className="rounded-lg border border-yellow-500/10 bg-yellow-500/5 p-3 hover:border-yellow-500/30 transition-colors">
                <div className="flex items-start gap-2">
                  <span className="text-[10px] font-bold text-yellow-400 bg-yellow-500/10 rounded px-1.5 py-0.5 shrink-0">{i + 1}</span>
                  <p className="text-xs leading-relaxed text-muted-foreground">{highlightText(point, handleKeywordClick)}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Threat Landscape (combined card) ───────────── */}
      {hasThreatLandscape && (
        <Section icon={Users} title="Threat Landscape" accent="text-purple-400">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
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
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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
              <ul className="space-y-2">
                {item.post_exploitation.map((pe, i) => (
                  <ActionBullet key={i} text={pe} icon={ChevronRight} accent="text-orange-400/80" accentBg="bg-orange-500/10" onKeywordClick={handleKeywordClick} />
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* ── Targeting ──────────────────────────────────── */}
      {hasTargeting && (
        <Section icon={Globe} title="Targeting" accent="text-emerald-400">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
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
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
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
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {item.detection_opportunities.length > 0 && (
            <Section icon={Radio} title="Detection Opportunities" accent="text-blue-400">
              <ul className="space-y-2.5">
                {item.detection_opportunities.map((det, i) => (
                  <ActionBullet key={i} text={det} icon={Eye} accent="text-blue-400" accentBg="bg-blue-500/10" onKeywordClick={handleKeywordClick} />
                ))}
              </ul>
            </Section>
          )}
          {item.mitigation_recommendations.length > 0 && (
            <Section icon={CheckCircle2} title="Mitigation Recommendations" accent="text-green-400">
              <ul className="space-y-2.5">
                {item.mitigation_recommendations.map((mit, i) => (
                  <ActionBullet key={i} text={mit} icon={CheckCircle2} accent="text-green-400" accentBg="bg-green-500/10" onKeywordClick={handleKeywordClick} />
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}

      {/* ── YARA & KQL Detection Rules (side-by-side) ── */}
      {(item.yara_rule || item.kql_rule) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {item.yara_rule && (
            <Section icon={FileCode} title="YARA Rule" accent="text-amber-400">
              <div className="relative group">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(item.yara_rule!);
                    setCopiedField("yara");
                    setTimeout(() => setCopiedField(null), 2000);
                  }}
                  className="absolute top-2 right-2 z-10 p-1.5 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Copy YARA rule"
                >
                  {copiedField === "yara" ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
                <pre className="text-[11px] font-mono leading-relaxed text-muted-foreground bg-black/30 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap border border-amber-500/10">
                  {item.yara_rule}
                </pre>
              </div>
            </Section>
          )}
          {item.kql_rule && (
            <Section icon={FileType2} title="KQL Detection Query" accent="text-cyan-400">
              <div className="relative group">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(item.kql_rule!);
                    setCopiedField("kql");
                    setTimeout(() => setCopiedField(null), 2000);
                  }}
                  className="absolute top-2 right-2 z-10 p-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Copy KQL query"
                >
                  {copiedField === "kql" ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
                <pre className="text-[11px] font-mono leading-relaxed text-muted-foreground bg-black/30 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap border border-cyan-500/10">
                  {item.kql_rule}
                </pre>
              </div>
            </Section>
          )}
        </div>
      )}

      {/* ── Reference Links ────────────────────────────── */}
      {(item.source_url || (item.reference_links && item.reference_links.length > 0)) && (
        <Section icon={Link2} title="Reference Sources" accent="text-violet-400">
          <ul className="space-y-2">
            {/* Always show the actual source URL first */}
            {item.source_url && (
              <li>
                <a
                  href={item.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-xs text-emerald-400 hover:text-emerald-300 hover:underline transition-colors group font-medium"
                >
                  <ExternalLink className="h-3 w-3 shrink-0 opacity-80 group-hover:opacity-100" />
                  <span className="break-all">{item.source_url}</span>
                  <Badge variant="outline" className="text-[9px] h-4 px-1.5 border-emerald-500/30 text-emerald-400 ml-1">Original Source</Badge>
                </a>
              </li>
            )}
            {/* Additional reference links (skip if same as source_url) */}
            {item.reference_links?.filter(link => link !== item.source_url).map((link, i) => (
              <li key={i}>
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-xs text-violet-400 hover:text-violet-300 hover:underline transition-colors group"
                >
                  <ExternalLink className="h-3 w-3 shrink-0 opacity-60 group-hover:opacity-100" />
                  <span className="break-all">{link}</span>
                </a>
              </li>
            ))}
          </ul>
        </Section>
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

      {/* ── IOC Search Popup ───────────────────────────── */}
      {iocKeyword && (
        <IOCSearchPopup keyword={iocKeyword} onClose={() => setIocKeyword(null)} />
      )}
    </div>
  );
}
