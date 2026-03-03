"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loading } from "@/components/Loading";
import { Pagination } from "@/components/Pagination";
import {
  Newspaper,
  Search,
  RefreshCw,
  Clock,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  Shield,
  Zap,
  Globe,
  Bug,
  Cloud,
  Factory,
  FlaskConical,
  Wrench,
  Scale,
  Tag,
  AlertTriangle,
  Sparkles,
  Filter,
  SortDesc,
  LayoutGrid,
  List,
  Rows3,
  PanelRightOpen,
  PanelRightClose,
  X,
  ArrowLeft,
  TrendingUp,
  BarChart3,
  Activity,
  Eye,
  FileText,
  BookOpen,
  TriangleAlert,
  Swords,
  Lightbulb,
  CheckCircle2,
  Radio,
  Users,
  Crosshair,
  Calendar,
  Target,
  Layers,
  ShieldCheck,
  Download,
  Loader2,
  ChevronDown,
  FileDown,
  FileCode,
  FileType2,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import * as api from "@/lib/api";
import type {
  NewsListResponse,
  NewsItem,
  NewsCategoriesResponse,
  NewsCategory,
  NewsCategoryCount,
} from "@/types";

// ── Category config ──────────────────────────────────────
const CATEGORY_META: Record<
  NewsCategory,
  { label: string; shortLabel: string; icon: React.ElementType; color: string; bg: string; border: string; accent: string }
> = {
  active_threats: {
    label: "Active Threats",
    shortLabel: "Threats",
    icon: AlertTriangle,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    accent: "border-l-red-500",
  },
  exploited_vulnerabilities: {
    label: "Exploited Vulnerabilities",
    shortLabel: "Vulns",
    icon: Bug,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    accent: "border-l-orange-500",
  },
  ransomware_breaches: {
    label: "Ransomware & Breaches",
    shortLabel: "Ransom",
    icon: Shield,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
    accent: "border-l-rose-500",
  },
  nation_state: {
    label: "Nation-State Activity",
    shortLabel: "Nation",
    icon: Globe,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    accent: "border-l-purple-500",
  },
  cloud_identity: {
    label: "Cloud & Identity",
    shortLabel: "Cloud",
    icon: Cloud,
    color: "text-sky-400",
    bg: "bg-sky-500/10",
    border: "border-sky-500/30",
    accent: "border-l-sky-500",
  },
  ot_ics: {
    label: "OT / ICS",
    shortLabel: "OT/ICS",
    icon: Factory,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    accent: "border-l-amber-500",
  },
  security_research: {
    label: "Security Research",
    shortLabel: "Research",
    icon: FlaskConical,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    accent: "border-l-emerald-500",
  },
  tools_technology: {
    label: "Tools & Technology",
    shortLabel: "Tools",
    icon: Wrench,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    accent: "border-l-blue-500",
  },
  policy_regulation: {
    label: "Policy & Regulation",
    shortLabel: "Policy",
    icon: Scale,
    color: "text-teal-400",
    bg: "bg-teal-500/10",
    border: "border-teal-500/30",
    accent: "border-l-teal-500",
  },
};

const ALL_CATEGORIES: NewsCategory[] = [
  "active_threats",
  "exploited_vulnerabilities",
  "ransomware_breaches",
  "nation_state",
  "cloud_identity",
  "ot_ics",
  "security_research",
  "tools_technology",
  "policy_regulation",
];

const SORT_OPTIONS = [
  { value: "published_at:desc", label: "Most Recent" },
  { value: "relevance_score:desc", label: "Highest Relevance" },
  { value: "created_at:desc", label: "Recently Added" },
];

type ViewMode = "grid" | "list" | "compact";

// ── Helpers ──────────────────────────────────────────────
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

function formatPublishDate(dateStr: string | null): string {
  if (!dateStr) return "";
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDate(d: string | null) {
  if (!d) return "\u2014";
  return new Date(d).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function relevanceBadge(score: number) {
  if (score >= 80) return { color: "bg-red-500/20 text-red-300 border-red-500/30", label: "Critical" };
  if (score >= 60) return { color: "bg-orange-500/20 text-orange-300 border-orange-500/30", label: "High" };
  if (score >= 40) return { color: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30", label: "Medium" };
  return { color: "bg-green-500/20 text-green-300 border-green-500/30", label: "Low" };
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

const PRIORITY_META: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: "CRITICAL", color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" },
  high: { label: "HIGH", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  medium: { label: "MEDIUM", color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30" },
  low: { label: "LOW", color: "text-green-400", bg: "bg-green-500/10 border-green-500/30" },
};

// ── Skeleton loaders ─────────────────────────────────────
function CardSkeleton() {
  return (
    <div className="rounded-lg border border-border/50 bg-card/50 p-4 animate-pulse">
      <div className="flex items-start gap-3">
        <div className="h-8 w-8 rounded bg-muted/40 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="h-4 w-3/4 rounded bg-muted/40 mb-2" />
          <div className="h-3 w-1/2 rounded bg-muted/30 mb-3" />
          <div className="h-3 w-full rounded bg-muted/30 mb-1.5" />
          <div className="h-3 w-5/6 rounded bg-muted/30 mb-3" />
          <div className="flex gap-2">
            <div className="h-5 w-14 rounded bg-muted/30" />
            <div className="h-5 w-14 rounded bg-muted/30" />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Quick Stats Bar ──────────────────────────────────────
function QuickStatsBar({
  categories,
  news,
}: {
  categories: NewsCategoriesResponse | null;
  news: NewsListResponse | null;
}) {
  if (!categories || !news) return null;

  const total = categories.total;
  const topCategory = categories.categories.reduce<NewsCategoryCount | null>(
    (best, c) => (!best || c.count > best.count ? c : best),
    null,
  );
  const avgRelevance = news.items.length
    ? Math.round(news.items.reduce((s, n) => s + n.relevance_score, 0) / news.items.length)
    : 0;
  const criticalCount = news.items.filter((n) => n.relevance_score >= 80).length;
  const todayCount = news.items.filter((n) => {
    if (!n.published_at) return false;
    const diff = Date.now() - new Date(n.published_at).getTime();
    return diff < 86400000;
  }).length;

  const stats = [
    { label: "Total", value: total, icon: Newspaper, color: "text-primary" },
    { label: "Today", value: todayCount, icon: Activity, color: "text-emerald-400" },
    { label: "Critical", value: criticalCount, icon: AlertTriangle, color: "text-red-400" },
    { label: "Avg Score", value: avgRelevance, icon: TrendingUp, color: "text-yellow-400" },
    {
      label: "Top",
      value: topCategory ? CATEGORY_META[topCategory.category]?.shortLabel || topCategory.category : "\u2014",
      icon: BarChart3,
      color: topCategory ? CATEGORY_META[topCategory.category]?.color || "text-muted-foreground" : "text-muted-foreground",
    },
  ];

  return (
    <div className="flex items-center gap-1 overflow-x-auto scrollbar-none">
      {stats.map((s, i) => {
        const Icon = s.icon;
        return (
          <React.Fragment key={s.label}>
            {i > 0 && <div className="h-4 w-px bg-border/30 shrink-0 mx-0.5" />}
            <div className="flex items-center gap-1.5 shrink-0 px-2 py-1 rounded-md bg-card/30 border border-border/20">
              <Icon className={cn("h-3 w-3", s.color)} />
              <span className="text-[9px] text-muted-foreground/60">{s.label}</span>
              <span className={cn("text-[11px] font-bold", s.color)}>{s.value}</span>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ── Top Critical Horizontal Strip ────────────────────────
function TopCriticalStrip({ items, onSelect }: { items: NewsItem[]; onSelect: (id: string) => void }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const critical = items.filter((n) => n.relevance_score >= 70).slice(0, 8);

  if (critical.length === 0) return null;

  const scroll = (dir: "left" | "right") => {
    if (!scrollRef.current) return;
    scrollRef.current.scrollBy({ left: dir === "left" ? -300 : 300, behavior: "smooth" });
  };

  return (
    <div className="relative group/strip">
      <h2 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1.5 px-1">
        <Zap className="h-3 w-3 text-yellow-400" />
        Top Critical
        <span className="text-muted-foreground/40">({critical.length})</span>
      </h2>

      {/* Scroll arrows */}
      <button
        onClick={() => scroll("left")}
        className="absolute left-0 top-[55%] z-10 -translate-y-1/2 h-7 w-7 rounded-full bg-card/90 border border-border/50 flex items-center justify-center opacity-0 group-hover/strip:opacity-100 transition-opacity shadow-lg hover:bg-card"
      >
        <ChevronLeft className="h-3.5 w-3.5" />
      </button>
      <button
        onClick={() => scroll("right")}
        className="absolute right-0 top-[55%] z-10 -translate-y-1/2 h-7 w-7 rounded-full bg-card/90 border border-border/50 flex items-center justify-center opacity-0 group-hover/strip:opacity-100 transition-opacity shadow-lg hover:bg-card"
      >
        <ChevronRight className="h-3.5 w-3.5" />
      </button>

      <div
        ref={scrollRef}
        className="flex gap-2 overflow-x-auto scrollbar-none pb-1 scroll-smooth"
      >
        {critical.map((item) => {
          const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
          const Icon = meta.icon;
          return (
            <button
              key={`top-${item.id}`}
              onClick={() => onSelect(item.id)}
              className={cn(
                "card-3d shrink-0 w-[260px] rounded-lg border border-border/50 bg-card/50 p-2.5",
                "hover:border-primary/30 transition-all cursor-pointer group text-left",
                "border-l-2",
                meta.accent,
              )}
            >
              <div className="flex items-start gap-2">
                <div className={cn("h-6 w-6 rounded flex items-center justify-center shrink-0", meta.bg)}>
                  <Icon className={cn("h-3 w-3", meta.color)} />
                </div>
                <div className="min-w-0 flex-1">
                  <h4 className="text-[11px] font-semibold line-clamp-2 leading-snug group-hover:text-primary transition-colors">
                    {item.headline}
                  </h4>
                  <p className="text-[9px] text-muted-foreground mt-1 flex items-center gap-1">
                    <span>{item.source}</span>
                    <span className="text-muted-foreground/30">&bull;</span>
                    <span>{timeAgo(item.published_at)}</span>
                  </p>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px] h-5 px-1.5 shrink-0 border font-bold",
                    relevanceBadge(item.relevance_score).color,
                  )}
                >
                  {item.relevance_score}
                </Badge>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Category Sidebar Widget ──────────────────────────────
function CategoryWidget({
  cat,
  count,
  active,
  collapsed,
  onClick,
}: {
  cat: NewsCategory;
  count: NewsCategoryCount | undefined;
  active: boolean;
  collapsed: boolean;
  onClick: () => void;
}) {
  const meta = CATEGORY_META[cat];
  const Icon = meta.icon;
  const c = count?.count || 0;

  if (collapsed) {
    return (
      <button
        onClick={onClick}
        title={`${meta.label} (${c})`}
        className={cn(
          "card-3d w-full rounded-lg border p-2 transition-all duration-200 flex flex-col items-center gap-1",
          active
            ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
            : "border-border/50 bg-card/50 hover:border-border hover:bg-card/80",
        )}
      >
        <div className={cn("h-6 w-6 rounded flex items-center justify-center", meta.bg)}>
          <Icon className={cn("h-3.5 w-3.5", meta.color)} />
        </div>
        <span className="text-[9px] font-bold text-muted-foreground">{c}</span>
      </button>
    );
  }

  return (
    <button
      onClick={onClick}
      className={cn(
        "card-3d w-full text-left rounded-lg border p-2.5 transition-all duration-200",
        active
          ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
          : "border-border/50 bg-card/50 hover:border-border hover:bg-card/80",
      )}
    >
      <div className="flex items-center gap-2 mb-1">
        <div className={cn("h-5 w-5 rounded flex items-center justify-center", meta.bg)}>
          <Icon className={cn("h-3 w-3", meta.color)} />
        </div>
        <span className="text-[11px] font-medium truncate flex-1">{meta.label}</span>
        <Badge variant="outline" className="text-[9px] h-4 px-1 shrink-0">
          {c}
        </Badge>
      </div>
      {count?.latest_headline && (
        <p className="text-[10px] text-muted-foreground line-clamp-1 leading-relaxed pl-7">
          {count.latest_headline}
        </p>
      )}
    </button>
  );
}

// ── News Card (Grid view) ────────────────────────────────
function NewsCardGrid({
  item,
  onSelect,
  isActive,
}: {
  item: NewsItem;
  onSelect: (id: string) => void;
  isActive: boolean;
}) {
  const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
  const Icon = meta.icon;
  const rel = relevanceBadge(item.relevance_score);

  return (
    <button
      onClick={() => onSelect(item.id)}
      className={cn(
        "card-3d rounded-lg border bg-card/50 p-3.5 transition-all duration-200 cursor-pointer group text-left w-full",
        "border-l-2",
        meta.accent,
        isActive
          ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
          : "border-border/50 hover:border-border hover:bg-card/80",
      )}
    >
      <div className="flex items-start gap-2.5">
        <div className={cn("h-7 w-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5", meta.bg)}>
          <Icon className={cn("h-3.5 w-3.5", meta.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-[13px] font-semibold leading-snug line-clamp-2 group-hover:text-primary transition-colors">
            {item.headline}
          </h3>
          <p className="text-[10px] text-muted-foreground mt-1 flex items-center gap-1 flex-wrap">
            <span className="font-medium">{item.source}</span>
            <span className="text-muted-foreground/40">&bull;</span>
            <Clock className="h-2.5 w-2.5" />
            <span>{timeAgo(item.published_at)}</span>
            {item.ai_enriched && (
              <>
                <span className="text-muted-foreground/40">&bull;</span>
                <Sparkles className="h-2.5 w-2.5 text-yellow-400" />
              </>
            )}
          </p>
          {item.summary && (
            <p className="text-[11px] text-muted-foreground/70 mt-1.5 line-clamp-2 leading-relaxed">
              {item.summary}
            </p>
          )}
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            <Badge variant="outline" className={cn("text-[9px] h-4 px-1 border", rel.color)}>
              {item.relevance_score}
            </Badge>
            {item.tags.slice(0, 2).map((tag) => (
              <Badge key={tag} variant="outline" className="text-[9px] h-4 px-1 border-border/50 text-muted-foreground">
                {tag}
              </Badge>
            ))}
            {item.cves.slice(0, 1).map((cve) => (
              <Badge key={cve} variant="outline" className="text-[9px] h-4 px-1 border-red-500/30 text-red-400">
                {cve}
              </Badge>
            ))}
          </div>
        </div>
      </div>
    </button>
  );
}

// ── News Card (List view) ────────────────────────────────
function NewsCardList({
  item,
  onSelect,
  isActive,
}: {
  item: NewsItem;
  onSelect: (id: string) => void;
  isActive: boolean;
}) {
  const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
  const Icon = meta.icon;
  const rel = relevanceBadge(item.relevance_score);

  return (
    <button
      onClick={() => onSelect(item.id)}
      className={cn(
        "card-3d rounded-lg border bg-card/50 p-4 transition-all duration-200 cursor-pointer group text-left w-full",
        "border-l-2",
        meta.accent,
        isActive
          ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
          : "border-border/50 hover:border-border hover:bg-card/80",
      )}
    >
      <div className="flex items-start gap-3">
        <div className={cn("h-8 w-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5", meta.bg)}>
          <Icon className={cn("h-4 w-4", meta.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold leading-snug line-clamp-2 group-hover:text-primary transition-colors">
            {item.headline}
          </h3>
          <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1.5">
            <span className="font-medium">{item.source}</span>
            <span className="text-muted-foreground/40">&bull;</span>
            <Clock className="h-3 w-3" />
            <span title={item.published_at || undefined}>
              {formatPublishDate(item.published_at)}
            </span>
            <span className="text-muted-foreground/50">({timeAgo(item.published_at)})</span>
            {item.ai_enriched && (
              <>
                <span className="text-muted-foreground/40">&bull;</span>
                <Sparkles className="h-3 w-3 text-yellow-400" />
                <span className="text-yellow-400/80">AI</span>
              </>
            )}
          </p>
          {item.summary && (
            <p className="text-xs text-muted-foreground/80 mt-2 line-clamp-2 leading-relaxed">
              {item.summary}
            </p>
          )}
          <div className="flex items-center gap-2 mt-2.5 flex-wrap">
            <Badge variant="outline" className={cn("text-[10px] h-5 px-1.5 border", rel.color)}>
              {item.relevance_score}
            </Badge>
            <Badge variant="outline" className="text-[10px] h-5 px-1.5">
              {meta.label}
            </Badge>
            {item.tags.slice(0, 3).map((tag) => (
              <Badge key={tag} variant="outline" className="text-[10px] h-5 px-1.5 border-border/50 text-muted-foreground">
                {tag}
              </Badge>
            ))}
            {item.cves.slice(0, 2).map((cve) => (
              <Badge key={cve} variant="outline" className="text-[10px] h-5 px-1.5 border-red-500/30 text-red-400">
                {cve}
              </Badge>
            ))}
            {item.threat_actors.slice(0, 1).map((ta) => (
              <Badge key={ta} variant="outline" className="text-[10px] h-5 px-1.5 border-purple-500/30 text-purple-400">
                {ta}
              </Badge>
            ))}
          </div>
        </div>
        <ChevronRight className="h-4 w-4 text-muted-foreground/40 shrink-0 mt-1 group-hover:text-muted-foreground transition-colors" />
      </div>
    </button>
  );
}

// ── News Card (Compact view) ─────────────────────────────
function NewsCardCompact({
  item,
  onSelect,
  isActive,
}: {
  item: NewsItem;
  onSelect: (id: string) => void;
  isActive: boolean;
}) {
  const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
  const Icon = meta.icon;
  const rel = relevanceBadge(item.relevance_score);

  return (
    <button
      onClick={() => onSelect(item.id)}
      className={cn(
        "w-full flex items-center gap-2.5 px-3 py-2 rounded-md border transition-all duration-150 cursor-pointer group text-left",
        "border-l-2",
        meta.accent,
        isActive
          ? "border-primary/50 bg-primary/5"
          : "border-border/30 bg-card/30 hover:bg-card/60 hover:border-border/50",
      )}
    >
      <div className={cn("h-5 w-5 rounded flex items-center justify-center shrink-0", meta.bg)}>
        <Icon className={cn("h-2.5 w-2.5", meta.color)} />
      </div>
      <Badge variant="outline" className={cn("text-[9px] h-4 px-1 border shrink-0 font-bold tabular-nums", rel.color)}>
        {item.relevance_score}
      </Badge>
      <span className="text-[12px] font-medium truncate flex-1 group-hover:text-primary transition-colors">
        {item.headline}
      </span>
      <span className="text-[10px] text-muted-foreground/60 shrink-0 hidden sm:block">{item.source}</span>
      <span className="text-[10px] text-muted-foreground/40 shrink-0 tabular-nums">{timeAgo(item.published_at)}</span>
      {item.ai_enriched && <Sparkles className="h-2.5 w-2.5 text-yellow-400 shrink-0" />}
    </button>
  );
}

// ── Keyword Highlighting (reading pane) ──────────────────
const HIGHLIGHT_RULES: { pattern: RegExp; style: string }[] = [
  { pattern: /\bCVE-\d{4}-\d{4,}\b/g, style: "font-semibold text-orange-400 bg-orange-500/10 px-1 rounded" },
  { pattern: /\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b/g, style: "font-semibold text-blue-400 bg-blue-500/10 px-1 rounded" },
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, style: "font-mono text-sky-400 bg-sky-500/10 px-1 rounded text-[11px]" },
  { pattern: /\b(APT\d+|UNC\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|Turla|Sandworm|Kimsuky|ScarCruft|Volt Typhoon|Storm-\d+|Midnight Blizzard|Scattered Spider)\b/gi, style: "font-semibold text-purple-400 bg-purple-500/10 px-1 rounded" },
  { pattern: /\b(zero[- ]day|critical|exploit(?:ed|ation|s)?|ransom(?:ware)?|malware|backdoor|RCE|remote code execution|privilege escalation|data (?:breach|exfiltration|leak)|supply[- ]chain|phishing|trojan|rootkit|C2|lateral movement)\b/gi, style: "font-medium text-amber-400" },
  { pattern: /\b(patch|update|upgrade|block|disable|revoke|rotate|deploy|scan|isolate|remediate|mitigat(?:e|ion)|harden|restrict|enforce|audit|verify|review|monitor|detect|enable)\b/gi, style: "font-medium text-green-400" },
];

function highlightText(text: string): React.ReactNode[] {
  const allMatches: { start: number; end: number; text: string; style: string }[] = [];
  for (const rule of HIGHLIGHT_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      allMatches.push({ start: m.index, end: m.index + m[0].length, text: m[0], style: rule.style });
    }
  }
  allMatches.sort((a, b) => a.start - b.start);
  const filtered: typeof allMatches = [];
  let lastEnd = 0;
  for (const m of allMatches) {
    if (m.start >= lastEnd) { filtered.push(m); lastEnd = m.end; }
  }
  const nodes: React.ReactNode[] = [];
  let cursor = 0;
  for (let i = 0; i < filtered.length; i++) {
    const m = filtered[i];
    if (cursor < m.start) nodes.push(text.slice(cursor, m.start));
    nodes.push(<span key={`h-${i}`} className={m.style}>{m.text}</span>);
    cursor = m.end;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes.length > 0 ? nodes : [text];
}

function Prose({ text, className }: { text: string; className?: string }) {
  return <p className={cn("text-[12px] leading-relaxed text-muted-foreground", className)}>{highlightText(text)}</p>;
}

function TagList({ items, color = "border-border/50 text-muted-foreground" }: { items: string[]; color?: string }) {
  if (!items.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item) => (
        <Badge key={item} variant="outline" className={cn("text-[9px] h-4 px-1", color)}>
          {item}
        </Badge>
      ))}
    </div>
  );
}

// ── Reading Pane ─────────────────────────────────────────
function ReadingPane({
  item,
  loading,
  onClose,
}: {
  item: NewsItem | null;
  loading: boolean;
  onClose: () => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!item) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center">
        <Eye className="h-8 w-8 text-muted-foreground/20 mb-2" />
        <p className="text-xs text-muted-foreground/50">Select an article to read</p>
        <p className="text-[10px] text-muted-foreground/30 mt-1">Click any article from the list</p>
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
    (item.ioc_summary?.urls?.length || 0) > 0;

  return (
    <div className="space-y-3 animate-in fade-in slide-in-from-right-4 duration-200">
      {/* Header */}
      <div className="flex items-start gap-2">
        <div className={cn("h-8 w-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5", meta.bg)}>
          <CatIcon className={cn("h-4 w-4", meta.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-sm font-bold leading-snug">{item.headline}</h2>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap text-[10px] text-muted-foreground">
            <span className="font-medium">{item.source}</span>
            <span className="text-muted-foreground/40">&bull;</span>
            <Clock className="h-2.5 w-2.5" />
            <span>{formatDate(item.published_at)}</span>
            <span className="text-muted-foreground/50">({timeAgo(item.published_at)})</span>
          </div>
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", meta.border, meta.color)}>
              {meta.label}
            </Badge>
            <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border font-semibold", priority.bg, priority.color)}>
              {priority.label}
            </Badge>
            <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", relevanceColor(item.relevance_score))}>
              {item.relevance_score}
            </Badge>
            <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", confidenceColor(item.confidence))}>
              {item.confidence}
            </Badge>
          </div>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 p-1 rounded hover:bg-accent/30 transition-colors"
          title="Close pane"
        >
          <X className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>

      {/* Action links */}
      <div className="flex items-center gap-2 border-b border-border/30 pb-2">
        <Link
          href={`/news/${item.id}`}
          className="flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded border border-primary/30 bg-primary/5 text-primary hover:bg-primary/10 transition-colors"
        >
          <ExternalLink className="h-2.5 w-2.5" /> Full Page
        </Link>
        <a
          href={item.source_url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded border border-border/50 text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
        >
          Source <ExternalLink className="h-2.5 w-2.5" />
        </a>
      </div>

      {/* Summary */}
      {item.summary && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1 flex items-center gap-1">
            <FileText className="h-3 w-3 text-blue-400" /> Summary
          </h3>
          <Prose text={item.summary} />
        </section>
      )}

      {/* Executive Brief */}
      {item.executive_brief && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1 flex items-center gap-1">
            <BookOpen className="h-3 w-3 text-indigo-400" /> Intelligence Brief
          </h3>
          <Prose text={item.executive_brief} />
        </section>
      )}

      {/* Risk + Attack */}
      {(item.risk_assessment || item.attack_narrative) && (
        <div className="grid grid-cols-1 gap-2">
          {item.risk_assessment && (
            <section className="rounded-md border border-red-500/10 bg-red-500/5 p-2.5">
              <h3 className="text-[10px] uppercase tracking-wider text-red-400/70 mb-1 flex items-center gap-1">
                <TriangleAlert className="h-3 w-3" /> Risk Assessment
              </h3>
              <Prose text={item.risk_assessment} />
            </section>
          )}
          {item.attack_narrative && (
            <section className="rounded-md border border-orange-500/10 bg-orange-500/5 p-2.5">
              <h3 className="text-[10px] uppercase tracking-wider text-orange-400/70 mb-1 flex items-center gap-1">
                <Swords className="h-3 w-3" /> Attack Narrative
              </h3>
              <Prose text={item.attack_narrative} />
            </section>
          )}
        </div>
      )}

      {/* Key Takeaways */}
      {item.why_it_matters.length > 0 && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Lightbulb className="h-3 w-3 text-yellow-400" /> Key Takeaways
          </h3>
          <div className="space-y-1">
            {item.why_it_matters.map((point, i) => (
              <div key={i} className="flex items-start gap-2 text-[11px] text-muted-foreground leading-relaxed">
                <span className="text-[9px] font-bold text-yellow-400 bg-yellow-500/10 rounded px-1 py-0.5 shrink-0 mt-0.5">{i + 1}</span>
                <span>{highlightText(point)}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Threat Landscape */}
      {(item.threat_actors.length > 0 || item.malware_families.length > 0 || item.cves.length > 0) && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Users className="h-3 w-3 text-purple-400" /> Threat Landscape
          </h3>
          <div className="space-y-1.5">
            {item.threat_actors.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Actors</span>
                <TagList items={item.threat_actors} color="border-purple-500/30 text-purple-400" />
              </div>
            )}
            {item.malware_families.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Malware</span>
                <TagList items={item.malware_families} color="border-red-500/30 text-red-400" />
              </div>
            )}
            {item.cves.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">CVEs</span>
                <TagList items={item.cves} color="border-orange-500/30 text-orange-400" />
              </div>
            )}
            {item.vulnerable_products.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Products</span>
                <TagList items={item.vulnerable_products} color="border-amber-500/30 text-amber-400" />
              </div>
            )}
          </div>
        </section>
      )}

      {/* MITRE ATT&CK */}
      {item.tactics_techniques.length > 0 && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Crosshair className="h-3 w-3 text-blue-400" /> MITRE ATT&CK
          </h3>
          <div className="flex flex-wrap gap-1">
            {item.tactics_techniques.map((t, i) => (
              <Badge key={i} variant="outline" className="text-[9px] h-4 px-1 border-blue-500/30 text-blue-400">
                {t}
              </Badge>
            ))}
          </div>
        </section>
      )}

      {/* Targeting */}
      {(item.targeted_sectors.length > 0 || item.targeted_regions.length > 0) && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Globe className="h-3 w-3 text-emerald-400" /> Targeting
          </h3>
          <div className="space-y-1.5">
            {item.targeted_sectors.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Sectors</span>
                <TagList items={item.targeted_sectors} color="border-emerald-500/30 text-emerald-400" />
              </div>
            )}
            {item.targeted_regions.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Regions</span>
                <TagList items={item.targeted_regions} color="border-sky-500/30 text-sky-400" />
              </div>
            )}
          </div>
        </section>
      )}

      {/* IOCs */}
      {hasIOCs && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Eye className="h-3 w-3 text-red-400" /> IOCs
          </h3>
          <div className="space-y-1.5">
            {item.ioc_summary?.domains && item.ioc_summary.domains.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">Domains</span>
                <TagList items={item.ioc_summary.domains} color="border-blue-500/30 text-blue-400" />
              </div>
            )}
            {item.ioc_summary?.ips && item.ioc_summary.ips.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] text-muted-foreground/50 uppercase w-14 shrink-0">IPs</span>
                <TagList items={item.ioc_summary.ips} color="border-sky-500/30 text-sky-400" />
              </div>
            )}
            {item.ioc_summary?.hashes && item.ioc_summary.hashes.length > 0 && (
              <div>
                <span className="text-[9px] text-muted-foreground/50 uppercase">Hashes</span>
                <div className="mt-0.5 space-y-0.5">
                  {item.ioc_summary.hashes.map((h) => (
                    <p key={h} className="text-[9px] font-mono text-muted-foreground break-all">{h}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Detection + Mitigation */}
      {(item.detection_opportunities.length > 0 || item.mitigation_recommendations.length > 0) && (
        <div className="grid grid-cols-1 gap-2">
          {item.detection_opportunities.length > 0 && (
            <section className="rounded-md border border-blue-500/10 bg-blue-500/5 p-2.5">
              <h3 className="text-[10px] uppercase tracking-wider text-blue-400/70 mb-1 flex items-center gap-1">
                <Radio className="h-3 w-3" /> Detection
              </h3>
              <ul className="space-y-1">
                {item.detection_opportunities.map((d, i) => (
                  <li key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                    <Eye className="h-3 w-3 text-blue-400/60 shrink-0 mt-0.5" />
                    <span>{highlightText(d)}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {item.mitigation_recommendations.length > 0 && (
            <section className="rounded-md border border-green-500/10 bg-green-500/5 p-2.5">
              <h3 className="text-[10px] uppercase tracking-wider text-green-400/70 mb-1 flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" /> Mitigations
              </h3>
              <ul className="space-y-1">
                {item.mitigation_recommendations.map((m, i) => (
                  <li key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                    <CheckCircle2 className="h-3 w-3 text-green-400/60 shrink-0 mt-0.5" />
                    <span>{highlightText(m)}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}

      {/* Timeline */}
      {item.timeline.length > 0 && (
        <section>
          <h3 className="text-[10px] uppercase tracking-wider text-muted-foreground/60 mb-1.5 flex items-center gap-1">
            <Calendar className="h-3 w-3 text-indigo-400" /> Timeline
          </h3>
          <div className="relative pl-3 space-y-2">
            <div className="absolute left-[5px] top-1 bottom-1 w-px bg-indigo-500/20" />
            {item.timeline.map((ev, i) => (
              <div key={i} className="relative flex items-start gap-2">
                <div className="absolute left-[-8px] top-1 h-2 w-2 rounded-full border border-indigo-400 bg-background" />
                <div>
                  {ev.date && <p className="text-[9px] font-medium text-indigo-400">{ev.date}</p>}
                  <p className="text-[11px] text-muted-foreground">{ev.event}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Tags */}
      {item.tags.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-border/20">
          <Tag className="h-3 w-3 text-muted-foreground/40" />
          {item.tags.map((tag) => (
            <Badge key={tag} variant="outline" className="text-[9px] h-4 px-1 border-border/30 text-muted-foreground/60">
              {tag}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────
export default function CyberNewsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Data
  const [news, setNews] = useState<NewsListResponse | null>(null);
  const [categories, setCategories] = useState<NewsCategoriesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [catLoading, setCatLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Filters
  const [page, setPage] = useState(1);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(
    searchParams.get("category") || null,
  );
  const [searchQuery, setSearchQuery] = useState(searchParams.get("q") || "");
  const [sortKey, setSortKey] = useState("published_at:desc");
  const [selectedTag, setSelectedTag] = useState<string | null>(
    searchParams.get("tag") || null,
  );

  // UI
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>("grid");
  const [readingPaneOpen, setReadingPaneOpen] = useState(false);
  const [selectedArticle, setSelectedArticle] = useState<NewsItem | null>(null);
  const [articleLoading, setArticleLoading] = useState(false);
  const [newItemIds, setNewItemIds] = useState<Set<string>>(new Set());

  // Refs
  const prevItemIdsRef = useRef<Set<string>>(new Set());
  const autoRefreshRef = useRef<NodeJS.Timeout | null>(null);

  const fetchCategories = useCallback(async () => {
    setCatLoading(true);
    try {
      const data = await api.getNewsCategories();
      setCategories(data);
    } catch {
      /* ignore */
    } finally {
      setCatLoading(false);
    }
  }, []);

  const fetchNews = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [field, dir] = sortKey.split(":");
      const params: Record<string, string | number | boolean | undefined> = {
        page,
        page_size: 20,
        sort_by: field,
        sort_order: dir,
        ai_enriched: true,
      };
      if (selectedCategory) params.category = selectedCategory;
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (selectedTag) params.tag = selectedTag;

      const data = await api.getNews(params);

      // Detect new items for slide-in animation
      if (silent && data.items.length > 0) {
        const fresh = new Set<string>();
        data.items.forEach((i) => {
          if (!prevItemIdsRef.current.has(i.id)) fresh.add(i.id);
        });
        if (fresh.size > 0) {
          setNewItemIds(fresh);
          setTimeout(() => setNewItemIds(new Set()), 3000);
        }
      }
      if (data.items.length > 0) {
        prevItemIdsRef.current = new Set(data.items.map((i) => i.id));
      }

      setNews(data);
    } catch {
      /* ignore */
    } finally {
      if (!silent) setLoading(false);
    }
  }, [page, selectedCategory, searchQuery, selectedTag, sortKey]);

  useEffect(() => { fetchCategories(); }, [fetchCategories]);
  useEffect(() => { fetchNews(); }, [fetchNews]);

  // Auto-refresh every 60s
  useEffect(() => {
    autoRefreshRef.current = setInterval(() => {
      fetchNews(true);
      fetchCategories();
    }, 60000);
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current);
    };
  }, [fetchNews, fetchCategories]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await api.refreshNews();
      setTimeout(() => {
        fetchNews();
        fetchCategories();
        setRefreshing(false);
      }, 2000);
    } catch {
      setRefreshing(false);
    }
  };

  const handleCategoryClick = (cat: NewsCategory) => {
    setSelectedCategory(selectedCategory === cat ? null : cat);
    setPage(1);
  };

  const handleArticleSelect = async (id: string) => {
    if (!readingPaneOpen) setReadingPaneOpen(true);
    if (selectedArticle?.id === id) {
      router.push(`/news/${id}`);
      return;
    }
    setArticleLoading(true);
    try {
      const detail = await api.getNewsItem(id);
      setSelectedArticle(detail);
    } catch { /* ignore */ } finally {
      setArticleLoading(false);
    }
  };

  const handleClosePane = () => {
    setReadingPaneOpen(false);
    setSelectedArticle(null);
  };

  const catCountMap = new Map<string, NewsCategoryCount>();
  categories?.categories.forEach((c) => catCountMap.set(c.category, c));

  const VIEW_MODES: { mode: ViewMode; icon: React.ElementType; label: string }[] = [
    { mode: "grid", icon: LayoutGrid, label: "Grid" },
    { mode: "list", icon: List, label: "List" },
    { mode: "compact", icon: Rows3, label: "Compact" },
  ];

  const renderNewsItems = () => {
    if (!news) return null;
    const items = news.items;

    if (viewMode === "compact") {
      return (
        <div className="space-y-1">
          {items.map((item) => (
            <div key={item.id} className={cn(newItemIds.has(item.id) && "animate-in slide-in-from-top-2 fade-in duration-500")}>
              <NewsCardCompact item={item} onSelect={handleArticleSelect} isActive={selectedArticle?.id === item.id} />
            </div>
          ))}
        </div>
      );
    }
    if (viewMode === "list") {
      return (
        <div className="space-y-2">
          {items.map((item) => (
            <div key={item.id} className={cn(newItemIds.has(item.id) && "animate-in slide-in-from-top-2 fade-in duration-500")}>
              <NewsCardList item={item} onSelect={handleArticleSelect} isActive={selectedArticle?.id === item.id} />
            </div>
          ))}
        </div>
      );
    }
    // Grid
    return (
      <div className={cn("grid gap-2", readingPaneOpen ? "grid-cols-1" : "grid-cols-1 xl:grid-cols-2")}>
        {items.map((item) => (
          <div key={item.id} className={cn(newItemIds.has(item.id) && "animate-in slide-in-from-top-2 fade-in duration-500")}>
            <NewsCardGrid item={item} onSelect={handleArticleSelect} isActive={selectedArticle?.id === item.id} />
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* ── Header ──────────────────────────────────── */}
      <div className="shrink-0 px-4 pt-3 pb-2 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Newspaper className="h-5 w-5 text-primary" />
            <div>
              <h1 className="text-lg font-bold tracking-tight">Cyber News</h1>
              <p className="text-[11px] text-muted-foreground -mt-0.5">
                Structured intelligence
                {categories && (
                  <> &mdash; <span className="font-medium text-foreground">{categories.total}</span> articles</>
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 text-[9px] text-muted-foreground/40" title="Auto-refreshes every 60s">
              <Activity className="h-3 w-3 text-emerald-500 animate-pulse" />
              <span className="hidden sm:inline">Live</span>
            </div>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="icon-btn-3d flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md border border-border/50 hover:border-primary/40 transition-all"
            >
              <RefreshCw className={cn("h-3 w-3", refreshing && "animate-spin")} />
              Refresh
            </button>
          </div>
        </div>
        <QuickStatsBar categories={categories} news={news} />
      </div>

      {/* ── Main area ───────────────────────────────── */}
      <div className="flex-1 flex overflow-hidden">
        {/* ── Left: Collapsible Category Sidebar ────── */}
        <div
          className={cn(
            "shrink-0 border-r border-border/30 overflow-y-auto scrollbar-none transition-all duration-200 hidden lg:block",
            sidebarCollapsed ? "w-16 p-1.5" : "w-52 p-2",
          )}
        >
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full flex items-center justify-center mb-2 py-1 rounded-md hover:bg-accent/30 text-muted-foreground/50 hover:text-muted-foreground transition-colors"
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {sidebarCollapsed ? <ChevronsRight className="h-3.5 w-3.5" /> : <ChevronsLeft className="h-3.5 w-3.5" />}
          </button>

          {/* All News */}
          <button
            onClick={() => { setSelectedCategory(null); setPage(1); }}
            className={cn(
              "card-3d w-full rounded-lg border transition-all duration-200 mb-1.5",
              sidebarCollapsed ? "p-2 flex flex-col items-center gap-1" : "p-2.5 text-left",
              !selectedCategory
                ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                : "border-border/50 bg-card/50 hover:border-border hover:bg-card/80",
            )}
          >
            {sidebarCollapsed ? (
              <>
                <Newspaper className="h-3.5 w-3.5 text-primary" />
                <span className="text-[9px] font-bold text-muted-foreground">{categories?.total || 0}</span>
              </>
            ) : (
              <div className="flex items-center gap-2">
                <div className="h-5 w-5 rounded flex items-center justify-center bg-primary/10">
                  <Newspaper className="h-3 w-3 text-primary" />
                </div>
                <span className="text-[11px] font-medium">All News</span>
                <Badge variant="outline" className="text-[9px] h-4 px-1 ml-auto shrink-0">
                  {categories?.total || 0}
                </Badge>
              </div>
            )}
          </button>

          <div className="space-y-1">
            {catLoading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="rounded-lg border border-border/50 bg-card/50 p-2 animate-pulse">
                    <div className="h-5 w-full rounded bg-muted/40" />
                  </div>
                ))
              : ALL_CATEGORIES.map((cat) => (
                  <CategoryWidget
                    key={cat}
                    cat={cat}
                    count={catCountMap.get(cat)}
                    active={selectedCategory === cat}
                    collapsed={sidebarCollapsed}
                    onClick={() => handleCategoryClick(cat)}
                  />
                ))}
          </div>
        </div>

        {/* ── Center: News Feed ─────────────────────── */}
        <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
          {/* Toolbar */}
          <div className="shrink-0 px-3 py-2 border-b border-border/30 flex items-center gap-2">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/60" />
              <input
                type="text"
                placeholder="Search headlines..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-card/50 border border-border/50 rounded-md focus:outline-none focus:ring-1 focus:ring-primary/30 focus:border-primary/40"
              />
            </div>

            <select
              value={selectedCategory || ""}
              onChange={(e) => { setSelectedCategory(e.target.value || null); setPage(1); }}
              className="lg:hidden text-[11px] bg-card/50 border border-border/50 rounded-md px-2 py-1.5"
            >
              <option value="">All</option>
              {ALL_CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>{CATEGORY_META[cat].label}</option>
              ))}
            </select>

            <select
              value={sortKey}
              onChange={(e) => { setSortKey(e.target.value); setPage(1); }}
              className="text-[11px] bg-card/50 border border-border/50 rounded-md px-2 py-1.5"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>

            {/* View mode */}
            <div className="flex items-center border border-border/50 rounded-md overflow-hidden">
              {VIEW_MODES.map(({ mode, icon: VIcon, label }) => (
                <button
                  key={mode}
                  onClick={() => setViewMode(mode)}
                  title={label}
                  className={cn(
                    "px-2 py-1.5 transition-colors",
                    viewMode === mode
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground/50 hover:text-muted-foreground hover:bg-accent/20",
                  )}
                >
                  <VIcon className="h-3.5 w-3.5" />
                </button>
              ))}
            </div>

            {/* Reading pane toggle */}
            <button
              onClick={() => readingPaneOpen ? handleClosePane() : setReadingPaneOpen(true)}
              title={readingPaneOpen ? "Close reading pane" : "Open reading pane"}
              className={cn(
                "p-1.5 rounded-md border transition-colors",
                readingPaneOpen
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-border/50 text-muted-foreground/50 hover:text-muted-foreground hover:bg-accent/20",
              )}
            >
              {readingPaneOpen ? <PanelRightClose className="h-3.5 w-3.5" /> : <PanelRightOpen className="h-3.5 w-3.5" />}
            </button>
          </div>

          {/* Active filters bar */}
          {(selectedCategory || selectedTag) && (
            <div className="shrink-0 px-3 py-1.5 flex items-center gap-2 flex-wrap border-b border-border/20">
              <Filter className="h-3 w-3 text-muted-foreground/60" />
              {selectedCategory && (
                <Badge
                  variant="outline"
                  className="text-[10px] h-5 px-2 cursor-pointer hover:border-red-500/40"
                  onClick={() => { setSelectedCategory(null); setPage(1); }}
                >
                  {CATEGORY_META[selectedCategory as NewsCategory]?.label || selectedCategory} &times;
                </Badge>
              )}
              {selectedTag && (
                <Badge
                  variant="outline"
                  className="text-[10px] h-5 px-2 cursor-pointer hover:border-red-500/40"
                  onClick={() => { setSelectedTag(null); setPage(1); }}
                >
                  tag: {selectedTag} &times;
                </Badge>
              )}
            </div>
          )}

          {/* Content split: news list + reading pane */}
          <div className="flex-1 flex overflow-hidden">
            {/* News list */}
            <div className={cn(
              "overflow-y-auto scrollbar-thin flex-1 min-w-0",
              readingPaneOpen && "max-w-[50%]",
            )}>
              <div className="p-3 space-y-3">
                {/* Top Critical Strip */}
                {!selectedCategory && !searchQuery && !selectedTag && page === 1 && news && (
                  <TopCriticalStrip items={news.items} onSelect={handleArticleSelect} />
                )}

                {loading ? (
                  <div className={cn(
                    "grid gap-2",
                    viewMode === "grid" && !readingPaneOpen ? "grid-cols-1 xl:grid-cols-2" : "grid-cols-1",
                  )}>
                    {Array.from({ length: 6 }).map((_, i) => <CardSkeleton key={i} />)}
                  </div>
                ) : !news || news.items.length === 0 ? (
                  <Card className="card-3d">
                    <CardContent className="py-12 text-center">
                      <Newspaper className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                      <p className="text-sm text-muted-foreground">
                        No news articles found.
                        {selectedCategory && " Try a different category or clear filters."}
                      </p>
                      <button onClick={handleRefresh} className="mt-3 text-xs text-primary hover:underline">
                        Refresh feeds
                      </button>
                    </CardContent>
                  </Card>
                ) : (
                  <>
                    {renderNewsItems()}
                    {news.pages > 1 && (
                      <Pagination page={page} pages={news.pages} onPageChange={setPage} />
                    )}
                  </>
                )}
              </div>
            </div>

            {/* Reading pane */}
            {readingPaneOpen && (
              <div className="w-[50%] shrink-0 border-l border-border/30 overflow-y-auto scrollbar-thin bg-card/20 animate-in slide-in-from-right-8 duration-300">
                <div className="p-4">
                  <ReadingPane item={selectedArticle} loading={articleLoading} onClose={handleClosePane} />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
