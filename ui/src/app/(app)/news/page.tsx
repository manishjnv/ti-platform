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
  ShieldAlert,
  ArrowUpDown,
  Link2,
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
  NewsPipelineStatus,
  NewsStatsResponse,
  VulnerableProduct,
  VulnerableProductsListResponse,
  ThreatCampaign,
  ThreatCampaignsListResponse,
  ExtractionStatsResponse,
} from "@/types";

// ── Category config ──────────────────────────────────────
const CATEGORY_META: Record<
  NewsCategory,
  { label: string; shortLabel: string; icon: React.ElementType; color: string; bg: string; border: string; accent: string; glow: string }
> = {
  active_threats: {
    label: "Active Threats",
    shortLabel: "Threats",
    icon: AlertTriangle,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    accent: "border-l-red-500",
    glow: "shadow-[0_0_12px_-3px_rgba(239,68,68,0.25)]",
  },
  exploited_vulnerabilities: {
    label: "Exploited Vulnerabilities",
    shortLabel: "Vulns",
    icon: Bug,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    accent: "border-l-orange-500",
    glow: "shadow-[0_0_12px_-3px_rgba(249,115,22,0.25)]",
  },
  ransomware_breaches: {
    label: "Ransomware & Breaches",
    shortLabel: "Ransom",
    icon: Shield,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/30",
    accent: "border-l-rose-500",
    glow: "shadow-[0_0_12px_-3px_rgba(244,63,94,0.25)]",
  },
  nation_state: {
    label: "Nation-State Activity",
    shortLabel: "Nation",
    icon: Globe,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    accent: "border-l-purple-500",
    glow: "shadow-[0_0_12px_-3px_rgba(168,85,247,0.25)]",
  },
  cloud_identity: {
    label: "Cloud & Identity",
    shortLabel: "Cloud",
    icon: Cloud,
    color: "text-sky-400",
    bg: "bg-sky-500/10",
    border: "border-sky-500/30",
    accent: "border-l-sky-500",
    glow: "shadow-[0_0_12px_-3px_rgba(14,165,233,0.25)]",
  },
  ot_ics: {
    label: "OT / ICS",
    shortLabel: "OT/ICS",
    icon: Factory,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    accent: "border-l-amber-500",
    glow: "shadow-[0_0_12px_-3px_rgba(245,158,11,0.25)]",
  },
  security_research: {
    label: "Security Research",
    shortLabel: "Research",
    icon: FlaskConical,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    accent: "border-l-emerald-500",
    glow: "shadow-[0_0_12px_-3px_rgba(52,211,153,0.25)]",
  },
  tools_technology: {
    label: "Tools & Technology",
    shortLabel: "Tools",
    icon: Wrench,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    accent: "border-l-blue-500",
    glow: "shadow-[0_0_12px_-3px_rgba(96,165,250,0.25)]",
  },
  policy_regulation: {
    label: "Policy & Regulation",
    shortLabel: "Policy",
    icon: Scale,
    color: "text-teal-400",
    bg: "bg-teal-500/10",
    border: "border-teal-500/30",
    accent: "border-l-teal-500",
    glow: "shadow-[0_0_12px_-3px_rgba(45,212,191,0.25)]",
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
  stats,
  onFilterCategory,
  onSortBy,
}: {
  categories: NewsCategoriesResponse | null;
  stats: NewsStatsResponse | null;
  onFilterCategory?: (cat: string | null) => void;
  onSortBy?: (sort: string) => void;
}) {
  if (!categories || !stats) return null;

  const topCategory = categories.categories.reduce<NewsCategoryCount | null>(
    (best, c) => (!best || c.count > best.count ? c : best),
    null,
  );

  const statItems: { label: string; value: string | number; icon: React.ElementType; color: string; onClick?: () => void; title?: string }[] = [
    { label: "Total", value: stats.total, icon: Newspaper, color: "text-primary", onClick: () => onFilterCategory?.(null), title: "Show all articles" },
    { label: "Today", value: stats.today, icon: Calendar, color: "text-emerald-400", onClick: () => onSortBy?.("published_at:desc"), title: "Sort by newest" },
    { label: "Critical", value: stats.critical, icon: AlertTriangle, color: "text-red-400", onClick: () => onSortBy?.("relevance_score:desc"), title: "Sort by relevance (critical first)" },
    { label: "High", value: stats.high, icon: Shield, color: "text-orange-400", onClick: () => onSortBy?.("relevance_score:desc"), title: "Sort by priority" },
    { label: "Avg Score", value: stats.avg_score, icon: TrendingUp, color: "text-yellow-400", onClick: () => onSortBy?.("relevance_score:desc"), title: "Sort by relevance score" },
    { label: "Sources", value: stats.sources, icon: Globe, color: "text-sky-400", title: "Unique sources across all articles" },
    { label: "Enriched", value: `${stats.enriched_pct}%`, icon: Sparkles, color: "text-purple-400", title: "AI enrichment rate" },
    {
      label: "Top",
      value: topCategory ? CATEGORY_META[topCategory.category]?.shortLabel || topCategory.category : "\u2014",
      icon: BarChart3,
      color: topCategory ? CATEGORY_META[topCategory.category]?.color || "text-muted-foreground" : "text-muted-foreground",
      onClick: topCategory ? () => onFilterCategory?.(topCategory.category) : undefined,
      title: topCategory ? `Filter by ${CATEGORY_META[topCategory.category]?.label || topCategory.category}` : undefined,
    },
  ];

  return (
    <div className="flex items-center gap-1 overflow-x-auto scrollbar-none">
      {statItems.map((s, i) => {
        const Icon = s.icon;
        const isClickable = !!s.onClick;
        return (
          <React.Fragment key={s.label}>
            {i > 0 && <div className="h-4 w-px bg-border/30 shrink-0 mx-0.5" />}
            <button
              type="button"
              onClick={s.onClick}
              disabled={!isClickable}
              title={s.title}
              className={cn(
                "flex items-center gap-1.5 shrink-0 px-2 py-1 rounded-md bg-card/30 border border-border/20 transition-all",
                isClickable && "cursor-pointer hover:bg-card/60 hover:border-primary/30 hover:scale-[1.03] active:scale-100",
                !isClickable && "cursor-default",
              )}
            >
              <Icon className={cn("h-3 w-3", s.color)} />
              <span className="text-[9px] text-muted-foreground/60">{s.label}</span>
              <span className={cn("text-[11px] font-bold", s.color)}>{s.value}</span>
            </button>
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
                "border-l-[3px]",
                meta.accent,
                meta.glow,
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
        "border-l-[3px]",
        meta.accent,
        meta.glow,
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
        "border-l-[3px]",
        meta.accent,
        meta.glow,
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
        "border-l-[3px]",
        meta.accent,
        meta.glow,
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

// ── Subtopic types ────────────────────────────────────────
type Subtopic = "news" | "vulnerable-products" | "threat-campaigns";

const SUBTOPIC_META: { id: Subtopic; label: string; shortLabel: string; icon: React.ElementType; color: string; bg: string; border: string; description: string }[] = [
  {
    id: "news",
    label: "Cyber News Feed",
    shortLabel: "News",
    icon: Newspaper,
    color: "text-primary",
    bg: "bg-primary/10",
    border: "border-primary/40",
    description: "Structured intelligence from all sources",
  },
  {
    id: "vulnerable-products",
    label: "Vulnerable Products (24H)",
    shortLabel: "Vulns",
    icon: Bug,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/40",
    description: "Products with active vulnerabilities",
  },
  {
    id: "threat-campaigns",
    label: "Threat Actors & Campaigns (7 Days)",
    shortLabel: "Actors",
    icon: Swords,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/40",
    description: "Active threat actors and campaigns",
  },
];

// ── Severity badge helper ──────────────────────────────────
function severityBadge(sev: string) {
  switch (sev) {
    case "critical": return { color: "bg-red-500/20 text-red-300 border-red-500/30", label: "Critical" };
    case "high": return { color: "bg-orange-500/20 text-orange-300 border-orange-500/30", label: "High" };
    case "medium": return { color: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30", label: "Medium" };
    case "low": return { color: "bg-green-500/20 text-green-300 border-green-500/30", label: "Low" };
    default: return { color: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30", label: sev || "Unknown" };
  }
}

// ── Clickable entity helper ───────────────────────────────
function EntityBadge({ label, searchPrefix, className }: { label: string; searchPrefix?: string; className?: string }) {
  const router = useRouter();
  return (
    <button
      onClick={() => router.push(`/search?q=${encodeURIComponent(searchPrefix ? `${searchPrefix}:${label}` : label)}`)}
      className={cn("cursor-pointer hover:brightness-125 transition-all", className)}
      title={`Search for "${label}"`}
    >
      {label}
    </button>
  );
}

// ── Helpers: isNew / isStale ──────────────────────────────
function isNewEntry(firstSeen: string): boolean {
  return Date.now() - new Date(firstSeen).getTime() < 24 * 60 * 60 * 1000;
}
function isStaleEntry(lastSeen: string, days = 7): boolean {
  return Date.now() - new Date(lastSeen).getTime() > days * 24 * 60 * 60 * 1000;
}

// ── Vendor Stats Widget ────────────────────────────────────
function VendorStatsWidget() {
  const [data, setData] = useState<Array<{ vendor: string; count: number; critical: number; high: number; kev_count: number }> | null>(null);
  useEffect(() => { api.getVendorStats().then(setData).catch(() => {}); }, []);
  if (!data || data.length === 0) return null;
  const max = data[0]?.count || 1;
  return (
    <Card className="card-3d mb-3">
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-xs font-semibold flex items-center gap-1.5"><Factory className="h-3.5 w-3.5 text-orange-400" />Top Vendors by Vulnerabilities</CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-3">
        <div className="space-y-1.5">
          {data.slice(0, 10).map((v) => (
            <div key={v.vendor} className="flex items-center gap-2 text-[11px]">
              <span className="w-[100px] truncate text-muted-foreground font-medium" title={v.vendor}>{v.vendor}</span>
              <div className="flex-1 h-3 bg-muted/20 rounded-full overflow-hidden relative">
                <div className="h-full rounded-full bg-gradient-to-r from-orange-500/60 to-red-500/60" style={{ width: `${(v.count / max) * 100}%` }} />
              </div>
              <span className="w-6 text-right font-mono text-muted-foreground">{v.count}</span>
              {v.kev_count > 0 && <span title={`${v.kev_count} KEV`} className="text-[8px] px-1 rounded bg-red-500/20 text-red-300">{v.kev_count} KEV</span>}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Campaign Timeline Widget ───────────────────────────────
function CampaignTimelineWidget({ campaigns }: { campaigns: Array<{ id: string; actor_name: string; first_seen: string; last_seen: string; severity: string }> }) {
  if (!campaigns || campaigns.length === 0) return null;
  // Find date range
  const allDates = campaigns.flatMap((c) => [new Date(c.first_seen).getTime(), new Date(c.last_seen).getTime()]);
  const minDate = Math.min(...allDates);
  const maxDate = Math.max(...allDates);
  const range = maxDate - minDate || 1;

  return (
    <Card className="card-3d mb-3">
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-xs font-semibold flex items-center gap-1.5"><Calendar className="h-3.5 w-3.5 text-red-400" />Campaign Timeline</CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-3">
        <div className="space-y-1">
          {campaigns.slice(0, 12).map((c) => {
            const start = ((new Date(c.first_seen).getTime() - minDate) / range) * 100;
            const width = Math.max(((new Date(c.last_seen).getTime() - new Date(c.first_seen).getTime()) / range) * 100, 2);
            const sev = c.severity;
            const color = sev === "critical" ? "bg-red-500/70" : sev === "high" ? "bg-orange-500/70" : sev === "medium" ? "bg-yellow-500/70" : "bg-green-500/70";
            return (
              <div key={c.id} className="flex items-center gap-2 text-[10px]">
                <span className="w-[90px] truncate text-muted-foreground font-medium" title={c.actor_name}>{c.actor_name}</span>
                <div className="flex-1 h-2.5 bg-muted/15 rounded-full relative overflow-hidden">
                  <div className={cn("absolute h-full rounded-full", color)} style={{ left: `${start}%`, width: `${width}%` }} title={`${formatPublishDate(c.first_seen)} — ${formatPublishDate(c.last_seen)}`} />
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex justify-between text-[9px] text-muted-foreground/50 mt-1.5">
          <span>{formatPublishDate(new Date(minDate).toISOString())}</span>
          <span>{formatPublishDate(new Date(maxDate).toISOString())}</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Vulnerable Products Table ─────────────────────────────
function VulnerableProductsTable() {
  const [data, setData] = useState<VulnerableProductsListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("last_seen");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [sevFilter, setSevFilter] = useState("");
  const [windowMode, setWindowMode] = useState<"24h" | "all">("24h");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [cveLookupOpen, setCveLookupOpen] = useState(false);
  const [cveInput, setCveInput] = useState("");
  const [cveLookupResult, setCveLookupResult] = useState<{ requested: number; found: number; missing: string[]; results: Record<string, any> } | null>(null);
  const [cveLookupLoading, setCveLookupLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getVulnerableProducts({
        search: search.trim() || undefined,
        severity: sevFilter || undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        limit: 200,
        window: windowMode,
      });
      setData(result);
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [search, sevFilter, sortBy, sortOrder, windowMode]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCveLookup = async () => {
    const cves = cveInput.split(/[\n,]+/).map(s => s.trim()).filter(s => /^CVE-/i.test(s));
    if (!cves.length) return;
    setCveLookupLoading(true);
    try {
      const result = await api.bulkCveLookup(cves);
      setCveLookupResult(result);
    } catch { /* ignore */ } finally {
      setCveLookupLoading(false);
    }
  };

  const toggleSort = (col: string) => {
    if (sortBy === col) {
      setSortOrder(sortOrder === "desc" ? "asc" : "desc");
    } else {
      setSortBy(col);
      setSortOrder("desc");
    }
  };

  const SortHeader = ({ col, children }: { col: string; children: React.ReactNode }) => (
    <button
      onClick={() => toggleSort(col)}
      className={cn(
        "flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider hover:text-foreground transition-colors",
        sortBy === col ? "text-primary" : "text-muted-foreground/70",
      )}
    >
      {children}
      <ArrowUpDown className="h-3 w-3" />
    </button>
  );

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/60" />
          <input
            type="text"
            placeholder="Search products, CVEs, vendors..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-card/50 border border-border/50 rounded-md focus:outline-none focus:ring-1 focus:ring-primary/30 focus:border-primary/40"
          />
        </div>
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
          className="text-[11px] bg-card/50 border border-border/50 rounded-md px-2 py-1.5"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        {/* Time window toggle */}
        <div className="flex items-center bg-card/50 border border-border/50 rounded-md overflow-hidden">
          <button
            onClick={() => setWindowMode("24h")}
            className={cn(
              "px-2.5 py-1.5 text-[11px] font-medium transition-colors",
              windowMode === "24h" ? "bg-orange-500/20 text-orange-300" : "text-muted-foreground/60 hover:text-muted-foreground",
            )}
          >
            Last 24H
          </button>
          <button
            onClick={() => setWindowMode("all")}
            className={cn(
              "px-2.5 py-1.5 text-[11px] font-medium transition-colors",
              windowMode === "all" ? "bg-orange-500/20 text-orange-300" : "text-muted-foreground/60 hover:text-muted-foreground",
            )}
          >
            View All
          </button>
        </div>
        <span className="text-[10px] text-muted-foreground/60 ml-auto">
          {data ? `${data.total} products` : ""}
        </span>
        {/* Export buttons */}
        <div className="flex items-center gap-1">
          <button onClick={() => { setCveLookupOpen(!cveLookupOpen); setCveLookupResult(null); }} className={cn("flex items-center gap-1 px-2 py-1 text-[10px] border border-border/50 rounded-md hover:bg-accent/20 transition-colors", cveLookupOpen ? "text-blue-400 border-blue-500/40" : "text-muted-foreground hover:text-foreground")} title="Bulk CVE Lookup"><Search className="h-3 w-3" />CVE Lookup</button>
          <a href={api.getExtractionExportUrl("vulnerable-products", "csv", windowMode)} className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:text-foreground border border-border/50 rounded-md hover:bg-accent/20 transition-colors" title="Export CSV"><FileDown className="h-3 w-3" />CSV</a>
          <a href={api.getExtractionExportUrl("vulnerable-products", "json", windowMode)} className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:text-foreground border border-border/50 rounded-md hover:bg-accent/20 transition-colors" title="Export JSON"><FileCode className="h-3 w-3" />JSON</a>
        </div>
      </div>

      {/* Bulk CVE Lookup Panel */}
      {cveLookupOpen && (
        <div className="mb-3 p-3 bg-card/60 border border-border/40 rounded-lg space-y-2">
          <div className="flex gap-2 items-start">
            <textarea
              value={cveInput}
              onChange={e => setCveInput(e.target.value)}
              placeholder="Paste CVEs (one per line or comma-separated)&#10;CVE-2024-1234, CVE-2023-5678&#10;CVE-2024-9999"
              rows={3}
              className="flex-1 text-[11px] bg-background/60 border border-border/40 rounded-md px-2 py-1.5 resize-none focus:outline-none focus:border-blue-500/50 placeholder:text-muted-foreground/40"
            />
            <button
              onClick={handleCveLookup}
              disabled={cveLookupLoading || !cveInput.trim()}
              className="px-3 py-1.5 text-[10px] font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md disabled:opacity-40 transition-colors"
            >
              {cveLookupLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : "Lookup"}
            </button>
          </div>
          {cveLookupResult && (
            <div className="space-y-2">
              <div className="flex gap-3 text-[10px]">
                <span className="text-muted-foreground">Requested: <span className="text-foreground font-medium">{cveLookupResult.requested}</span></span>
                <span className="text-green-400">Found: {cveLookupResult.found}</span>
                {cveLookupResult.missing.length > 0 && <span className="text-amber-400">Missing: {cveLookupResult.missing.length}</span>}
              </div>
              {cveLookupResult.missing.length > 0 && (
                <div className="text-[10px] text-muted-foreground/60">Not tracked: {cveLookupResult.missing.join(", ")}</div>
              )}
              {Object.keys(cveLookupResult.results).length > 0 && (
                <div className="border border-border/30 rounded overflow-hidden">
                  <table className="w-full text-[10px]">
                    <thead><tr className="bg-muted/30 text-left text-muted-foreground/60">
                      <th className="px-2 py-1">CVE</th><th className="px-2 py-1">Product</th><th className="px-2 py-1">Severity</th><th className="px-2 py-1">CVSS</th><th className="px-2 py-1">EPSS</th><th className="px-2 py-1">KEV</th>
                    </tr></thead>
                    <tbody>
                      {Object.entries(cveLookupResult.results).map(([cve, p]: [string, any]) => (
                        <tr key={cve} className="border-t border-border/20 hover:bg-muted/10">
                          <td className="px-2 py-1 font-mono text-blue-400">{cve}</td>
                          <td className="px-2 py-1">{p.product_name}</td>
                          <td className="px-2 py-1"><Badge variant="outline" className={cn("text-[9px] px-1", p.severity === "critical" ? "border-red-500/40 text-red-400" : p.severity === "high" ? "border-orange-500/40 text-orange-400" : "border-border")}>{p.severity}</Badge></td>
                          <td className="px-2 py-1">{p.cvss_score ?? "—"}</td>
                          <td className="px-2 py-1">{p.epss_score ? `${(p.epss_score * 100).toFixed(1)}%` : "—"}</td>
                          <td className="px-2 py-1">{p.is_kev ? <ShieldAlert className="h-3 w-3 text-red-400" /> : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground/40" />
        </div>
      ) : !data || data.items.length === 0 ? (
        <Card className="card-3d">
          <CardContent className="py-12 text-center">
            <Bug className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              No vulnerable products found{windowMode === "24h" ? " in the last 24 hours" : ""}.
            </p>
            {windowMode === "24h" && (
              <button
                onClick={() => setWindowMode("all")}
                className="mt-2 text-xs text-primary hover:underline"
              >
                View all products →
              </button>
            )}
            <p className="text-xs text-muted-foreground/60 mt-1">Products are extracted automatically from enriched news articles.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-lg border border-border/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-card/80 border-b border-border/30">
                  <th className="text-left px-3 py-2"><SortHeader col="product_name">Product</SortHeader></th>
                  <th className="text-left px-3 py-2 hidden md:table-cell">Vendor</th>
                  <th className="text-left px-3 py-2">CVE</th>
                  <th className="text-center px-3 py-2 hidden lg:table-cell"><SortHeader col="cvss_score">CVSS</SortHeader></th>
                  <th className="text-center px-3 py-2 hidden lg:table-cell"><SortHeader col="epss_score">EPSS</SortHeader></th>
                  <th className="text-center px-3 py-2"><SortHeader col="severity">Severity</SortHeader></th>
                  <th className="text-center px-3 py-2 hidden lg:table-cell">Flags</th>
                  <th className="text-left px-3 py-2 hidden xl:table-cell">Linked Actors</th>
                  <th className="text-left px-3 py-2 hidden xl:table-cell">Sources</th>
                  <th className="text-right px-3 py-2"><SortHeader col="last_seen">Published</SortHeader></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {data.items.map((item) => {
                  const sev = severityBadge(item.severity);
                  const isNew = isNewEntry(item.first_seen);
                  const stale = isStaleEntry(item.last_seen);
                  const expanded = expandedId === item.id;
                  return (
                    <React.Fragment key={item.id}>
                    <tr
                      onClick={() => setExpandedId(expanded ? null : item.id)}
                      className={cn(
                        "hover:bg-accent/10 transition-colors cursor-pointer",
                        stale && "opacity-50",
                        item.is_false_positive && "opacity-40 line-through",
                        expanded && "bg-accent/10",
                      )}
                    >
                      <td className="px-3 py-2 font-medium max-w-[200px]" title={item.product_name}>
                        <div className="flex items-center gap-1.5">
                          <ChevronDown className={cn("h-3 w-3 text-muted-foreground/50 shrink-0 transition-transform", expanded && "rotate-180")} />
                          <span className="truncate">{item.product_name}</span>
                          {isNew && <span className="shrink-0 text-[7px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded px-1">NEW</span>}
                          {stale && <span className="shrink-0 text-[7px] font-bold bg-zinc-500/20 text-zinc-400 border border-zinc-500/30 rounded px-1">STALE</span>}
                          {item.is_false_positive && <span className="shrink-0 text-[7px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded px-1">FP</span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground hidden md:table-cell">{item.vendor || "—"}</td>
                      <td className="px-3 py-2">
                        {item.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:underline font-mono text-[10px]"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {item.cve_id}
                          </a>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-center hidden lg:table-cell">
                        {item.cvss_score != null ? (
                          <span className={cn(
                            "font-mono text-[10px] font-bold",
                            item.cvss_score >= 9 ? "text-red-400" :
                            item.cvss_score >= 7 ? "text-orange-400" :
                            item.cvss_score >= 4 ? "text-yellow-400" : "text-green-400"
                          )}>
                            {item.cvss_score.toFixed(1)}
                          </span>
                        ) : <span className="text-muted-foreground/40">—</span>}
                      </td>
                      <td className="px-3 py-2 text-center hidden lg:table-cell">
                        {item.epss_score != null ? (
                          <span className={cn(
                            "font-mono text-[10px] font-bold",
                            item.epss_score >= 50 ? "text-red-400" :
                            item.epss_score >= 20 ? "text-orange-400" :
                            item.epss_score >= 5 ? "text-yellow-400" : "text-green-400"
                          )}>
                            {item.epss_score.toFixed(1)}%
                          </span>
                        ) : <span className="text-muted-foreground/40">—</span>}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", sev.color)}>
                          {sev.label}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-center hidden lg:table-cell">
                        <div className="flex items-center justify-center gap-1">
                          {item.is_kev && <span title="CISA KEV"><ShieldAlert className="h-3.5 w-3.5 text-red-400" /></span>}
                          {item.exploit_available && <span title="Exploit available"><Zap className="h-3.5 w-3.5 text-amber-400" /></span>}
                          {item.patch_available && <span title="Patch available"><ShieldCheck className="h-3.5 w-3.5 text-green-400" /></span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden xl:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[140px]">
                          {(item.related_campaigns || []).slice(0, 2).map((c) => (
                            <span key={c.id} className="inline-flex items-center gap-0.5 text-[8px] px-1 py-0 rounded border border-red-500/30 text-red-300" title={c.campaign_name || c.actor_name}>
                              <Users className="h-2 w-2" />
                              {c.actor_name}
                            </span>
                          ))}
                          {(item.related_campaigns || []).length > 2 && (
                            <span className="text-[8px] text-muted-foreground/50">+{item.related_campaigns.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden xl:table-cell">
                        <div className="flex flex-col gap-0.5 max-w-[180px]">
                          {(item.source_articles || []).slice(0, 2).map((a) => (
                            <a
                              key={a.id}
                              href={a.source_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-[10px] text-primary hover:underline truncate"
                              title={a.headline}
                              onClick={(e) => e.stopPropagation()}
                            >
                              <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                              <span className="truncate">{a.source}</span>
                            </a>
                          ))}
                          {(item.source_articles || []).length > 2 && (
                            <span className="text-[9px] text-muted-foreground/50">+{item.source_articles.length - 2} more</span>
                          )}
                          {(!item.source_articles || item.source_articles.length === 0) && (
                            <span className="text-[10px] text-muted-foreground/40">{item.source_count} source{item.source_count !== 1 ? "s" : ""}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex flex-col items-end gap-0">
                          <span className="text-muted-foreground text-[10px]">{timeAgo(item.last_seen)}</span>
                          <span className="text-muted-foreground/50 text-[9px]">{formatPublishDate(item.last_seen)}</span>
                        </div>
                      </td>
                    </tr>
                    {/* Expanded detail panel */}
                    {expanded && (
                      <tr className="bg-card/60">
                        <td colSpan={10} className="px-4 py-3">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                            {/* Col 1: Core Details */}
                            <div className="space-y-2">
                              <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">Details</h4>
                              <div className="space-y-1">
                                <div className="flex justify-between"><span className="text-muted-foreground">Confidence</span><Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", item.confidence === "high" ? "border-green-500/30 text-green-300" : item.confidence === "medium" ? "border-yellow-500/30 text-yellow-300" : "border-zinc-500/30 text-zinc-300")}>{item.confidence}</Badge></div>
                                {item.affected_versions && <div className="flex justify-between"><span className="text-muted-foreground">Affected Versions</span><span className="text-foreground text-right max-w-[180px] truncate" title={item.affected_versions}>{item.affected_versions}</span></div>}
                                <div className="flex justify-between"><span className="text-muted-foreground">First Seen</span><span>{formatPublishDate(item.first_seen)}</span></div>
                                <div className="flex justify-between"><span className="text-muted-foreground">Last Seen</span><span>{formatPublishDate(item.last_seen)}</span></div>
                                {item.epss_score != null && (
                                  <div>
                                    <span className="text-muted-foreground">EPSS Probability</span>
                                    <div className="mt-1 h-2 rounded-full bg-muted/30 overflow-hidden">
                                      <div className={cn("h-full rounded-full", item.epss_score >= 50 ? "bg-red-500" : item.epss_score >= 20 ? "bg-orange-500" : item.epss_score >= 5 ? "bg-yellow-500" : "bg-green-500")} style={{ width: `${Math.min(item.epss_score, 100)}%` }} />
                                    </div>
                                    <span className="text-[9px] text-muted-foreground/60">{item.epss_score.toFixed(2)}% chance of exploitation in next 30 days</span>
                                  </div>
                                )}
                              </div>
                            </div>
                            {/* Col 2: Sectors & Regions */}
                            <div className="space-y-2">
                              {item.targeted_sectors.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Targeted Sectors</h4>
                                  <div className="flex gap-1 flex-wrap">{item.targeted_sectors.map((s) => <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/30 text-muted-foreground">{s}</span>)}</div>
                                </div>
                              )}
                              {item.targeted_regions.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Targeted Regions</h4>
                                  <div className="flex gap-1 flex-wrap">{item.targeted_regions.map((r) => <span key={r} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/30 text-muted-foreground">{r}</span>)}</div>
                                </div>
                              )}
                              {(item.related_campaigns || []).length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Linked Threat Actors</h4>
                                  <div className="flex gap-1 flex-wrap">{item.related_campaigns.map((c) => (
                                    <span key={c.id} className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded border border-red-500/30 text-red-300"><Users className="h-2.5 w-2.5" />{c.actor_name}{c.campaign_name ? ` — ${c.campaign_name}` : ""}</span>
                                  ))}</div>
                                </div>
                              )}
                            </div>
                            {/* Col 3: Source Articles */}
                            <div className="space-y-2">
                              <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">Source Articles ({(item.source_articles || []).length})</h4>
                              <div className="space-y-1 max-h-[160px] overflow-y-auto">
                                {(item.source_articles || []).map((a) => (
                                  <a key={a.id} href={a.source_url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="flex items-start gap-1.5 p-1.5 rounded hover:bg-accent/20 transition-colors">
                                    <ExternalLink className="h-3 w-3 text-primary shrink-0 mt-0.5" />
                                    <div className="min-w-0">
                                      <div className="text-[10px] text-foreground truncate">{a.headline}</div>
                                      <div className="text-[9px] text-muted-foreground/50">{a.source}{a.published_at ? ` · ${formatPublishDate(a.published_at)}` : ""}</div>
                                    </div>
                                  </a>
                                ))}
                              </div>
                            </div>
                          </div>
                          {/* False Positive Toggle */}
                          <div className="mt-3 pt-2 border-t border-border/20 flex items-center justify-between">
                            <span className="text-[10px] text-muted-foreground/60">
                              {item.is_false_positive ? "Marked as false positive" : "Is this a false positive?"}
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                const newVal = !item.is_false_positive;
                                api.toggleFalsePositive("vulnerable-products", item.id, newVal).then(() => {
                                  setData(prev => prev ? { ...prev, items: prev.items.map(i => i.id === item.id ? { ...i, is_false_positive: newVal } : i) } : prev);
                                });
                              }}
                              className={cn(
                                "text-[10px] px-2 py-1 rounded-md border transition-colors",
                                item.is_false_positive
                                  ? "bg-amber-500/20 text-amber-300 border-amber-500/30 hover:bg-amber-500/10"
                                  : "text-muted-foreground border-border/40 hover:bg-accent/20"
                              )}
                            >
                              {item.is_false_positive ? "✕ Undo" : "Flag False Positive"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Threat Campaigns Table ────────────────────────────────
function ThreatCampaignsTable() {
  const [data, setData] = useState<ThreatCampaignsListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("last_seen");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [sevFilter, setSevFilter] = useState("");
  const [windowMode, setWindowMode] = useState<"7d" | "all">("7d");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getThreatCampaigns({
        search: search.trim() || undefined,
        severity: sevFilter || undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        limit: 200,
        window: windowMode,
      });
      setData(result);
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [search, sevFilter, sortBy, sortOrder, windowMode]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const toggleSort = (col: string) => {
    if (sortBy === col) {
      setSortOrder(sortOrder === "desc" ? "asc" : "desc");
    } else {
      setSortBy(col);
      setSortOrder("desc");
    }
  };

  const SortHeader = ({ col, children }: { col: string; children: React.ReactNode }) => (
    <button
      onClick={() => toggleSort(col)}
      className={cn(
        "flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider hover:text-foreground transition-colors",
        sortBy === col ? "text-primary" : "text-muted-foreground/70",
      )}
    >
      {children}
      <ArrowUpDown className="h-3 w-3" />
    </button>
  );

  return (
    <div className="space-y-3">
      {/* Campaign Timeline */}
      {data && data.items.length > 0 && (
        <CampaignTimelineWidget campaigns={data.items.map((i) => ({ id: i.id, actor_name: i.actor_name, first_seen: i.first_seen, last_seen: i.last_seen, severity: i.severity }))} />
      )}
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/60" />
          <input
            type="text"
            placeholder="Search actors, campaigns..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-card/50 border border-border/50 rounded-md focus:outline-none focus:ring-1 focus:ring-primary/30 focus:border-primary/40"
          />
        </div>
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
          className="text-[11px] bg-card/50 border border-border/50 rounded-md px-2 py-1.5"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        {/* Time window toggle */}
        <div className="flex items-center bg-card/50 border border-border/50 rounded-md overflow-hidden">
          <button
            onClick={() => setWindowMode("7d")}
            className={cn(
              "px-2.5 py-1.5 text-[11px] font-medium transition-colors",
              windowMode === "7d" ? "bg-red-500/20 text-red-300" : "text-muted-foreground/60 hover:text-muted-foreground",
            )}
          >
            Last 7 Days
          </button>
          <button
            onClick={() => setWindowMode("all")}
            className={cn(
              "px-2.5 py-1.5 text-[11px] font-medium transition-colors",
              windowMode === "all" ? "bg-red-500/20 text-red-300" : "text-muted-foreground/60 hover:text-muted-foreground",
            )}
          >
            View All
          </button>
        </div>
        <span className="text-[10px] text-muted-foreground/60 ml-auto">
          {data ? `${data.total} campaigns` : ""}
        </span>
        {/* Export buttons */}
        <div className="flex items-center gap-1">
          <a href={api.getExtractionExportUrl("threat-campaigns", "csv", windowMode)} className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:text-foreground border border-border/50 rounded-md hover:bg-accent/20 transition-colors" title="Export CSV"><FileDown className="h-3 w-3" />CSV</a>
          <a href={api.getExtractionExportUrl("threat-campaigns", "json", windowMode)} className="flex items-center gap-1 px-2 py-1 text-[10px] text-muted-foreground hover:text-foreground border border-border/50 rounded-md hover:bg-accent/20 transition-colors" title="Export JSON"><FileCode className="h-3 w-3" />JSON</a>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground/40" />
        </div>
      ) : !data || data.items.length === 0 ? (
        <Card className="card-3d">
          <CardContent className="py-12 text-center">
            <Swords className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              No active threat campaigns found{windowMode === "7d" ? " in the last 7 days" : ""}.
            </p>
            {windowMode === "7d" && (
              <button
                onClick={() => setWindowMode("all")}
                className="mt-2 text-xs text-primary hover:underline"
              >
                View all campaigns →
              </button>
            )}
            <p className="text-xs text-muted-foreground/60 mt-1">Campaigns are extracted automatically from enriched news articles.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-lg border border-border/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-card/80 border-b border-border/30">
                  <th className="text-left px-3 py-2"><SortHeader col="actor_name">Threat Actor</SortHeader></th>
                  <th className="text-left px-3 py-2 hidden md:table-cell">Campaign</th>
                  <th className="text-center px-3 py-2"><SortHeader col="severity">Severity</SortHeader></th>
                  <th className="text-left px-3 py-2 hidden lg:table-cell">Malware</th>
                  <th className="text-left px-3 py-2 hidden lg:table-cell">Techniques</th>
                  <th className="text-left px-3 py-2 hidden xl:table-cell">CVEs</th>
                  <th className="text-left px-3 py-2 hidden xl:table-cell">Linked Products</th>
                  <th className="text-left px-3 py-2 hidden xl:table-cell">Targets</th>
                  <th className="text-left px-3 py-2 hidden md:table-cell">Sources</th>
                  <th className="text-right px-3 py-2"><SortHeader col="last_seen">Published</SortHeader></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {data.items.map((item) => {
                  const sev = severityBadge(item.severity);
                  const isNew = isNewEntry(item.first_seen);
                  const stale = isStaleEntry(item.last_seen, 14);
                  const expanded = expandedId === item.id;
                  // Extract MITRE T-codes from techniques_used
                  const parseTechnique = (t: string) => {
                    const m = t.match(/(T\d{4}(?:\.\d{3})?)/);
                    return m ? { code: m[1], label: t } : { code: null, label: t };
                  };
                  return (
                    <React.Fragment key={item.id}>
                    <tr
                      onClick={() => setExpandedId(expanded ? null : item.id)}
                      className={cn(
                        "hover:bg-accent/10 transition-colors cursor-pointer",
                        stale && "opacity-50",
                        item.is_false_positive && "opacity-40 line-through",
                        expanded && "bg-accent/10",
                      )}
                    >
                      <td className="px-3 py-2 font-medium max-w-[160px]" title={item.actor_name}>
                        <div className="flex items-center gap-1.5">
                          <ChevronDown className={cn("h-3 w-3 text-muted-foreground/50 shrink-0 transition-transform", expanded && "rotate-180")} />
                          <Users className="h-3 w-3 text-red-400 shrink-0" />
                          <EntityBadge label={item.actor_name} searchPrefix="actor" className="text-xs font-medium text-foreground hover:text-primary" />
                          {isNew && <span className="shrink-0 text-[7px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded px-1">NEW</span>}
                          {stale && <span className="shrink-0 text-[7px] font-bold bg-zinc-500/20 text-zinc-400 border border-zinc-500/30 rounded px-1">STALE</span>}
                          {item.is_false_positive && <span className="shrink-0 text-[7px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded px-1">FP</span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground hidden md:table-cell max-w-[140px] truncate" title={item.campaign_name || ""}>
                        {item.campaign_name || "—"}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", sev.color)}>
                          {sev.label}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 hidden lg:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[120px]">
                          {item.malware_used.slice(0, 2).map((m) => (
                            <EntityBadge key={m} label={m} searchPrefix="malware" className="text-[8px] px-1 py-0 rounded border border-purple-500/30 text-purple-300 hover:bg-purple-500/10" />
                          ))}
                          {item.malware_used.length > 2 && (
                            <span className="text-[8px] text-muted-foreground/50">+{item.malware_used.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden lg:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[120px]">
                          {item.techniques_used.slice(0, 2).map((t) => {
                            const parsed = parseTechnique(t);
                            return parsed.code ? (
                              <a key={t} href={`https://attack.mitre.org/techniques/${parsed.code.replace(".", "/")}`} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-[8px] px-1 py-0 rounded border border-sky-500/30 text-sky-300 hover:bg-sky-500/10" title={parsed.label}>
                                {parsed.code}
                              </a>
                            ) : (
                              <EntityBadge key={t} label={t} searchPrefix="technique" className="text-[8px] px-1 py-0 rounded border border-sky-500/30 text-sky-300 hover:bg-sky-500/10" />
                            );
                          })}
                          {item.techniques_used.length > 2 && (
                            <span className="text-[8px] text-muted-foreground/50">+{item.techniques_used.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden xl:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[100px]">
                          {item.cves_exploited.slice(0, 2).map((c) => (
                            <a
                              key={c}
                              href={`https://nvd.nist.gov/vuln/detail/${c}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[8px] font-mono text-orange-300 hover:underline"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {c}
                            </a>
                          ))}
                          {item.cves_exploited.length > 2 && (
                            <span className="text-[8px] text-muted-foreground/50">+{item.cves_exploited.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden xl:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[130px]">
                          {(item.related_products || []).slice(0, 2).map((p) => (
                            <span key={p.id} className="inline-flex items-center gap-0.5 text-[8px] px-1 py-0 rounded border border-orange-500/30 text-orange-300" title={`${p.product_name}${p.cve_id ? ` (${p.cve_id})` : ''}`}>
                              <Bug className="h-2 w-2" />
                              {p.product_name.length > 16 ? p.product_name.slice(0, 14) + "…" : p.product_name}
                            </span>
                          ))}
                          {(item.related_products || []).length > 2 && (
                            <span className="text-[8px] text-muted-foreground/50">+{item.related_products.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden xl:table-cell">
                        <div className="flex gap-1 flex-wrap max-w-[100px]">
                          {item.targeted_sectors.slice(0, 2).map((s) => (
                            <span key={s} className="text-[8px] text-muted-foreground">{s}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2 hidden md:table-cell">
                        <div className="flex flex-col gap-0.5 max-w-[180px]">
                          {(item.source_articles || []).slice(0, 2).map((a) => (
                            <a
                              key={a.id}
                              href={a.source_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-[10px] text-primary hover:underline truncate"
                              title={a.headline}
                              onClick={(e) => e.stopPropagation()}
                            >
                              <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                              <span className="truncate">{a.source}</span>
                            </a>
                          ))}
                          {(item.source_articles || []).length > 2 && (
                            <span className="text-[9px] text-muted-foreground/50">+{item.source_articles.length - 2} more</span>
                          )}
                          {(!item.source_articles || item.source_articles.length === 0) && (
                            <span className="text-[10px] text-muted-foreground/40">{item.source_count} source{item.source_count !== 1 ? "s" : ""}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex flex-col items-end gap-0">
                          <span className="text-muted-foreground text-[10px]">{timeAgo(item.last_seen)}</span>
                          <span className="text-muted-foreground/50 text-[9px]">{formatPublishDate(item.last_seen)}</span>
                        </div>
                      </td>
                    </tr>
                    {/* Expanded detail panel */}
                    {expanded && (
                      <tr className="bg-card/60">
                        <td colSpan={10} className="px-4 py-3">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                            {/* Col 1: Campaign Timeline + Details */}
                            <div className="space-y-2">
                              <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">Campaign Details</h4>
                              <div className="space-y-1">
                                <div className="flex justify-between"><span className="text-muted-foreground">Confidence</span><Badge variant="outline" className={cn("text-[9px] h-4 px-1.5 border", item.confidence === "high" ? "border-green-500/30 text-green-300" : item.confidence === "medium" ? "border-yellow-500/30 text-yellow-300" : "border-zinc-500/30 text-zinc-300")}>{item.confidence}</Badge></div>
                                <div className="flex justify-between"><span className="text-muted-foreground">Active Period</span><span>{formatPublishDate(item.first_seen)} — {formatPublishDate(item.last_seen)}</span></div>
                                <div className="flex justify-between"><span className="text-muted-foreground">Sources</span><span>{item.source_count}</span></div>
                              </div>
                              {/* Mini timeline bar */}
                              <div className="mt-2">
                                <div className="flex items-center gap-2 text-[9px] text-muted-foreground/60">
                                  <span>{formatPublishDate(item.first_seen)}</span>
                                  <div className="flex-1 h-1.5 rounded-full bg-muted/30 relative overflow-hidden">
                                    <div className="absolute inset-y-0 left-0 rounded-full bg-red-500/60" style={{ width: "100%" }} />
                                  </div>
                                  <span>{formatPublishDate(item.last_seen)}</span>
                                </div>
                              </div>
                            </div>
                            {/* Col 2: MITRE + Malware + Regions */}
                            <div className="space-y-2">
                              {item.techniques_used.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">MITRE ATT&CK Techniques</h4>
                                  <div className="flex gap-1 flex-wrap">
                                    {item.techniques_used.map((t) => {
                                      const parsed = parseTechnique(t);
                                      return parsed.code ? (
                                        <a key={t} href={`https://attack.mitre.org/techniques/${parsed.code.replace(".", "/")}`} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-[9px] px-1.5 py-0.5 rounded border border-sky-500/30 text-sky-300 hover:bg-sky-500/10">
                                          {parsed.code} — {parsed.label.replace(parsed.code, "").replace(/[:\-–—]\s*/, "").trim() || parsed.code}
                                        </a>
                                      ) : (
                                        <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/30 text-muted-foreground">{t}</span>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}
                              {item.malware_used.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Malware</h4>
                                  <div className="flex gap-1 flex-wrap">{item.malware_used.map((m) => <span key={m} className="text-[9px] px-1.5 py-0.5 rounded border border-purple-500/30 text-purple-300">{m}</span>)}</div>
                                </div>
                              )}
                              {item.targeted_sectors.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Targeted Sectors</h4>
                                  <div className="flex gap-1 flex-wrap">{item.targeted_sectors.map((s) => <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/30 text-muted-foreground">{s}</span>)}</div>
                                </div>
                              )}
                              {item.targeted_regions.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Targeted Regions</h4>
                                  <div className="flex gap-1 flex-wrap">{item.targeted_regions.map((r) => <span key={r} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/30 text-muted-foreground">{r}</span>)}</div>
                                </div>
                              )}
                            </div>
                            {/* Col 3: CVEs + Products + Sources */}
                            <div className="space-y-2">
                              {item.cves_exploited.length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">CVEs Exploited</h4>
                                  <div className="flex gap-1 flex-wrap">{item.cves_exploited.map((c) => (
                                    <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-[9px] font-mono text-orange-300 hover:underline px-1.5 py-0.5 rounded border border-orange-500/30">{c}</a>
                                  ))}</div>
                                </div>
                              )}
                              {(item.related_products || []).length > 0 && (
                                <div>
                                  <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider mb-1">Linked Products</h4>
                                  <div className="flex gap-1 flex-wrap">{item.related_products.map((p) => (
                                    <span key={p.id} className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded border border-orange-500/30 text-orange-300"><Bug className="h-2.5 w-2.5" />{p.product_name}{p.cve_id ? ` (${p.cve_id})` : ""}</span>
                                  ))}</div>
                                </div>
                              )}
                              <h4 className="font-semibold text-muted-foreground uppercase text-[10px] tracking-wider">Source Articles ({(item.source_articles || []).length})</h4>
                              <div className="space-y-1 max-h-[120px] overflow-y-auto">
                                {(item.source_articles || []).map((a) => (
                                  <a key={a.id} href={a.source_url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="flex items-start gap-1.5 p-1.5 rounded hover:bg-accent/20 transition-colors">
                                    <ExternalLink className="h-3 w-3 text-primary shrink-0 mt-0.5" />
                                    <div className="min-w-0">
                                      <div className="text-[10px] text-foreground truncate">{a.headline}</div>
                                      <div className="text-[9px] text-muted-foreground/50">{a.source}{a.published_at ? ` · ${formatPublishDate(a.published_at)}` : ""}</div>
                                    </div>
                                  </a>
                                ))}
                              </div>
                            </div>
                          </div>
                          {/* False Positive Toggle */}
                          <div className="mt-3 pt-2 border-t border-border/20 flex items-center justify-between">
                            <span className="text-[10px] text-muted-foreground/60">
                              {item.is_false_positive ? "Marked as false positive" : "Is this a false positive?"}
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                const newVal = !item.is_false_positive;
                                api.toggleFalsePositive("threat-campaigns", item.id, newVal).then(() => {
                                  setData(prev => prev ? { ...prev, items: prev.items.map(i => i.id === item.id ? { ...i, is_false_positive: newVal } : i) } : prev);
                                });
                              }}
                              className={cn(
                                "text-[10px] px-2 py-1 rounded-md border transition-colors",
                                item.is_false_positive
                                  ? "bg-amber-500/20 text-amber-300 border-amber-500/30 hover:bg-amber-500/10"
                                  : "text-muted-foreground border-border/40 hover:bg-accent/20"
                              )}
                            >
                              {item.is_false_positive ? "✕ Undo" : "Flag False Positive"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
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
  const [newsStats, setNewsStats] = useState<NewsStatsResponse | null>(null);
  const [pipelineStatus, setPipelineStatus] = useState<NewsPipelineStatus | null>(null);
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
  const [activeSubtopic, setActiveSubtopic] = useState<Subtopic>("news");
  const [extractionStats, setExtractionStats] = useState<ExtractionStatsResponse | null>(null);

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

  const fetchStats = useCallback(async () => {
    try {
      const data = await api.getNewsStats();
      setNewsStats(data);
    } catch { /* ignore */ }
  }, []);

  const fetchExtractionStats = useCallback(async () => {
    try {
      const data = await api.getExtractionStats();
      setExtractionStats(data);
    } catch { /* ignore */ }
  }, []);

  const fetchPipelineStatus = useCallback(async () => {
    try {
      const data = await api.getNewsPipelineStatus();
      setPipelineStatus(data);
    } catch { /* ignore */ }
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

  useEffect(() => { fetchCategories(); fetchStats(); fetchExtractionStats(); }, [fetchCategories, fetchStats, fetchExtractionStats]);
  useEffect(() => { fetchNews(); }, [fetchNews]);
  useEffect(() => { fetchPipelineStatus(); }, [fetchPipelineStatus]);

  // Auto-refresh every 60s
  useEffect(() => {
    autoRefreshRef.current = setInterval(() => {
      fetchNews(true);
      fetchCategories();
      fetchStats();
      fetchPipelineStatus();
      fetchExtractionStats();
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
        fetchStats();
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
            {pipelineStatus?.status === "ok" ? (
              <div className="flex items-center gap-1 text-[9px] text-muted-foreground/40" title="Auto-refreshes every 60s">
                <Activity className="h-3 w-3 text-emerald-500 animate-pulse" />
                <span className="hidden sm:inline">Live</span>
              </div>
            ) : pipelineStatus?.status === "stale" ? (
              <div className="flex items-center gap-1 text-[9px] text-yellow-400" title="No new articles in the last hour">
                <AlertTriangle className="h-3 w-3" />
                <span className="hidden sm:inline">Stale</span>
              </div>
            ) : pipelineStatus?.status === "degraded" || pipelineStatus?.status === "down" ? (
              <div className="flex items-center gap-1 text-[9px] text-red-400" title="Pipeline issues detected">
                <AlertTriangle className="h-3 w-3" />
                <span className="hidden sm:inline">{pipelineStatus.status === "down" ? "Down" : "Degraded"}</span>
              </div>
            ) : (
              <div className="flex items-center gap-1 text-[9px] text-muted-foreground/40" title="Auto-refreshes every 60s">
                <Activity className="h-3 w-3 text-emerald-500 animate-pulse" />
                <span className="hidden sm:inline">Live</span>
              </div>
            )}
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
        <QuickStatsBar
          categories={categories}
          stats={newsStats}
          onFilterCategory={(cat) => { setSelectedCategory(cat); setPage(1); }}
          onSortBy={(sort) => { setSortKey(sort); setPage(1); }}
        />

        {/* ── Subtopic Tabs ─────────────────────────── */}
        <div className="flex items-center gap-0 bg-card/60 border border-border/40 rounded-lg p-0.5">
          {SUBTOPIC_META.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeSubtopic === tab.id;
            const count = tab.id === "vulnerable-products"
              ? extractionStats?.vulnerable_products_count
              : tab.id === "threat-campaigns"
                ? extractionStats?.threat_campaigns_count
                : categories?.total ?? null;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubtopic(tab.id)}
                className={cn(
                  "relative flex items-center justify-center gap-2 flex-1 px-4 py-2 rounded-md text-xs font-semibold transition-all duration-200",
                  isActive
                    ? `${tab.bg} ${tab.color} shadow-sm border ${tab.border}`
                    : "text-muted-foreground/60 hover:text-muted-foreground hover:bg-accent/20",
                )}
              >
                <Icon className={cn("h-4 w-4", isActive ? tab.color : "")} />
                <span>{tab.label}</span>
                {count != null && (
                  <span className={cn(
                    "text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[24px] text-center",
                    isActive
                      ? `${tab.bg} ${tab.color} border ${tab.border}`
                      : "bg-muted/40 text-muted-foreground/70",
                  )}>
                    {count}
                  </span>
                )}
                {isActive && (
                  <span className={cn(
                    "absolute bottom-0 left-1/2 -translate-x-1/2 w-8 h-0.5 rounded-full",
                    tab.id === "news" ? "bg-primary" : tab.id === "vulnerable-products" ? "bg-orange-400" : "bg-red-400",
                  )} />
                )}
              </button>
            );
          })}
        </div>

        {/* ── Pipeline Status Banner ────────────────── */}
        {pipelineStatus && pipelineStatus.status !== "ok" && (
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium border",
            pipelineStatus.status === "down"
              ? "bg-red-500/10 border-red-500/30 text-red-400"
              : pipelineStatus.status === "degraded"
                ? "bg-orange-500/10 border-orange-500/30 text-orange-400"
                : "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
          )}>
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>
              {pipelineStatus.status === "down"
                ? "News pipeline is down — all feed sources are failing"
                : pipelineStatus.status === "degraded"
                  ? `News pipeline degraded — ${pipelineStatus.total_sources_failing} sources failing, no new articles in the last hour`
                  : `No new cyber news in the last hour (${pipelineStatus.stored_last_24h} in last 24h)`}
            </span>
            {pipelineStatus.last_article_at && (
              <span className="text-muted-foreground ml-auto shrink-0">
                Last article: {timeAgo(pipelineStatus.last_article_at)}
              </span>
            )}
          </div>
        )}
      </div>

      {/* ── Main area ───────────────────────────────── */}
      {activeSubtopic === "vulnerable-products" ? (
        <div className="flex-1 overflow-y-auto scrollbar-thin p-4">
          <VendorStatsWidget />
          <VulnerableProductsTable />
        </div>
      ) : activeSubtopic === "threat-campaigns" ? (
        <div className="flex-1 overflow-y-auto scrollbar-thin p-4">
          <ThreatCampaignsTable />
        </div>
      ) : (
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
      )}
    </div>
  );
}
