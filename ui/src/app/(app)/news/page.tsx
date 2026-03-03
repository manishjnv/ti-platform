"use client";

import React, { useEffect, useState, useCallback } from "react";
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
  Shield,
  Zap,
  Globe,
  Bug,
  Cloud,
  Factory,
  FlaskConical,
  Wrench,
  Scale,
  Crosshair,
  Tag,
  AlertTriangle,
  Sparkles,
  Filter,
  SortDesc,
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
  { label: string; icon: React.ElementType; color: string; bg: string }
> = {
  active_threats: {
    label: "Active Threats",
    icon: AlertTriangle,
    color: "text-red-400",
    bg: "bg-red-500/10",
  },
  exploited_vulnerabilities: {
    label: "Exploited Vulnerabilities",
    icon: Bug,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
  },
  ransomware_breaches: {
    label: "Ransomware & Breaches",
    icon: Shield,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
  },
  nation_state: {
    label: "Nation-State Activity",
    icon: Globe,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
  },
  cloud_identity: {
    label: "Cloud & Identity",
    icon: Cloud,
    color: "text-sky-400",
    bg: "bg-sky-500/10",
  },
  ot_ics: {
    label: "OT / ICS",
    icon: Factory,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
  },
  security_research: {
    label: "Security Research",
    icon: FlaskConical,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
  },
  tools_technology: {
    label: "Tools & Technology",
    icon: Wrench,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
  },
  policy_regulation: {
    label: "Policy & Regulation",
    icon: Scale,
    color: "text-teal-400",
    bg: "bg-teal-500/10",
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

function relevanceBadge(score: number) {
  if (score >= 80) return { color: "bg-red-500/20 text-red-300 border-red-500/30", label: "Critical" };
  if (score >= 60) return { color: "bg-orange-500/20 text-orange-300 border-orange-500/30", label: "High" };
  if (score >= 40) return { color: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30", label: "Medium" };
  return { color: "bg-green-500/20 text-green-300 border-green-500/30", label: "Low" };
}

// ── Skeleton loaders ─────────────────────────────────────
function CategoryWidgetSkeleton() {
  return (
    <div className="rounded-lg border border-border/50 bg-card/50 p-3 animate-pulse">
      <div className="flex items-center gap-2 mb-2">
        <div className="h-6 w-6 rounded bg-muted/40" />
        <div className="h-4 w-24 rounded bg-muted/40" />
        <div className="ml-auto h-5 w-8 rounded bg-muted/40" />
      </div>
      <div className="h-3 w-full rounded bg-muted/30 mb-1.5" />
      <div className="h-3 w-2/3 rounded bg-muted/30" />
    </div>
  );
}

function NewsCardSkeleton() {
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

// ── Category Widget ──────────────────────────────────────
function CategoryWidget({
  cat,
  count,
  active,
  onClick,
}: {
  cat: NewsCategory;
  count: NewsCategoryCount | undefined;
  active: boolean;
  onClick: () => void;
}) {
  const meta = CATEGORY_META[cat];
  const Icon = meta.icon;
  const c = count?.count || 0;

  return (
    <button
      onClick={onClick}
      className={cn(
        "card-3d w-full text-left rounded-lg border p-3 transition-all duration-200",
        active
          ? `border-primary/50 bg-primary/5 ring-1 ring-primary/20`
          : "border-border/50 bg-card/50 hover:border-border hover:bg-card/80"
      )}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <div className={cn("h-6 w-6 rounded flex items-center justify-center", meta.bg)}>
          <Icon className={cn("h-3.5 w-3.5", meta.color)} />
        </div>
        <span className="text-xs font-medium truncate flex-1">{meta.label}</span>
        <Badge variant="outline" className="text-[10px] h-5 px-1.5 shrink-0">
          {c}
        </Badge>
      </div>
      {count?.latest_headline && (
        <p className="text-[11px] text-muted-foreground line-clamp-2 leading-relaxed">
          {count.latest_headline}
        </p>
      )}
      {count?.latest_published_at && (
        <p className="text-[10px] text-muted-foreground/60 mt-1">
          {timeAgo(count.latest_published_at)}
        </p>
      )}
    </button>
  );
}

// ── News Card ────────────────────────────────────────────
function NewsCard({ item }: { item: NewsItem }) {
  const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
  const Icon = meta.icon;
  const rel = relevanceBadge(item.relevance_score);

  return (
    <Link href={`/news/${item.id}`}>
      <div className="card-3d rounded-lg border border-border/50 bg-card/50 p-4 hover:border-border hover:bg-card/80 transition-all duration-200 cursor-pointer group">
        <div className="flex items-start gap-3">
          {/* Category icon */}
          <div className={cn("h-8 w-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5", meta.bg)}>
            <Icon className={cn("h-4 w-4", meta.color)} />
          </div>

          <div className="flex-1 min-w-0">
            {/* Headline */}
            <h3 className="text-sm font-semibold leading-snug line-clamp-2 group-hover:text-primary transition-colors">
              {item.headline}
            </h3>

            {/* Source + time */}
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1.5">
              <span className="font-medium">{item.source}</span>
              <span className="text-muted-foreground/40">•</span>
              <Clock className="h-3 w-3" />
              <span title={item.published_at || undefined}>
                {formatPublishDate(item.published_at)}
              </span>
              <span className="text-muted-foreground/50">
                ({timeAgo(item.published_at)})
              </span>
              {item.ai_enriched && (
                <>
                  <span className="text-muted-foreground/40">•</span>
                  <Sparkles className="h-3 w-3 text-yellow-400" />
                  <span className="text-yellow-400/80">AI</span>
                </>
              )}
            </p>

            {/* Summary */}
            {item.summary && (
              <p className="text-xs text-muted-foreground/80 mt-2 line-clamp-2 leading-relaxed">
                {item.summary}
              </p>
            )}

            {/* Tags + relevance */}
            <div className="flex items-center gap-2 mt-2.5 flex-wrap">
              {/* Relevance badge */}
              <Badge variant="outline" className={cn("text-[10px] h-5 px-1.5 border", rel.color)}>
                {item.relevance_score}
              </Badge>

              {/* Category badge */}
              <Badge variant="outline" className="text-[10px] h-5 px-1.5">
                {meta.label}
              </Badge>

              {/* Tags (max 3) */}
              {item.tags.slice(0, 3).map((tag) => (
                <Badge
                  key={tag}
                  variant="outline"
                  className="text-[10px] h-5 px-1.5 border-border/50 text-muted-foreground"
                >
                  {tag}
                </Badge>
              ))}

              {/* CVEs */}
              {item.cves.slice(0, 2).map((cve) => (
                <Badge
                  key={cve}
                  variant="outline"
                  className="text-[10px] h-5 px-1.5 border-red-500/30 text-red-400"
                >
                  {cve}
                </Badge>
              ))}

              {/* Threat actors */}
              {item.threat_actors.slice(0, 1).map((ta) => (
                <Badge
                  key={ta}
                  variant="outline"
                  className="text-[10px] h-5 px-1.5 border-purple-500/30 text-purple-400"
                >
                  {ta}
                </Badge>
              ))}
            </div>
          </div>

          {/* Chevron */}
          <ChevronRight className="h-4 w-4 text-muted-foreground/40 shrink-0 mt-1 group-hover:text-muted-foreground transition-colors" />
        </div>
      </div>
    </Link>
  );
}

// ── Main Page ────────────────────────────────────────────
export default function CyberNewsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [news, setNews] = useState<NewsListResponse | null>(null);
  const [categories, setCategories] = useState<NewsCategoriesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [catLoading, setCatLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [page, setPage] = useState(1);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(
    searchParams.get("category") || null
  );
  const [searchQuery, setSearchQuery] = useState(searchParams.get("q") || "");
  const [sortKey, setSortKey] = useState("published_at:desc");
  const [selectedTag, setSelectedTag] = useState<string | null>(
    searchParams.get("tag") || null
  );

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

  const fetchNews = useCallback(async () => {
    setLoading(true);
    try {
      const [field, dir] = sortKey.split(":");
      const params: Record<string, string | number | boolean | undefined> = {
        page,
        page_size: 20,
        sort_by: field,
        sort_order: dir,
        ai_enriched: true,    // Only show AI-enriched articles with full analysis
      };
      if (selectedCategory) params.category = selectedCategory;
      if (searchQuery.trim()) params.search = searchQuery.trim();
      if (selectedTag) params.tag = selectedTag;

      const data = await api.getNews(params);
      setNews(data);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, [page, selectedCategory, searchQuery, selectedTag, sortKey]);

  useEffect(() => {
    fetchCategories();
  }, [fetchCategories]);

  useEffect(() => {
    fetchNews();
  }, [fetchNews]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await api.refreshNews();
      // Wait a moment then reload
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
    if (selectedCategory === cat) {
      setSelectedCategory(null);
    } else {
      setSelectedCategory(cat);
    }
    setPage(1);
  };

  const handleTagClick = (tag: string) => {
    setSelectedTag(selectedTag === tag ? null : tag);
    setPage(1);
  };

  // Count total by category
  const catCountMap = new Map<string, NewsCategoryCount>();
  categories?.categories.forEach((c) => catCountMap.set(c.category, c));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Newspaper className="h-6 w-6 text-primary" />
            Cyber News
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Structured intelligence from cybersecurity news sources
            {categories && (
              <span className="ml-1">
                — <span className="font-medium text-foreground">{categories.total}</span> articles
              </span>
            )}
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="icon-btn-3d flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-border/50 hover:border-primary/40 transition-all"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
          Refresh
        </button>
      </div>

      <div className="flex gap-6">
        {/* ── Left: Category Widgets ──────────────────── */}
        <div className="w-64 shrink-0 space-y-2 hidden lg:block">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/70 px-1 mb-2">
            Categories
          </h2>

          {/* All button */}
          <button
            onClick={() => {
              setSelectedCategory(null);
              setPage(1);
            }}
            className={cn(
              "card-3d w-full text-left rounded-lg border p-3 transition-all duration-200",
              !selectedCategory
                ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                : "border-border/50 bg-card/50 hover:border-border hover:bg-card/80"
            )}
          >
            <div className="flex items-center gap-2">
              <div className="h-6 w-6 rounded flex items-center justify-center bg-primary/10">
                <Newspaper className="h-3.5 w-3.5 text-primary" />
              </div>
              <span className="text-xs font-medium">All News</span>
              <Badge variant="outline" className="text-[10px] h-5 px-1.5 ml-auto shrink-0">
                {categories?.total || 0}
              </Badge>
            </div>
          </button>

          {catLoading
            ? Array.from({ length: 5 }).map((_, i) => <CategoryWidgetSkeleton key={i} />)
            : ALL_CATEGORIES.map((cat) => (
                <CategoryWidget
                  key={cat}
                  cat={cat}
                  count={catCountMap.get(cat)}
                  active={selectedCategory === cat}
                  onClick={() => handleCategoryClick(cat)}
                />
              ))}
        </div>

        {/* ── Right: News Feed ────────────────────────── */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* Search + filters bar */}
          <div className="flex items-center gap-3">
            {/* Search */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60" />
              <input
                type="text"
                placeholder="Search headlines..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="w-full pl-9 pr-4 py-2 text-sm bg-card/50 border border-border/50 rounded-lg focus:outline-none focus:ring-1 focus:ring-primary/30 focus:border-primary/40"
              />
            </div>

            {/* Mobile category selector */}
            <select
              value={selectedCategory || ""}
              onChange={(e) => {
                setSelectedCategory(e.target.value || null);
                setPage(1);
              }}
              className="lg:hidden text-xs bg-card/50 border border-border/50 rounded-md px-2 py-2"
            >
              <option value="">All Categories</option>
              {ALL_CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>
                  {CATEGORY_META[cat].label}
                </option>
              ))}
            </select>

            {/* Sort */}
            <select
              value={sortKey}
              onChange={(e) => {
                setSortKey(e.target.value);
                setPage(1);
              }}
              className="text-xs bg-card/50 border border-border/50 rounded-md px-2 py-2"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          {/* Active filters */}
          {(selectedCategory || selectedTag) && (
            <div className="flex items-center gap-2 flex-wrap">
              <Filter className="h-3.5 w-3.5 text-muted-foreground/60" />
              {selectedCategory && (
                <Badge
                  variant="outline"
                  className="text-[10px] h-5 px-2 cursor-pointer hover:border-red-500/40"
                  onClick={() => {
                    setSelectedCategory(null);
                    setPage(1);
                  }}
                >
                  {CATEGORY_META[selectedCategory as NewsCategory]?.label || selectedCategory} ×
                </Badge>
              )}
              {selectedTag && (
                <Badge
                  variant="outline"
                  className="text-[10px] h-5 px-2 cursor-pointer hover:border-red-500/40"
                  onClick={() => {
                    setSelectedTag(null);
                    setPage(1);
                  }}
                >
                  tag: {selectedTag} ×
                </Badge>
              )}
            </div>
          )}

          {/* News list */}
          {loading ? (
            <div className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <NewsCardSkeleton key={i} />
              ))}
            </div>
          ) : !news || news.items.length === 0 ? (
            <Card className="card-3d">
              <CardContent className="py-12 text-center">
                <Newspaper className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">
                  No news articles found.
                  {selectedCategory && " Try a different category or clear filters."}
                </p>
                <button
                  onClick={handleRefresh}
                  className="mt-3 text-xs text-primary hover:underline"
                >
                  Refresh feeds
                </button>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Top 5 critical (when no filters) */}
              {!selectedCategory && !searchQuery && !selectedTag && page === 1 && (
                <div className="mb-4">
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/70 mb-2 flex items-center gap-1.5">
                    <Zap className="h-3.5 w-3.5 text-yellow-400" />
                    Top Critical
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                    {news.items
                      .filter((n) => n.relevance_score >= 70)
                      .slice(0, 5)
                      .map((item) => {
                        const meta = CATEGORY_META[item.category] || CATEGORY_META.active_threats;
                        const Icon = meta.icon;
                        return (
                          <Link key={`top-${item.id}`} href={`/news/${item.id}`}>
                            <div className="card-3d rounded-lg border border-border/50 bg-card/50 p-3 hover:border-primary/30 transition-all cursor-pointer group">
                              <div className="flex items-start gap-2">
                                <div className={cn("h-6 w-6 rounded flex items-center justify-center shrink-0", meta.bg)}>
                                  <Icon className={cn("h-3 w-3", meta.color)} />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <h4 className="text-xs font-semibold line-clamp-2 group-hover:text-primary transition-colors">
                                    {item.headline}
                                  </h4>
                                  <p className="text-[10px] text-muted-foreground mt-1">
                                    {item.source} • {formatPublishDate(item.published_at)} ({timeAgo(item.published_at)})
                                  </p>
                                </div>
                                <Badge
                                  variant="outline"
                                  className={cn(
                                    "text-[10px] h-5 px-1.5 shrink-0 border",
                                    relevanceBadge(item.relevance_score).color
                                  )}
                                >
                                  {item.relevance_score}
                                </Badge>
                              </div>
                            </div>
                          </Link>
                        );
                      })}
                  </div>
                </div>
              )}

              {/* Main news list */}
              <div className="space-y-2">
                {news.items.map((item) => (
                  <NewsCard key={item.id} item={item} />
                ))}
              </div>

              {/* Pagination */}
              {news.pages > 1 && (
                <Pagination
                  page={page}
                  pages={news.pages}
                  onPageChange={setPage}
                />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
