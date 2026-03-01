"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAppStore } from "@/store";
import { Pagination } from "@/components/Pagination";
import { Loading } from "@/components/Loading";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { StatCard } from "@/components/StatCard";
import type { Report, ReportStatus, ReportType } from "@/types";
import {
  FileText,
  Plus,
  Filter,
  RefreshCw,
  Search,
  ChevronRight,
  Clock,
  CheckCircle,
  Eye,
  Archive,
  AlertTriangle,
  Shield,
  FileWarning,
  BarChart3,
  Layers,
} from "lucide-react";

const STATUS_CONFIG: Record<ReportStatus, { label: string; color: string; icon: React.ElementType }> = {
  draft: { label: "Draft", color: "bg-gray-500/10 text-gray-400 border-gray-500/20", icon: Clock },
  review: { label: "In Review", color: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: Eye },
  published: { label: "Published", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: CheckCircle },
  archived: { label: "Archived", color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", icon: Archive },
};

const TYPE_CONFIG: Record<ReportType, { label: string; icon: React.ElementType }> = {
  incident: { label: "Incident Report", icon: AlertTriangle },
  threat_advisory: { label: "Threat Advisory", icon: Shield },
  weekly_summary: { label: "Weekly Summary", icon: BarChart3 },
  ioc_bulletin: { label: "IOC Bulletin", icon: FileWarning },
  custom: { label: "Custom Report", icon: FileText },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-cyan-400",
};

export default function ReportsPage() {
  const router = useRouter();
  const {
    reports,
    reportsTotal,
    reportsPage,
    reportsPages,
    reportsLoading,
    reportStats,
    fetchReports,
    fetchReportStats,
  } = useAppStore();

  const [showFilters, setShowFilters] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    fetchReports({ page: 1 });
    fetchReportStats();
  }, [fetchReports, fetchReportStats]);

  const handlePageChange = useCallback(
    (page: number) => {
      fetchReports({
        page,
        status: statusFilter || undefined,
        report_type: typeFilter || undefined,
        search: searchTerm || undefined,
      });
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
    [fetchReports, statusFilter, typeFilter, searchTerm]
  );

  const applyFilters = () => {
    fetchReports({
      page: 1,
      status: statusFilter || undefined,
      report_type: typeFilter || undefined,
      search: searchTerm || undefined,
    });
  };

  const clearFilters = () => {
    setStatusFilter("");
    setTypeFilter("");
    setSearchTerm("");
    fetchReports({ page: 1 });
  };

  const draftCount = reportStats?.by_status?.draft ?? 0;
  const publishedCount = reportStats?.by_status?.published ?? 0;
  const reviewCount = reportStats?.by_status?.review ?? 0;

  return (
    <div className="p-4 md:p-6 space-y-4 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Reports</h1>
            <p className="text-sm text-muted-foreground">
              {reportStats
                ? `${reportStats.total_reports} reports`
                : "Loading..."}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              fetchReports({ page: reportsPage });
              fetchReportStats();
            }}
            disabled={reportsLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${reportsLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter className="h-4 w-4 mr-1" />
            Filters
          </Button>
          <Button
            size="sm"
            onClick={() => router.push("/reports/new")}
          >
            <Plus className="h-4 w-4 mr-1" />
            New Report
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          title="Total"
          value={reportStats?.total_reports ?? 0}
          icon={<FileText className="h-4 w-4" />}
        />
        <StatCard
          title="Drafts"
          value={draftCount}
          icon={<Clock className="h-4 w-4" />}
        />
        <StatCard
          title="In Review"
          value={reviewCount}
          icon={<Eye className="h-4 w-4" />}
        />
        <StatCard
          title="Published"
          value={publishedCount}
          icon={<CheckCircle className="h-4 w-4" />}
        />
      </div>

      {/* Filters */}
      {showFilters && (
        <Card>
          <CardContent className="p-4 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* Search */}
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Search</label>
                <div className="relative">
                  <Search className="h-4 w-4 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search titles..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && applyFilters()}
                    className="w-full pl-8 pr-3 py-1.5 rounded-md border bg-background text-sm"
                  />
                </div>
              </div>

              {/* Status */}
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Status</label>
                <div className="flex flex-wrap gap-1">
                  {(["draft", "review", "published", "archived"] as ReportStatus[]).map((s) => {
                    const cfg = STATUS_CONFIG[s];
                    return (
                      <Badge
                        key={s}
                        variant="outline"
                        className={`cursor-pointer text-xs ${statusFilter === s ? cfg.color : ""}`}
                        onClick={() => setStatusFilter(statusFilter === s ? "" : s)}
                      >
                        {cfg.label}
                      </Badge>
                    );
                  })}
                </div>
              </div>

              {/* Type */}
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Type</label>
                <div className="flex flex-wrap gap-1">
                  {(["incident", "threat_advisory", "weekly_summary", "ioc_bulletin", "custom"] as ReportType[]).map((t) => {
                    const cfg = TYPE_CONFIG[t];
                    return (
                      <Badge
                        key={t}
                        variant="outline"
                        className={`cursor-pointer text-xs ${typeFilter === t ? "bg-primary/10 text-primary border-primary/20" : ""}`}
                        onClick={() => setTypeFilter(typeFilter === t ? "" : t)}
                      >
                        {cfg.label}
                      </Badge>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear
              </Button>
              <Button size="sm" onClick={applyFilters}>
                Apply
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Report List */}
      {reportsLoading && reports.length === 0 ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-24 rounded-lg bg-card animate-pulse" />
          ))}
        </div>
      ) : reports.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center">
            <FileText className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-medium mb-1">No reports yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Create your first threat intelligence report
            </p>
            <Button onClick={() => router.push("/reports/new")}>
              <Plus className="h-4 w-4 mr-1" />
              New Report
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {reports.map((report) => (
            <ReportRow
              key={report.id}
              report={report}
              onClick={() => router.push(`/reports/${report.id}`)}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {reportsPages > 1 && (
        <Pagination
          page={reportsPage}
          pages={reportsPages}
          onPageChange={handlePageChange}
        />
      )}
    </div>
  );
}

function ReportRow({ report, onClick }: { report: Report; onClick: () => void }) {
  const statusCfg = STATUS_CONFIG[report.status];
  const typeCfg = TYPE_CONFIG[report.report_type];
  const StatusIcon = statusCfg.icon;
  const TypeIcon = typeCfg.icon;

  const updatedAt = new Date(report.updated_at);
  const timeAgo = getTimeAgo(updatedAt);

  const linkedTotal = report.linked_intel_count + report.linked_ioc_count + report.linked_technique_count;

  return (
    <Card
      className="cursor-pointer hover:border-primary/30 transition-colors group"
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            {/* Title & Type */}
            <div className="flex items-center gap-2 mb-1">
              <TypeIcon className="h-4 w-4 text-muted-foreground shrink-0" />
              <h3 className="font-medium text-sm truncate">{report.title}</h3>
            </div>

            {/* Metadata row */}
            <div className="flex items-center flex-wrap gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${statusCfg.color}`}>
                <StatusIcon className="h-3 w-3 mr-0.5" />
                {statusCfg.label}
              </Badge>
              <span className={`font-medium ${SEVERITY_COLORS[report.severity] || ""}`}>
                {report.severity.toUpperCase()}
              </span>
              <span>•</span>
              <span>{typeCfg.label}</span>
              <span>•</span>
              <span>{report.tlp}</span>
              {linkedTotal > 0 && (
                <>
                  <span>•</span>
                  <span className="flex items-center gap-0.5">
                    <Layers className="h-3 w-3" />
                    {linkedTotal} linked
                  </span>
                </>
              )}
              {report.tags.length > 0 && (
                <>
                  <span>•</span>
                  {report.tags.slice(0, 3).map((tag) => (
                    <Badge key={tag} variant="outline" className="text-[10px] px-1 py-0">
                      {tag}
                    </Badge>
                  ))}
                </>
              )}
            </div>

            {/* Summary preview */}
            {report.summary && (
              <p className="text-xs text-muted-foreground mt-1 line-clamp-1">
                {report.summary}
              </p>
            )}
          </div>

          {/* Right: time + arrow */}
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs text-muted-foreground">{timeAgo}</span>
            <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHrs = Math.floor(diffMins / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}
