"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Report, ReportItem, ReportStatus, ReportType, Severity } from "@/types";
import * as api from "@/lib/api";
import {
  ArrowLeft,
  Save,
  Sparkles,
  FileText,
  AlertTriangle,
  Shield,
  BarChart3,
  FileWarning,
  Loader2,
  Download,
  Trash2,
  Clock,
  CheckCircle,
  Eye,
  Archive,
  Layers,
  Link2,
  X,
  Send,
  Edit3,
} from "lucide-react";

const STATUS_CONFIG: Record<ReportStatus, { label: string; color: string; icon: React.ElementType; next?: ReportStatus }> = {
  draft: { label: "Draft", color: "bg-gray-500/10 text-gray-400 border-gray-500/20", icon: Clock, next: "review" },
  review: { label: "In Review", color: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: Eye, next: "published" },
  published: { label: "Published", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: CheckCircle, next: "archived" },
  archived: { label: "Archived", color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", icon: Archive },
};

const TYPE_LABELS: Record<ReportType, string> = {
  incident: "Incident Report",
  threat_advisory: "Threat Advisory",
  weekly_summary: "Weekly Summary",
  ioc_bulletin: "IOC Bulletin",
  custom: "Custom Report",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  info: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
};

const TLP_COLORS: Record<string, string> = {
  "TLP:RED": "bg-red-500/10 text-red-400 border-red-500/20",
  "TLP:AMBER+STRICT": "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "TLP:AMBER": "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "TLP:GREEN": "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  "TLP:CLEAR": "bg-zinc-500/10 text-zinc-300 border-zinc-500/20",
};

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low", "info"];
const TLP_OPTIONS = ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"];

export default function ReportDetailPage() {
  const router = useRouter();
  const params = useParams();
  const reportId = params.id as string;

  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Edit state
  const [editTitle, setEditTitle] = useState("");
  const [editSeverity, setEditSeverity] = useState<Severity>("medium");
  const [editTlp, setEditTlp] = useState("TLP:GREEN");
  const [editTags, setEditTags] = useState("");
  const [editSections, setEditSections] = useState<Array<{ key: string; title: string; hint?: string; body: string }>>([]);

  const fetchReport = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getReport(reportId);
      setReport(data);
      // Sync edit state
      setEditTitle(data.title);
      setEditSeverity(data.severity);
      setEditTlp(data.tlp);
      setEditTags(data.tags.join(", "));
      setEditSections(data.content?.sections || []);
    } catch (e: any) {
      setError(e.message || "Failed to load report");
    }
    setLoading(false);
  }, [reportId]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  const handleSave = async () => {
    if (!report) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateReport(reportId, {
        title: editTitle.trim(),
        severity: editSeverity,
        tlp: editTlp,
        tags: editTags.split(",").map((t) => t.trim()).filter(Boolean),
        content: { sections: editSections },
      });
      setReport(updated);
      setEditing(false);
    } catch (e: any) {
      setError(e.message || "Failed to save");
    }
    setSaving(false);
  };

  const handleStatusChange = async (newStatus: ReportStatus) => {
    if (!report) return;
    setSaving(true);
    try {
      const updated = await api.updateReport(reportId, { status: newStatus });
      setReport(updated);
    } catch (e: any) {
      setError(e.message);
    }
    setSaving(false);
  };

  const handleAISummary = async () => {
    setAiLoading(true);
    try {
      const result = await api.generateReportAISummary(reportId);
      if (result.summary) {
        setReport((prev) => (prev ? { ...prev, summary: result.summary } : prev));
      }
    } catch (e: any) {
      setError(e.message || "AI unavailable");
    }
    setAiLoading(false);
  };

  const handleExport = async () => {
    const url = await api.exportReport(reportId, "markdown", true);
    window.open(url, "_blank");
  };

  const handleDelete = async () => {
    if (!confirm("Delete this report? This cannot be undone.")) return;
    setDeleting(true);
    try {
      await api.deleteReport(reportId);
      router.push("/reports");
    } catch (e: any) {
      setError(e.message);
      setDeleting(false);
    }
  };

  const handleRemoveItem = async (itemId: string) => {
    try {
      await api.removeReportItem(reportId, itemId);
      fetchReport();
    } catch {
      // silent
    }
  };

  if (loading) {
    return (
      <div className="p-6 max-w-4xl mx-auto">
        <div className="space-y-4">
          <div className="h-8 w-48 bg-card animate-pulse rounded" />
          <div className="h-48 bg-card animate-pulse rounded-lg" />
          <div className="h-32 bg-card animate-pulse rounded-lg" />
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-6 max-w-4xl mx-auto text-center">
        <FileText className="h-12 w-12 mx-auto text-muted-foreground/30 mb-4" />
        <h2 className="text-lg font-medium">Report not found</h2>
        <Button variant="outline" className="mt-4" onClick={() => router.push("/reports")}>
          Back to Reports
        </Button>
      </div>
    );
  }

  const statusCfg = STATUS_CONFIG[report.status];
  const StatusIcon = statusCfg.icon;
  const linkedTotal = report.linked_intel_count + report.linked_ioc_count + report.linked_technique_count;
  const sections = report.content?.sections || [];

  return (
    <div className="p-6 space-y-4 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <Button variant="ghost" size="sm" onClick={() => router.push("/reports")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="min-w-0">
            {editing ? (
              <input
                type="text"
                value={editTitle}
                onChange={(e) => setEditTitle(e.target.value)}
                className="text-2xl font-bold bg-transparent border-b border-primary/30 focus:outline-none w-full"
              />
            ) : (
              <h1 className="text-2xl font-bold tracking-tight truncate">{report.title}</h1>
            )}
            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground flex-wrap">
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${statusCfg.color}`}>
                <StatusIcon className="h-3 w-3 mr-0.5" />
                {statusCfg.label}
              </Badge>
              <span>{TYPE_LABELS[report.report_type]}</span>
              <span>•</span>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[report.severity]}`}>
                {report.severity.toUpperCase()}
              </Badge>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${TLP_COLORS[report.tlp] || ""}`}>
                {report.tlp}
              </Badge>
              {report.author_email && (
                <>
                  <span>•</span>
                  <span>by {report.author_email}</span>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          {!editing && (
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <Edit3 className="h-3.5 w-3.5 mr-1" />
              Edit
            </Button>
          )}
          {editing && (
            <>
              <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
                Cancel
              </Button>
              <Button size="sm" onClick={handleSave} disabled={saving}>
                {saving ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Save className="h-3.5 w-3.5 mr-1" />}
                Save
              </Button>
            </>
          )}
          {!editing && statusCfg.next && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleStatusChange(statusCfg.next!)}
              disabled={saving}
            >
              <Send className="h-3.5 w-3.5 mr-1" />
              {statusCfg.next === "review" ? "Submit for Review" : statusCfg.next === "published" ? "Publish" : "Archive"}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={handleAISummary} disabled={aiLoading}>
            {aiLoading ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1" />}
            AI Summary
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="h-3.5 w-3.5 mr-1" />
            Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleDelete} disabled={deleting} className="text-red-400 hover:text-red-300">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Summary */}
      {report.summary && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-primary" />
              Executive Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground whitespace-pre-line">{report.summary}</p>
          </CardContent>
        </Card>
      )}

      {/* Metadata row when editing */}
      {editing && (
        <Card>
          <CardContent className="p-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Severity</label>
                <div className="flex flex-wrap gap-1">
                  {SEVERITY_OPTIONS.map((s) => (
                    <Badge
                      key={s}
                      variant="outline"
                      className={`cursor-pointer text-xs ${editSeverity === s ? SEVERITY_COLORS[s] : ""}`}
                      onClick={() => setEditSeverity(s)}
                    >
                      {s}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">TLP</label>
                <div className="flex flex-wrap gap-1">
                  {TLP_OPTIONS.map((t) => (
                    <Badge
                      key={t}
                      variant="outline"
                      className={`cursor-pointer text-[10px] ${editTlp === t ? TLP_COLORS[t] : ""}`}
                      onClick={() => setEditTlp(t)}
                    >
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Tags</label>
                <input
                  type="text"
                  value={editTags}
                  onChange={(e) => setEditTags(e.target.value)}
                  placeholder="tag1, tag2, ..."
                  className="w-full px-3 py-1.5 rounded-md border bg-background text-sm"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tags (view mode) */}
      {!editing && report.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {report.tags.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>
      )}

      {/* Content Sections */}
      {(editing ? editSections : sections).length > 0 && (
        <div className="space-y-3">
          {(editing ? editSections : sections).map((section, idx) => {
            const body = section.body || "";
            if (!editing && !body.trim()) return null;
            return (
              <Card key={section.key}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">{section.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  {editing ? (
                    <textarea
                      value={body}
                      onChange={(e) =>
                        setEditSections((prev) =>
                          prev.map((s, i) => (i === idx ? { ...s, body: e.target.value } : s))
                        )
                      }
                      placeholder={section.hint || `Write ${section.title.toLowerCase()}...`}
                      rows={4}
                      className="w-full px-3 py-2 rounded-md border bg-background text-sm resize-y focus:outline-none focus:ring-2 focus:ring-primary/30"
                    />
                  ) : (
                    <p className="text-sm text-muted-foreground whitespace-pre-line">{body}</p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Linked Items */}
      {report.items && report.items.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="h-4 w-4" />
              Linked Items ({report.items.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1.5">
              {report.items.map((item) => (
                <LinkedItemRow
                  key={item.id}
                  item={item}
                  onRemove={() => handleRemoveItem(item.id)}
                  editing={editing}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Timestamps */}
      <div className="text-xs text-muted-foreground flex flex-wrap gap-4 pt-2 border-t">
        <span>Created: {new Date(report.created_at).toLocaleString()}</span>
        <span>Updated: {new Date(report.updated_at).toLocaleString()}</span>
        {report.published_at && (
          <span>Published: {new Date(report.published_at).toLocaleString()}</span>
        )}
      </div>
    </div>
  );
}

function LinkedItemRow({
  item,
  onRemove,
  editing,
}: {
  item: ReportItem;
  onRemove: () => void;
  editing: boolean;
}) {
  const meta = item.item_metadata || {};
  const typeColors: Record<string, string> = {
    intel: "text-blue-400",
    ioc: "text-amber-400",
    technique: "text-purple-400",
  };

  const href =
    item.item_type === "intel"
      ? `/intel/${item.item_id}`
      : item.item_type === "technique"
        ? `/threats`
        : undefined;

  return (
    <div className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/30 group text-sm">
      <Badge variant="outline" className={`text-[10px] px-1.5 ${typeColors[item.item_type] || ""}`}>
        {item.item_type}
      </Badge>
      {href ? (
        <a href={href} className="flex-1 truncate hover:underline text-foreground">
          {item.item_title || item.item_id}
        </a>
      ) : (
        <span className="flex-1 truncate">{item.item_title || item.item_id}</span>
      )}
      {typeof meta.severity === "string" && (
        <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[meta.severity] || ""}`}>
          {meta.severity.toUpperCase()}
        </Badge>
      )}
      {meta.risk_score !== undefined && (
        <span className="text-xs text-muted-foreground">Risk: {String(meta.risk_score)}</span>
      )}
      {editing && (
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100" onClick={onRemove}>
          <X className="h-3 w-3" />
        </Button>
      )}
    </div>
  );
}
