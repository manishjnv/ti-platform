"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useRouter, useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Report, ReportItem, ReportStatus, ReportType, Severity } from "@/types";
import * as api from "@/lib/api";
import MarkdownContent from "@/components/MarkdownContent";
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
  X,
  Send,
  Edit3,
  ChevronDown,
  FileCode2,
  Globe,
  Table2,
  Plus,
  Search,
  PenLine,
  Check,
  Tag,
  Info,
} from "lucide-react";

/* ─── Constants ─────────────────────────────────────────── */

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

/* ─── Main Component ────────────────────────────────────── */

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
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);

  // Edit state
  const [editTitle, setEditTitle] = useState("");
  const [editSummary, setEditSummary] = useState("");
  const [editSeverity, setEditSeverity] = useState<Severity>("medium");
  const [editTlp, setEditTlp] = useState("TLP:GREEN");
  const [editTags, setEditTags] = useState("");
  const [editSections, setEditSections] = useState<Array<{ key: string; title: string; hint?: string; body: string }>>([]);

  // Inline section editing (for non-global edit mode)
  const [editingSectionIdx, setEditingSectionIdx] = useState<number | null>(null);
  const [sectionDraft, setSectionDraft] = useState("");

  // Link Intel Items
  const [showLinkPanel, setShowLinkPanel] = useState(false);
  const [linkSearch, setLinkSearch] = useState("");
  const [linkResults, setLinkResults] = useState<any[]>([]);
  const [linkLoading, setLinkLoading] = useState(false);

  const fetchReport = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getReport(reportId);
      setReport(data);
      setEditTitle(data.title);
      setEditSummary(data.summary || "");
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

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) {
        setExportOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  /* ─── Handlers ──────────────────────────────────────── */

  const handleSave = async () => {
    if (!report) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateReport(reportId, {
        title: editTitle.trim(),
        summary: editSummary.trim() || undefined,
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

  const handleSectionInlineSave = async (idx: number) => {
    if (!report) return;
    const sections = [...(report.content?.sections || [])];
    sections[idx] = { ...sections[idx], body: sectionDraft };
    const isExecSummary = sections[idx].key === "executive_summary";
    setSaving(true);
    try {
      const updatePayload: Record<string, any> = { content: { sections } };
      if (isExecSummary) {
        updatePayload.summary = sectionDraft.trim() || undefined;
      }
      const updated = await api.updateReport(reportId, updatePayload);
      setReport(updated);
      setEditingSectionIdx(null);
      setSectionDraft("");
      setEditSections(updated.content?.sections || []);
      if (isExecSummary) setEditSummary(sectionDraft);
    } catch (e: any) {
      setError(e.message || "Failed to save section");
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
    setError(null);
    try {
      const result = await api.generateReportAISections(reportId);
      if (result.summary || result.sections) {
        setReport((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            summary: result.summary || prev.summary,
            content: { ...prev.content, sections: result.sections || prev.content?.sections || [] },
          };
        });
        setEditSummary(result.summary || editSummary);
        setEditSections(result.sections || editSections);
      }
    } catch (e: any) {
      setError(e.message || "AI unavailable");
    }
    setAiLoading(false);
  };

  const handleExport = async (format: string) => {
    setExportOpen(false);
    const url = await api.exportReport(reportId, format, true);
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

  const handleLinkSearch = async () => {
    if (!linkSearch.trim()) return;
    setLinkLoading(true);
    try {
      const res = await api.searchIntel({ query: linkSearch, page: 1, page_size: 10 });
      setLinkResults(res.results || []);
    } catch {
      setLinkResults([]);
    }
    setLinkLoading(false);
  };

  const handleLinkItem = async (item: any) => {
    try {
      await api.addReportItem(reportId, {
        item_type: "intel",
        item_id: item.id,
        item_title: item.title,
        item_metadata: {
          severity: item.severity,
          source_name: item.source_feed,
        },
      });
      setLinkResults((prev) => prev.filter((i) => i.id !== item.id));
      fetchReport();
    } catch (e: any) {
      setError(e.message || "Failed to link item");
    }
  };

  /* ─── Loading / Error states ────────────────────────── */

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
  const sections = report.content?.sections || [];
  const filledCount = sections.filter((s) => s.body?.trim()).length;
  const totalSections = sections.length;
  const linkedTotal = report.linked_intel_count + report.linked_ioc_count + report.linked_technique_count;

  /* ─── Render ────────────────────────────────────────── */

  return (
    <div className="p-6 space-y-4 max-w-4xl mx-auto">
      {/* ── Header ──────────────────────────────────────── */}
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
              <span>&middot;</span>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[report.severity]}`}>
                {report.severity.toUpperCase()}
              </Badge>
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${TLP_COLORS[report.tlp] || ""}`}>
                {report.tlp}
              </Badge>
              {report.author_email && (
                <>
                  <span>&middot;</span>
                  <span>by {report.author_email}</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {!editing && (
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <Edit3 className="h-3.5 w-3.5 mr-1" />
              Edit All
            </Button>
          )}
          {editing && (
            <>
              <Button variant="ghost" size="sm" onClick={() => { setEditing(false); fetchReport(); }}>
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
            {aiLoading ? "Generating..." : "AI Generate"}
          </Button>
          <div className="relative" ref={exportRef}>
            <Button variant="outline" size="sm" onClick={() => setExportOpen(!exportOpen)}>
              <Download className="h-3.5 w-3.5 mr-1" />
              Export
              <ChevronDown className="h-3 w-3 ml-1" />
            </Button>
            {exportOpen && (
              <div className="absolute right-0 top-full mt-1 w-48 rounded-lg border border-border bg-card shadow-xl z-50 py-1">
                <button onClick={() => handleExport("pdf")} className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-muted/50 text-left">
                  <FileText className="h-3.5 w-3.5 text-red-400" />
                  PDF Document
                </button>
                <button onClick={() => handleExport("markdown")} className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-muted/50 text-left">
                  <FileCode2 className="h-3.5 w-3.5 text-blue-400" />
                  Markdown (.md)
                </button>
                <button onClick={() => handleExport("html")} className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-muted/50 text-left">
                  <Globe className="h-3.5 w-3.5 text-emerald-400" />
                  HTML Report
                </button>
                <button onClick={() => handleExport("stix")} className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-muted/50 text-left">
                  <Shield className="h-3.5 w-3.5 text-purple-400" />
                  STIX 2.1 Bundle
                </button>
                <button onClick={() => handleExport("csv")} className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-muted/50 text-left">
                  <Table2 className="h-3.5 w-3.5 text-amber-400" />
                  CSV Spreadsheet
                </button>
              </div>
            )}
          </div>
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

      {/* ── Section progress bar ───────────────────────── */}
      {totalSections > 0 && (
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span>{filledCount}/{totalSections} sections filled</span>
          <div className="flex-1 h-1.5 bg-border/50 rounded-full overflow-hidden">
            <div
              className="h-full bg-primary/60 rounded-full transition-all"
              style={{ width: `${totalSections > 0 ? (filledCount / totalSections) * 100 : 0}%` }}
            />
          </div>
          {linkedTotal > 0 && (
            <span className="flex items-center gap-1">
              <Layers className="h-3 w-3" />
              {linkedTotal} linked
            </span>
          )}
        </div>
      )}

      {/* ── Metadata row (edit mode) ───────────────────── */}
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

      {/* ── Tags (view mode) ──────────────────────────── */}
      {!editing && report.tags.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          <Tag className="h-3 w-3 text-muted-foreground" />
          {report.tags.map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>
      )}

      {/* ── Content Sections ──────────────────────────── */}
      {(editing ? editSections : sections).map((section, idx) => {
        // For exec summary section, show the report.summary field
        const isExecSummary = section.key === "executive_summary";
        const body = isExecSummary ? (report.summary || section.body || "") : (section.body || "");
        const isInlineEditing = !editing && editingSectionIdx === idx;

        return (
          <Card key={section.key} className={`group transition-colors ${!body.trim() && !editing && !isInlineEditing ? "border-dashed border-border/50" : ""}`}>
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                {isExecSummary ? (
                  <span className="flex items-center justify-center h-5 w-5 rounded-full bg-primary/20 text-primary">
                    <Sparkles className="h-3 w-3" />
                  </span>
                ) : (
                  <span className="flex items-center justify-center h-5 w-5 rounded-full bg-primary/10 text-primary text-[10px] font-bold">
                    {idx + 1}
                  </span>
                )}
                <CardTitle className="text-sm">{section.title}</CardTitle>
              </div>
              {/* Inline edit button (view mode) */}
              {!editing && !isInlineEditing && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 opacity-0 group-hover:opacity-100 transition-opacity text-xs"
                  onClick={() => {
                    setEditingSectionIdx(idx);
                    setSectionDraft(body);
                  }}
                >
                  <PenLine className="h-3 w-3 mr-1" />
                  Edit
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {/* Global edit mode */}
              {editing && (
                <div>
                  {section.hint && (
                    <p className="text-[11px] text-muted-foreground/60 mb-2 flex items-center gap-1">
                      <Info className="h-3 w-3" />
                      {section.hint}
                    </p>
                  )}
                  <textarea
                    value={editSections[idx]?.body || ""}
                    onChange={(e) =>
                      setEditSections((prev) =>
                        prev.map((s, i) => (i === idx ? { ...s, body: e.target.value } : s))
                      )
                    }
                    placeholder={section.hint || `Write ${section.title.toLowerCase()}...`}
                    rows={5}
                    className="w-full px-3 py-2 rounded-md border bg-background text-sm resize-y focus:outline-none focus:ring-2 focus:ring-primary/30"
                  />
                </div>
              )}

              {/* Inline section edit mode */}
              {isInlineEditing && (
                <div className="space-y-2">
                  {section.hint && (
                    <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1">
                      <Info className="h-3 w-3" />
                      {section.hint}
                    </p>
                  )}
                  <textarea
                    value={sectionDraft}
                    onChange={(e) => setSectionDraft(e.target.value)}
                    placeholder={section.hint || `Write ${section.title.toLowerCase()}...`}
                    rows={6}
                    className="w-full px-3 py-2 rounded-md border bg-background text-sm resize-y focus:outline-none focus:ring-2 focus:ring-primary/30"
                    autoFocus
                  />
                  <div className="flex items-center justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => { setEditingSectionIdx(null); setSectionDraft(""); }}
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => handleSectionInlineSave(idx)}
                      disabled={saving}
                    >
                      {saving ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Check className="h-3.5 w-3.5 mr-1" />}
                      Save Section
                    </Button>
                  </div>
                </div>
              )}

              {/* View mode */}
              {!editing && !isInlineEditing && (
                <>
                  {body.trim() ? (
                    <MarkdownContent content={body} />
                  ) : (
                    <button
                      onClick={() => {
                        setEditingSectionIdx(idx);
                        setSectionDraft("");
                      }}
                      className="w-full py-4 text-center text-sm text-muted-foreground/40 hover:text-muted-foreground/60 transition-colors rounded-md border border-dashed border-border/30 hover:border-border/60"
                    >
                      <PenLine className="h-4 w-4 mx-auto mb-1 opacity-50" />
                      {section.hint || `Click to add ${section.title.toLowerCase()}`}
                    </button>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        );
      })}

      {/* ── Link Intel Items ──────────────────────────── */}
      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Layers className="h-4 w-4" />
            Linked Items ({linkedTotal})
          </CardTitle>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            onClick={() => setShowLinkPanel(!showLinkPanel)}
          >
            <Plus className="h-3 w-3 mr-1" />
            Link Intel
          </Button>
        </CardHeader>

        {/* Search & Link Panel */}
        {showLinkPanel && (
          <CardContent className="pt-0 pb-3 border-b border-border/30">
            <div className="flex items-center gap-2 mb-2">
              <div className="relative flex-1">
                <Search className="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  value={linkSearch}
                  onChange={(e) => setLinkSearch(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLinkSearch()}
                  placeholder="Search intel items to link..."
                  className="w-full pl-8 pr-3 py-1.5 rounded-md border bg-background text-sm"
                  autoFocus
                />
              </div>
              <Button size="sm" onClick={handleLinkSearch} disabled={linkLoading} className="h-8">
                {linkLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
              </Button>
            </div>
            {linkResults.length > 0 && (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {linkResults.map((item: any) => (
                  <div key={item.id} className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/30 text-sm">
                    <span className="flex-1 truncate">{item.title}</span>
                    {item.severity && (
                      <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[item.severity] || ""}`}>
                        {item.severity}
                      </Badge>
                    )}
                    <Button size="sm" variant="ghost" className="h-6 px-2 text-xs text-primary" onClick={() => handleLinkItem(item)}>
                      <Plus className="h-3 w-3 mr-0.5" />
                      Link
                    </Button>
                  </div>
                ))}
              </div>
            )}
            {linkResults.length === 0 && linkSearch && !linkLoading && (
              <p className="text-xs text-muted-foreground py-2 text-center">No items found. Try a different search term.</p>
            )}
          </CardContent>
        )}

        {/* Existing linked items */}
        <CardContent className={showLinkPanel ? "pt-3" : ""}>
          {report.items && report.items.length > 0 ? (
            <div className="space-y-1">
              {report.items.map((item) => (
                <LinkedItemRow
                  key={item.id}
                  item={item}
                  onRemove={() => handleRemoveItem(item.id)}
                />
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground/50 text-center py-4">
              No linked items yet. Use &ldquo;Link Intel&rdquo; to attach intelligence items to this report.
            </p>
          )}
        </CardContent>
      </Card>

      {/* ── Timestamps ────────────────────────────────── */}
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

/* ─── Linked Item Row ──────────────────────────────────── */

function LinkedItemRow({
  item,
  onRemove,
}: {
  item: ReportItem;
  onRemove: () => void;
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
          {(meta.severity as string).toUpperCase()}
        </Badge>
      )}
      {meta.risk_score !== undefined && (
        <span className="text-xs text-muted-foreground">Risk: {String(meta.risk_score)}</span>
      )}
      <Button variant="ghost" size="sm" className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 text-red-400" onClick={onRemove}>
        <X className="h-3 w-3" />
      </Button>
    </div>
  );
}
