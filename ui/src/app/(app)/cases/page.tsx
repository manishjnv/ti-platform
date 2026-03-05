"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Loading } from "@/components/Loading";
import { Pagination } from "@/components/Pagination";
import { StatCard } from "@/components/StatCard";
import {
  getCases,
  getCaseStats,
  createCase,
  deleteCase,
} from "@/lib/api";
import type {
  Case,
  CaseListResponse,
  CaseStats,
  CaseStatus,
  CasePriority,
  CaseType,
  CaseCreate,
  Severity,
} from "@/types";
import {
  Briefcase,
  Plus,
  Filter,
  RefreshCw,
  Search,
  ChevronRight,
  AlertTriangle,
  Clock,
  CheckCircle,
  Pause,
  XCircle,
  Shield,
  Crosshair,
  HelpCircle,
  Trash2,
  X,
} from "lucide-react";

/* ── Config Maps ──────────────────────────────────────── */

const STATUS_CONFIG: Record<CaseStatus, { label: string; color: string; icon: React.ElementType }> = {
  new: { label: "New", color: "bg-blue-500/10 text-blue-400 border-blue-500/20", icon: Clock },
  in_progress: { label: "In Progress", color: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: RefreshCw },
  pending: { label: "Pending", color: "bg-purple-500/10 text-purple-400 border-purple-500/20", icon: Pause },
  resolved: { label: "Resolved", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: CheckCircle },
  closed: { label: "Closed", color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", icon: XCircle },
};

const PRIORITY_CONFIG: Record<CasePriority, { label: string; color: string }> = {
  critical: { label: "Critical", color: "text-red-400 bg-red-500/10 border-red-500/20" },
  high: { label: "High", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  medium: { label: "Medium", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
  low: { label: "Low", color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
};

const TYPE_CONFIG: Record<CaseType, { label: string; icon: React.ElementType }> = {
  incident_response: { label: "Incident Response", icon: AlertTriangle },
  investigation: { label: "Investigation", icon: Search },
  hunt: { label: "Threat Hunt", icon: Crosshair },
  rfi: { label: "Request for Info", icon: HelpCircle },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-cyan-400",
};

/* ── Create Modal ─────────────────────────────────────── */

function CreateCaseModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [caseType, setCaseType] = useState<CaseType>("investigation");
  const [priority, setPriority] = useState<CasePriority>("medium");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [tagInput, setTagInput] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  if (!open) return null;

  const addTag = () => {
    const t = tagInput.trim().toLowerCase();
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setTagInput("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    setSaving(true);
    try {
      await createCase({
        title: title.trim(),
        description: description.trim() || undefined,
        case_type: caseType,
        priority,
        severity,
        tlp,
        tags: tags.length > 0 ? tags : undefined,
      });
      setTitle("");
      setDescription("");
      setCaseType("investigation");
      setPriority("medium");
      setSeverity("medium");
      setTlp("TLP:GREEN");
      setTags([]);
      onCreated();
      onClose();
    } catch {
      // Error handled by fetcher
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Briefcase className="h-5 w-5 text-primary" />
            New Case
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Title *</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              placeholder="Case title..."
              required
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary min-h-[80px]"
              placeholder="Describe the case..."
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground">Type</label>
              <select
                value={caseType}
                onChange={(e) => setCaseType(e.target.value as CaseType)}
                className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {Object.entries(TYPE_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as CasePriority)}
                className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {Object.entries(PRIORITY_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">TLP</label>
              <select
                value={tlp}
                onChange={(e) => setTlp(e.target.value)}
                className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="TLP:RED">TLP:RED</option>
                <option value="TLP:AMBER+STRICT">TLP:AMBER+STRICT</option>
                <option value="TLP:AMBER">TLP:AMBER</option>
                <option value="TLP:GREEN">TLP:GREEN</option>
                <option value="TLP:CLEAR">TLP:CLEAR</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Tags</label>
            <div className="flex gap-2 mt-1">
              <input
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                placeholder="Add tag and press Enter"
                className="flex-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <Button type="button" variant="ghost" size="sm" onClick={addTag} disabled={!tagInput.trim()}>Add</Button>
            </div>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {tags.map((t) => (
                  <Badge key={t} variant="outline" className="text-[10px] px-1.5 py-0 bg-muted/50 cursor-pointer hover:bg-destructive/10" onClick={() => setTags(tags.filter((x) => x !== t))}>
                    {t} <X className="h-2.5 w-2.5 ml-0.5" />
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" size="sm" type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button size="sm" type="submit" disabled={saving || !title.trim()}>
              {saving ? "Creating..." : "Create Case"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Main Page ────────────────────────────────────────── */

export default function CasesPage() {
  const router = useRouter();
  const [cases, setCases] = useState<Case[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<CaseStats | null>(null);

  const [showFilters, setShowFilters] = useState(false);
  const [statusFilter, setStatusFilter] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  const fetchData = useCallback(
    async (p = 1) => {
      setLoading(true);
      try {
        const [res, st] = await Promise.all([
          getCases({
            page: p,
            page_size: 20,
            status: statusFilter || undefined,
            priority: priorityFilter || undefined,
            case_type: typeFilter || undefined,
            search: searchTerm || undefined,
          }),
          getCaseStats(),
        ]);
        setCases(res.cases);
        setTotal(res.total);
        setPage(res.page);
        setPages(res.pages);
        setStats(st);
      } catch {
        // Handled by fetcher
      } finally {
        setLoading(false);
      }
    },
    [statusFilter, priorityFilter, typeFilter, searchTerm]
  );

  useEffect(() => {
    fetchData(1);
  }, [fetchData]);

  const handlePageChange = (p: number) => {
    fetchData(p);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const clearFilters = () => {
    setStatusFilter("");
    setPriorityFilter("");
    setTypeFilter("");
    setSearchTerm("");
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Delete this case?")) return;
    try {
      await deleteCase(id);
      fetchData(page);
    } catch {
      alert("Failed to delete case");
    }
  };

  if (loading && cases.length === 0) return <Loading />;

  return (
    <div className="space-y-4 pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Briefcase className="h-5 w-5 text-primary" />
            Cases
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            {total} case{total !== 1 ? "s" : ""} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
            className="text-xs"
          >
            <Filter className="h-3.5 w-3.5 mr-1" />
            Filters
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => fetchData(page)}
            className="text-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)} className="text-xs">
            <Plus className="h-3.5 w-3.5 mr-1" />
            New Case
          </Button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard
            title="Total Cases"
            value={stats.total_cases}
            icon={<Briefcase className="h-4 w-4" />}
          />
          <StatCard
            title="Open Cases"
            value={stats.open_cases}
            icon={<Clock className="h-4 w-4" />}
          />
          <StatCard
            title="Critical Priority"
            value={stats.by_priority?.critical || 0}
            icon={<AlertTriangle className="h-4 w-4" />}
          />
          <StatCard
            title="Closed (7d)"
            value={stats.recent_closed}
            icon={<CheckCircle className="h-4 w-4" />}
          />
        </div>
      )}

      {/* Filters */}
      {showFilters && (
        <Card>
          <CardContent className="p-3">
            <div className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[160px]">
                <label className="text-[10px] font-medium text-muted-foreground uppercase">Search</label>
                <div className="relative mt-1">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && fetchData(1)}
                    placeholder="Search cases..."
                    className="w-full pl-7 pr-3 py-1.5 rounded-md bg-muted/50 border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div>
                <label className="text-[10px] font-medium text-muted-foreground uppercase">Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="mt-1 block w-full px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                >
                  <option value="">All</option>
                  {Object.entries(STATUS_CONFIG).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[10px] font-medium text-muted-foreground uppercase">Priority</label>
                <select
                  value={priorityFilter}
                  onChange={(e) => setPriorityFilter(e.target.value)}
                  className="mt-1 block w-full px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                >
                  <option value="">All</option>
                  {Object.entries(PRIORITY_CONFIG).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[10px] font-medium text-muted-foreground uppercase">Type</label>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="mt-1 block w-full px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                >
                  <option value="">All</option>
                  {Object.entries(TYPE_CONFIG).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>
              </div>
              <div className="flex gap-2">
                <Button size="sm" className="text-xs" onClick={() => fetchData(1)}>
                  Apply
                </Button>
                <Button variant="ghost" size="sm" className="text-xs" onClick={clearFilters}>
                  Clear
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Case List */}
      <div className="space-y-2">
        {cases.map((c) => {
          const statusCfg = STATUS_CONFIG[c.status] || STATUS_CONFIG.new;
          const priorityCfg = PRIORITY_CONFIG[c.priority] || PRIORITY_CONFIG.medium;
          const typeCfg = TYPE_CONFIG[c.case_type] || TYPE_CONFIG.investigation;
          const StatusIcon = statusCfg.icon;
          const TypeIcon = typeCfg.icon;

          return (
            <Card
              key={c.id}
              className="hover:border-primary/40 cursor-pointer transition-all group"
              onClick={() => router.push(`/cases/${c.id}`)}
            >
              <CardContent className="p-3">
                <div className="flex items-start gap-3">
                  {/* Priority indicator */}
                  <div className={`mt-0.5 w-1.5 h-10 rounded-full ${
                    c.priority === "critical" ? "bg-red-500" :
                    c.priority === "high" ? "bg-orange-500" :
                    c.priority === "medium" ? "bg-yellow-500" : "bg-blue-500"
                  }`} />

                  {/* Main content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-semibold truncate group-hover:text-primary transition-colors">
                        {c.title}
                      </h3>
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${statusCfg.color}`}>
                        <StatusIcon className="h-3 w-3 mr-0.5" />
                        {statusCfg.label}
                      </Badge>
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${priorityCfg.color}`}>
                        {priorityCfg.label}
                      </Badge>
                    </div>

                    {c.description && (
                      <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{c.description}</p>
                    )}

                    <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <TypeIcon className="h-3 w-3" />
                        {typeCfg.label}
                      </span>
                      <span className={SEVERITY_COLORS[c.severity] || ""}>
                        {c.severity}
                      </span>
                      {c.linked_intel_count > 0 && (
                        <span>{c.linked_intel_count} intel</span>
                      )}
                      {c.linked_ioc_count > 0 && (
                        <span>{c.linked_ioc_count} IOC{c.linked_ioc_count > 1 ? "s" : ""}</span>
                      )}
                      <span>
                        {new Date(c.updated_at).toLocaleDateString()}
                      </span>
                      {c.owner_email && (
                        <span className="truncate max-w-[100px]" title={c.owner_email}>{c.owner_email.split('@')[0]}</span>
                      )}
                      {c.assignee_email && (
                        <span className="truncate max-w-[120px]">→ {c.assignee_email}</span>
                      )}
                    </div>

                    {c.tags.length > 0 && (
                      <div className="flex gap-1 mt-1.5 flex-wrap">
                        {c.tags.slice(0, 5).map((t) => (
                          <Badge
                            key={t}
                            variant="outline"
                            className="text-[9px] px-1 py-0 bg-muted/50"
                          >
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={(e) => handleDelete(c.id, e)}
                      className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors opacity-0 group-hover:opacity-100"
                      title="Delete case"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                    <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}

        {cases.length === 0 && !loading && (
          <Card>
            <CardContent className="p-8 text-center">
              <Briefcase className="h-10 w-10 mx-auto text-muted-foreground/30 mb-3" />
              <p className="text-sm text-muted-foreground">No cases yet</p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                Create your first case to start tracking incidents
              </p>
              <Button size="sm" className="mt-3 text-xs" onClick={() => setShowCreate(true)}>
                <Plus className="h-3.5 w-3.5 mr-1" />
                New Case
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <Pagination
          page={page}
          pages={pages}
          onPageChange={handlePageChange}
        />
      )}

      {/* Create Modal */}
      <CreateCaseModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={() => fetchData(1)}
      />
    </div>
  );
}
