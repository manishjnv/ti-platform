"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Loading } from "@/components/Loading";
import {
  getCase,
  updateCase,
  addCaseComment,
  addCaseItem,
  removeCaseItem,
} from "@/lib/api";
import type {
  Case,
  CaseStatus,
  CasePriority,
  CaseType,
  CaseItem,
  CaseActivity,
} from "@/types";
import {
  ArrowLeft,
  Briefcase,
  Clock,
  RefreshCw,
  Pause,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Search,
  Crosshair,
  HelpCircle,
  Shield,
  Tag,
  MessageSquare,
  Plus,
  Trash2,
  Send,
  User,
  FileText,
  Bug,
  Activity,
  Link2,
  Edit3,
  Save,
  X,
} from "lucide-react";

/* ── Config ───────────────────────────────────────────── */

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
  unknown: "text-muted-foreground",
};

const ITEM_TYPE_ICONS: Record<string, React.ElementType> = {
  intel: FileText,
  ioc: Bug,
  technique: Crosshair,
  observable: Shield,
};

/* ── Activity Icon ────────────────────────────────────── */

function ActivityIcon({ action }: { action: string }) {
  switch (action) {
    case "created": return <Plus className="h-3 w-3 text-emerald-400" />;
    case "comment": return <MessageSquare className="h-3 w-3 text-blue-400" />;
    case "status_changed":
    case "updated": return <Edit3 className="h-3 w-3 text-amber-400" />;
    case "item_added": return <Link2 className="h-3 w-3 text-purple-400" />;
    case "item_removed": return <Trash2 className="h-3 w-3 text-red-400" />;
    case "assigned": return <User className="h-3 w-3 text-cyan-400" />;
    default: return <Activity className="h-3 w-3 text-muted-foreground" />;
  }
}

/* ── Add Item Modal ───────────────────────────────────── */

function AddItemModal({
  open,
  onClose,
  onAdd,
}: {
  open: boolean;
  onClose: () => void;
  onAdd: (data: { item_type: string; item_id: string; item_title?: string; notes?: string }) => void;
}) {
  const [itemType, setItemType] = useState("intel");
  const [itemId, setItemId] = useState("");
  const [itemTitle, setItemTitle] = useState("");
  const [notes, setNotes] = useState("");

  if (!open) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!itemId.trim()) return;
    onAdd({
      item_type: itemType,
      item_id: itemId.trim(),
      item_title: itemTitle.trim() || undefined,
      notes: notes.trim() || undefined,
    });
    setItemId("");
    setItemTitle("");
    setNotes("");
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <Link2 className="h-4 w-4 text-primary" />
            Link Item to Case
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Type</label>
            <select
              value={itemType}
              onChange={(e) => setItemType(e.target.value)}
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm"
            >
              <option value="intel">Intel Item</option>
              <option value="ioc">IOC</option>
              <option value="technique">ATT&CK Technique</option>
              <option value="observable">Observable</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">ID *</label>
            <input
              value={itemId}
              onChange={(e) => setItemId(e.target.value)}
              placeholder={itemType === "technique" ? "e.g. T1059.001" : "UUID or identifier"}
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              required
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Title</label>
            <input
              value={itemTitle}
              onChange={(e) => setItemTitle(e.target.value)}
              placeholder="Human-readable label"
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Notes</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Context or relevance..."
              className="w-full mt-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary min-h-[60px]"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" type="button" onClick={onClose}>Cancel</Button>
            <Button size="sm" type="submit" disabled={!itemId.trim()}>Link Item</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Main Detail Page ─────────────────────────────────── */

export default function CaseDetailPage() {
  const params = useParams();
  const router = useRouter();
  const caseId = params?.id as string;

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [loading, setLoading] = useState(true);
  const [comment, setComment] = useState("");
  const [commenting, setCommenting] = useState(false);
  const [showAddItem, setShowAddItem] = useState(false);
  const [editing, setEditing] = useState(false);

  // Edit state
  const [editTitle, setEditTitle] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editStatus, setEditStatus] = useState<CaseStatus>("new");
  const [editPriority, setEditPriority] = useState<CasePriority>("medium");
  const [editType, setEditType] = useState<CaseType>("investigation");

  const fetchCase = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getCase(caseId);
      setCaseData(data);
      setEditTitle(data.title);
      setEditDesc(data.description || "");
      setEditStatus(data.status);
      setEditPriority(data.priority);
      setEditType(data.case_type);
    } catch {
      // Not found
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    fetchCase();
  }, [fetchCase]);

  const handleSave = async () => {
    if (!caseData) return;
    await updateCase(caseData.id, {
      title: editTitle,
      description: editDesc || undefined,
      status: editStatus,
      priority: editPriority,
      case_type: editType,
    });
    setEditing(false);
    fetchCase();
  };

  const handleComment = async () => {
    if (!comment.trim() || !caseData) return;
    setCommenting(true);
    try {
      await addCaseComment(caseData.id, comment.trim());
      setComment("");
      fetchCase();
    } catch {
      // handled
    } finally {
      setCommenting(false);
    }
  };

  const handleAddItem = async (data: { item_type: string; item_id: string; item_title?: string; notes?: string }) => {
    if (!caseData) return;
    try {
      await addCaseItem(caseData.id, data);
      fetchCase();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to link item";
      alert(msg.includes("409") ? "Item already linked to this case" : msg);
    }
  };

  const handleRemoveItem = async (itemId: string) => {
    if (!caseData || !confirm("Remove this linked item?")) return;
    await removeCaseItem(caseData.id, itemId);
    fetchCase();
  };

  if (loading) return <Loading />;
  if (!caseData) {
    return (
      <div className="text-center py-12">
        <p className="text-sm text-muted-foreground">Case not found</p>
        <Button size="sm" className="mt-3" onClick={() => router.push("/cases")}>
          <ArrowLeft className="h-3.5 w-3.5 mr-1" /> Back to Cases
        </Button>
      </div>
    );
  }

  const statusCfg = STATUS_CONFIG[caseData.status] || STATUS_CONFIG.new;
  const priorityCfg = PRIORITY_CONFIG[caseData.priority] || PRIORITY_CONFIG.medium;
  const typeCfg = TYPE_CONFIG[caseData.case_type] || TYPE_CONFIG.investigation;
  const StatusIcon = statusCfg.icon;
  const TypeIcon = typeCfg.icon;

  return (
    <div className="space-y-4 pb-10">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Button variant="ghost" size="sm" onClick={() => router.push("/cases")} className="shrink-0 mt-0.5">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1 min-w-0">
          {editing ? (
            <input
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              className="text-lg font-bold w-full bg-muted/50 border border-border rounded-lg px-3 py-1 focus:outline-none focus:ring-1 focus:ring-primary"
            />
          ) : (
            <h1 className="text-lg font-bold">{caseData.title}</h1>
          )}
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${statusCfg.color}`}>
              <StatusIcon className="h-3 w-3 mr-0.5" />
              {statusCfg.label}
            </Badge>
            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${priorityCfg.color}`}>
              {priorityCfg.label}
            </Badge>
            <span className="text-[10px] text-muted-foreground flex items-center gap-1">
              <TypeIcon className="h-3 w-3" />
              {typeCfg.label}
            </span>
            <span className={`text-[10px] capitalize ${SEVERITY_COLORS[caseData.severity] || ""}`}>
              {caseData.severity}
            </span>
            <span className="text-[10px] text-muted-foreground">
              Created {new Date(caseData.created_at).toLocaleDateString()}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {editing ? (
            <>
              <Button size="sm" className="text-xs" onClick={handleSave}>
                <Save className="h-3.5 w-3.5 mr-1" /> Save
              </Button>
              <Button variant="ghost" size="sm" className="text-xs" onClick={() => setEditing(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button variant="ghost" size="sm" className="text-xs" onClick={() => setEditing(true)}>
              <Edit3 className="h-3.5 w-3.5 mr-1" /> Edit
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-4">
          {/* Description */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Description</CardTitle>
            </CardHeader>
            <CardContent>
              {editing ? (
                <textarea
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary min-h-[100px]"
                  placeholder="Case description..."
                />
              ) : (
                <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                  {caseData.description || "No description provided."}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Edit fields */}
          {editing && (
            <Card>
              <CardContent className="p-4">
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="text-[10px] font-medium text-muted-foreground uppercase">Status</label>
                    <select
                      value={editStatus}
                      onChange={(e) => setEditStatus(e.target.value as CaseStatus)}
                      className="w-full mt-1 px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                    >
                      {Object.entries(STATUS_CONFIG).map(([k, v]) => (
                        <option key={k} value={k}>{v.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-medium text-muted-foreground uppercase">Priority</label>
                    <select
                      value={editPriority}
                      onChange={(e) => setEditPriority(e.target.value as CasePriority)}
                      className="w-full mt-1 px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                    >
                      {Object.entries(PRIORITY_CONFIG).map(([k, v]) => (
                        <option key={k} value={k}>{v.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-medium text-muted-foreground uppercase">Type</label>
                    <select
                      value={editType}
                      onChange={(e) => setEditType(e.target.value as CaseType)}
                      className="w-full mt-1 px-2 py-1.5 rounded-md bg-muted/50 border border-border text-xs"
                    >
                      {Object.entries(TYPE_CONFIG).map(([k, v]) => (
                        <option key={k} value={k}>{v.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Linked Items */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Link2 className="h-4 w-4 text-primary" />
                  Linked Items
                  <span className="text-xs text-muted-foreground font-normal">
                    ({caseData.items?.length || 0})
                  </span>
                </CardTitle>
                <Button size="sm" variant="ghost" className="text-xs" onClick={() => setShowAddItem(true)}>
                  <Plus className="h-3.5 w-3.5 mr-1" /> Link
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {caseData.items && caseData.items.length > 0 ? (
                <div className="space-y-1.5">
                  {caseData.items.map((item) => {
                    const ItemIcon = ITEM_TYPE_ICONS[item.item_type] || FileText;
                    return (
                      <div
                        key={item.id}
                        className="flex items-center gap-2 p-2 rounded-lg bg-muted/30 hover:bg-muted/50 group text-xs"
                      >
                        <ItemIcon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <Badge variant="outline" className="text-[9px] px-1 py-0 shrink-0">
                          {item.item_type}
                        </Badge>
                        <span className="font-medium truncate flex-1">
                          {item.item_title || item.item_id}
                        </span>
                        {item.notes && (
                          <span className="text-muted-foreground truncate max-w-[150px]" title={item.notes}>
                            {item.notes}
                          </span>
                        )}
                        <span className="text-muted-foreground shrink-0">
                          {new Date(item.created_at).toLocaleDateString()}
                        </span>
                        <button
                          onClick={() => handleRemoveItem(item.id)}
                          className="p-0.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground text-center py-4">
                  No linked items yet. Click &quot;Link&quot; to attach intel, IOCs, or techniques.
                </p>
              )}
            </CardContent>
          </Card>

          {/* Comment Box */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <MessageSquare className="h-4 w-4 text-primary" />
                Add Comment
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Write a comment..."
                  className="flex-1 px-3 py-2 rounded-lg bg-muted/50 border border-border text-sm focus:outline-none focus:ring-1 focus:ring-primary min-h-[60px]"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleComment();
                  }}
                />
                <Button
                  size="sm"
                  className="self-end"
                  disabled={!comment.trim() || commenting}
                  onClick={handleComment}
                >
                  <Send className="h-3.5 w-3.5" />
                </Button>
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">Ctrl+Enter to send</p>
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Meta Card */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status</span>
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${statusCfg.color}`}>
                  <StatusIcon className="h-3 w-3 mr-0.5" />
                  {statusCfg.label}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Priority</span>
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${priorityCfg.color}`}>
                  {priorityCfg.label}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Severity</span>
                <span className={`capitalize ${SEVERITY_COLORS[caseData.severity] || ""}`}>
                  {caseData.severity}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Type</span>
                <span className="flex items-center gap-1">
                  <TypeIcon className="h-3 w-3" />
                  {typeCfg.label}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">TLP</span>
                <span>{caseData.tlp}</span>
              </div>
              <hr className="border-border/50" />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Owner</span>
                <span className="truncate max-w-[140px]">{caseData.owner_email || "—"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Assignee</span>
                <span className="truncate max-w-[140px]">{caseData.assignee_email || "Unassigned"}</span>
              </div>
              <hr className="border-border/50" />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Created</span>
                <span>{new Date(caseData.created_at).toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Updated</span>
                <span>{new Date(caseData.updated_at).toLocaleString()}</span>
              </div>
              {caseData.closed_at && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Closed</span>
                  <span>{new Date(caseData.closed_at).toLocaleString()}</span>
                </div>
              )}
              <hr className="border-border/50" />
              <div className="flex justify-between">
                <span className="text-muted-foreground">Intel</span>
                <span>{caseData.linked_intel_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">IOCs</span>
                <span>{caseData.linked_ioc_count}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Observables</span>
                <span>{caseData.linked_observable_count}</span>
              </div>
            </CardContent>
          </Card>

          {/* Tags */}
          {caseData.tags.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Tag className="h-4 w-4" />
                  Tags
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1">
                  {caseData.tags.map((t) => (
                    <Badge key={t} variant="outline" className="text-[10px] px-1.5 py-0 bg-muted/50">
                      {t}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Activity Timeline */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                Activity
                <span className="text-xs text-muted-foreground font-normal">
                  ({caseData.activities?.length || 0})
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {caseData.activities && caseData.activities.length > 0 ? (
                <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
                  {caseData.activities.map((a) => (
                    <div key={a.id} className="flex gap-2">
                      <div className="mt-1 shrink-0">
                        <div className="w-5 h-5 rounded-full bg-muted/50 flex items-center justify-center">
                          <ActivityIcon action={a.action} />
                        </div>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 text-[10px]">
                          <span className="font-medium">{a.user_email || "System"}</span>
                          <span className="text-muted-foreground">
                            {new Date(a.created_at).toLocaleString()}
                          </span>
                        </div>
                        {a.action === "comment" ? (
                          <div className="mt-1 p-2 rounded-lg bg-muted/30 text-xs whitespace-pre-wrap">
                            {a.detail}
                          </div>
                        ) : (
                          <p className="text-[11px] text-muted-foreground mt-0.5">
                            {a.detail}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground text-center py-4">No activity yet</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Add Item Modal */}
      <AddItemModal
        open={showAddItem}
        onClose={() => setShowAddItem(false)}
        onAdd={handleAddItem}
      />
    </div>
  );
}
