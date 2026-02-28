"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ReportCreate, ReportTemplate, ReportType, Severity } from "@/types";
import * as api from "@/lib/api";
import {
  ArrowLeft,
  Loader2,
  FileText,
  AlertTriangle,
  Shield,
  BarChart3,
  FileWarning,
  Zap,
  ChevronRight,
  Sparkles,
  Info,
  Tag,
} from "lucide-react";

const TYPE_OPTIONS: {
  value: ReportType;
  label: string;
  desc: string;
  icon: React.ElementType;
  color: string;
}[] = [
  {
    value: "incident",
    label: "Incident Report",
    desc: "Document security incidents with timeline, impact, IOCs, and response actions",
    icon: AlertTriangle,
    color: "text-red-400 border-red-500/30 hover:border-red-400/60 hover:bg-red-500/5",
  },
  {
    value: "threat_advisory",
    label: "Threat Advisory",
    desc: "Proactive advisory on threat actors, campaigns, TTPs, and mitigations",
    icon: Shield,
    color: "text-amber-400 border-amber-500/30 hover:border-amber-400/60 hover:bg-amber-500/5",
  },
  {
    value: "weekly_summary",
    label: "Weekly Summary",
    desc: "Weekly threat landscape overview with key threats, stats, and recommendations",
    icon: BarChart3,
    color: "text-blue-400 border-blue-500/30 hover:border-blue-400/60 hover:bg-blue-500/5",
  },
  {
    value: "ioc_bulletin",
    label: "IOC Bulletin",
    desc: "IOC sharing bulletin with indicators, context, and detection guidance",
    icon: FileWarning,
    color: "text-purple-400 border-purple-500/30 hover:border-purple-400/60 hover:bg-purple-500/5",
  },
  {
    value: "custom",
    label: "Custom Report",
    desc: "Blank canvas — executive summary, body, and conclusion",
    icon: FileText,
    color: "text-cyan-400 border-cyan-500/30 hover:border-cyan-400/60 hover:bg-cyan-500/5",
  },
];

const SEVERITY_OPTIONS: { value: Severity; label: string; color: string }[] = [
  { value: "critical", label: "Critical", color: "bg-red-500/10 text-red-400 border-red-500/30" },
  { value: "high", label: "High", color: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  { value: "medium", label: "Medium", color: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  { value: "low", label: "Low", color: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
  { value: "info", label: "Info", color: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" },
];

const TLP_OPTIONS: { value: string; label: string; desc: string; color: string }[] = [
  { value: "TLP:RED", label: "RED", desc: "Named recipients only", color: "bg-red-500/10 text-red-400 border-red-500/30" },
  { value: "TLP:AMBER+STRICT", label: "AMBER+STRICT", desc: "Organization only", color: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  { value: "TLP:AMBER", label: "AMBER", desc: "Limited sharing", color: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  { value: "TLP:GREEN", label: "GREEN", desc: "Community sharing", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
  { value: "TLP:CLEAR", label: "CLEAR", desc: "Public / unrestricted", color: "bg-zinc-500/10 text-zinc-300 border-zinc-500/30" },
];

export default function NewReportPage() {
  const router = useRouter();
  const [templates, setTemplates] = useState<Record<string, ReportTemplate>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [reportType, setReportType] = useState<ReportType | null>(null);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [tags, setTags] = useState("");

  // Load templates
  useEffect(() => {
    api.getReportTemplates().then(setTemplates).catch(() => {});
  }, []);

  const selectedType = TYPE_OPTIONS.find((t) => t.value === reportType);
  const selectedTemplate = reportType ? templates[reportType] : null;

  const handleCreate = async () => {
    if (!reportType) {
      setError("Please select a report type");
      return;
    }
    if (!title.trim()) {
      setError("Title is required");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      // Build sections from template (blank bodies — user fills in detail page)
      const tmpl = templates[reportType];
      const sections = tmpl
        ? tmpl.sections.map((s) => ({
            key: s.key,
            title: s.title,
            hint: s.hint,
            body: "",
          }))
        : [];

      const data: ReportCreate = {
        title: title.trim(),
        report_type: reportType,
        severity,
        tlp,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        content: { sections },
      };
      const report = await api.createReport(data);
      router.push(`/reports/${report.id}`);
    } catch (e: any) {
      setError(e.message || "Failed to create report");
      setSaving(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={() => router.push("/reports")}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Create Report</h1>
          <p className="text-sm text-muted-foreground">
            Select a type, give it a title, and start writing
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Step 1 ─ Report Type */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center h-6 w-6 rounded-full bg-primary/10 text-primary text-xs font-bold">1</span>
          <h2 className="text-sm font-semibold">Choose Report Type</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {TYPE_OPTIONS.map((opt) => {
            const Icon = opt.icon;
            const isSelected = reportType === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => {
                  setReportType(opt.value);
                  setError(null);
                }}
                className={`relative flex items-start gap-3 p-4 rounded-xl border-2 text-left transition-all ${
                  isSelected
                    ? `${opt.color} ring-1 ring-current/20 bg-opacity-10`
                    : `border-border/50 hover:border-border ${opt.color.split(" ").slice(0, 1).join(" ")} opacity-70 hover:opacity-100`
                }`}
              >
                {isSelected && (
                  <span className="absolute top-2 right-2 h-2 w-2 rounded-full bg-current animate-pulse" />
                )}
                <div className={`mt-0.5 shrink-0 ${isSelected ? "" : "opacity-60"}`}>
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="font-medium text-sm">{opt.label}</div>
                  <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{opt.desc}</p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Template preview hint */}
      {selectedTemplate && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-primary/5 border border-primary/10 text-xs text-muted-foreground">
          <Sparkles className="h-3.5 w-3.5 mt-0.5 text-primary shrink-0" />
          <span>
            <strong className="text-foreground">{selectedType?.label}</strong> includes {selectedTemplate.sections.length} pre-built sections:{" "}
            {selectedTemplate.sections.map((s) => s.title).join(" → ")}. You can edit them after creation.
          </span>
        </div>
      )}

      {/* Step 2 ─ Details */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center h-6 w-6 rounded-full bg-primary/10 text-primary text-xs font-bold">2</span>
          <h2 className="text-sm font-semibold">Report Details</h2>
        </div>

        <Card>
          <CardContent className="p-4 space-y-5">
            {/* Title */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Title <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => {
                  setTitle(e.target.value);
                  setError(null);
                }}
                placeholder={
                  reportType === "incident"
                    ? "e.g. Ransomware Incident — LockBit 3.0 Detected"
                    : reportType === "threat_advisory"
                    ? "e.g. APT28 Targeting European Energy Sector"
                    : reportType === "weekly_summary"
                    ? "e.g. Weekly Threat Summary — Feb 22-28, 2026"
                    : reportType === "ioc_bulletin"
                    ? "e.g. IOC Bulletin — Active C2 Infrastructure"
                    : "Enter report title..."
                }
                className="w-full px-3 py-2.5 rounded-lg border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 placeholder:text-muted-foreground/40"
                autoFocus
              />
            </div>

            {/* Severity + TLP row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
              {/* Severity */}
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-2 block">Severity</label>
                <div className="flex flex-wrap gap-1.5">
                  {SEVERITY_OPTIONS.map((s) => (
                    <button
                      key={s.value}
                      onClick={() => setSeverity(s.value)}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                        severity === s.value
                          ? `${s.color} ring-1 ring-current/20`
                          : "border-border/50 text-muted-foreground hover:border-border"
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* TLP */}
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-2 block">
                  Traffic Light Protocol
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {TLP_OPTIONS.map((t) => (
                    <button
                      key={t.value}
                      onClick={() => setTlp(t.value)}
                      className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-medium transition-all ${
                        tlp === t.value
                          ? `${t.color} ring-1 ring-current/20`
                          : "border-border/50 text-muted-foreground hover:border-border"
                      }`}
                      title={t.desc}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Tags */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1 block">
                <Tag className="h-3 w-3" />
                Tags <span className="text-muted-foreground/50 font-normal">(optional, comma-separated)</span>
              </label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="apt28, ransomware, healthcare ..."
                className="w-full px-3 py-2 rounded-lg border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 placeholder:text-muted-foreground/40"
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Create button */}
      <div className="flex items-center justify-between pt-2">
        <p className="text-xs text-muted-foreground flex items-center gap-1">
          <Info className="h-3 w-3" />
          You can fill in section content after creation
        </p>
        <Button
          size="lg"
          onClick={handleCreate}
          disabled={saving || !reportType || !title.trim()}
          className="min-w-[180px]"
        >
          {saving ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Zap className="h-4 w-4 mr-2" />
          )}
          Create Report
          <ChevronRight className="h-4 w-4 ml-1" />
        </Button>
      </div>
    </div>
  );
}
