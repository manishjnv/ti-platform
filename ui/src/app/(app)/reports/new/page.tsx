"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Report, ReportCreate, ReportTemplate, ReportType, Severity } from "@/types";
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
  Check,
} from "lucide-react";

const TYPE_OPTIONS: { value: ReportType; label: string; icon: React.ElementType }[] = [
  { value: "incident", label: "Incident Report", icon: AlertTriangle },
  { value: "threat_advisory", label: "Threat Advisory", icon: Shield },
  { value: "weekly_summary", label: "Weekly Summary", icon: BarChart3 },
  { value: "ioc_bulletin", label: "IOC Bulletin", icon: FileWarning },
  { value: "custom", label: "Custom Report", icon: FileText },
];

const SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low", "info"];
const TLP_OPTIONS = ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"];

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

export default function NewReportPage() {
  const router = useRouter();
  const [templates, setTemplates] = useState<Record<string, ReportTemplate>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [title, setTitle] = useState("");
  const [reportType, setReportType] = useState<ReportType>("custom");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [tags, setTags] = useState("");
  const [sections, setSections] = useState<Array<{ key: string; title: string; hint?: string; body: string }>>([]);

  // Load templates
  useEffect(() => {
    api.getReportTemplates().then(setTemplates).catch(() => {});
  }, []);

  // When type changes, load template sections
  useEffect(() => {
    const tmpl = templates[reportType];
    if (tmpl) {
      setSections(
        tmpl.sections.map((s) => ({
          key: s.key,
          title: s.title,
          hint: s.hint,
          body: "",
        }))
      );
    }
  }, [reportType, templates]);

  const handleSave = async () => {
    if (!title.trim()) {
      setError("Title is required");
      return;
    }
    setSaving(true);
    setError(null);
    try {
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

  const updateSection = (index: number, body: string) => {
    setSections((prev) => prev.map((s, i) => (i === index ? { ...s, body } : s)));
  };

  return (
    <div className="p-6 space-y-4 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => router.push("/reports")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">New Report</h1>
            <p className="text-sm text-muted-foreground">
              Create a threat intelligence report
            </p>
          </div>
        </div>
        <Button onClick={handleSave} disabled={saving || !title.trim()}>
          {saving ? (
            <Loader2 className="h-4 w-4 mr-1 animate-spin" />
          ) : (
            <Save className="h-4 w-4 mr-1" />
          )}
          Create Report
        </Button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Report Type Selection */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">Report Type</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {TYPE_OPTIONS.map((opt) => {
              const Icon = opt.icon;
              const isSelected = reportType === opt.value;
              return (
                <button
                  key={opt.value}
                  onClick={() => setReportType(opt.value)}
                  className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border text-xs transition-colors ${
                    isSelected
                      ? "border-primary bg-primary/5 text-primary"
                      : "border-border hover:border-primary/30"
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <span className="text-center leading-tight">{opt.label}</span>
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Title & Metadata */}
      <Card>
        <CardContent className="p-4 space-y-4">
          {/* Title */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Title *</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Enter report title..."
              className="w-full px-3 py-2 rounded-md border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Severity */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Severity</label>
              <div className="flex flex-wrap gap-1">
                {SEVERITY_OPTIONS.map((s) => (
                  <Badge
                    key={s}
                    variant="outline"
                    className={`cursor-pointer text-xs ${severity === s ? SEVERITY_COLORS[s] : ""}`}
                    onClick={() => setSeverity(s)}
                  >
                    {s}
                  </Badge>
                ))}
              </div>
            </div>

            {/* TLP */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">TLP</label>
              <div className="flex flex-wrap gap-1">
                {TLP_OPTIONS.map((t) => (
                  <Badge
                    key={t}
                    variant="outline"
                    className={`cursor-pointer text-[10px] ${tlp === t ? TLP_COLORS[t] : ""}`}
                    onClick={() => setTlp(t)}
                  >
                    {t}
                  </Badge>
                ))}
              </div>
            </div>

            {/* Tags */}
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Tags</label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="tag1, tag2, ..."
                className="w-full px-3 py-1.5 rounded-md border bg-background text-sm"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Sections */}
      {sections.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-medium text-muted-foreground">Sections</h2>
          {sections.map((section, idx) => (
            <Card key={section.key}>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">{section.title}</CardTitle>
                {section.hint && (
                  <p className="text-xs text-muted-foreground">{section.hint}</p>
                )}
              </CardHeader>
              <CardContent>
                <textarea
                  value={section.body}
                  onChange={(e) => updateSection(idx, e.target.value)}
                  placeholder={section.hint || `Write ${section.title.toLowerCase()}...`}
                  rows={4}
                  className="w-full px-3 py-2 rounded-md border bg-background text-sm resize-y focus:outline-none focus:ring-2 focus:ring-primary/30"
                />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
