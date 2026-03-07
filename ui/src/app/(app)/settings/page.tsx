"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Settings as SettingsIcon,
  Shield,
  Bell,
  Palette,
  Database,
  Key,
  Save,
  Check,
  Trash2,
  Loader2,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Building2,
  Upload,
  Download,
  FileSpreadsheet,
  Globe,
  Server,
  Brain,
  Zap,
  Info,
  RefreshCw,
  Plus,
  X,
  Activity,
  BarChart3,
  MessageSquare,
  ChevronDown,
  ChevronUp,
  FlaskConical,
  Gauge,
  RotateCcw,
} from "lucide-react";
import * as api from "@/lib/api";
import { useAppStore } from "@/store";
import type { AISettings, FallbackProvider } from "@/types";

interface SettingSection {
  id: string;
  title: string;
  icon: React.ReactNode;
  description: string;
}

const SECTIONS: SettingSection[] = [
  {
    id: "general",
    title: "General",
    icon: <SettingsIcon className="h-4 w-4" />,
    description: "Platform name, timezone, and defaults",
  },
  {
    id: "security",
    title: "Security",
    icon: <Shield className="h-4 w-4" />,
    description: "Session, rate limiting, and PII controls",
  },
  {
    id: "notifications",
    title: "Notifications",
    icon: <Bell className="h-4 w-4" />,
    description: "Alerts, rules, and webhook integrations",
  },
  {
    id: "appearance",
    title: "Appearance",
    icon: <Palette className="h-4 w-4" />,
    description: "Theme, layout, and display preferences",
  },
  {
    id: "data",
    title: "Data & Storage",
    icon: <Database className="h-4 w-4" />,
    description: "Retention policies and database settings",
  },
  {
    id: "api",
    title: "API Keys",
    icon: <Key className="h-4 w-4" />,
    description: "External API integration status",
  },
  {
    id: "org",
    title: "Organization",
    icon: <Building2 className="h-4 w-4" />,
    description: "Org profile for personalized threat scoring",
  },
  {
    id: "ai",
    title: "AI Configuration",
    icon: <Brain className="h-4 w-4" />,
    description: "Providers, models, limits, and prompts",
  },
];

export default function SettingsPage() {
  const searchParams = useSearchParams();
  const user = useAppStore((s) => s.user);
  const isAdmin = user?.role === "admin";
  const [activeSection, setActiveSection] = useState(searchParams.get("tab") || "general");
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const visibleSections = isAdmin ? SECTIONS : SECTIONS.filter((s) => s.id !== "ai");

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getUserSettings();
      setSettings(data.settings);
    } catch {
      setError("Failed to load settings");
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const data = await api.updateUserSettings(settings);
      setSettings(data.settings);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setError("Failed to save settings");
    }
    setSaving(false);
  };

  const updateSetting = (key: string, value: unknown) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="p-4 lg:p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <SettingsIcon className="h-5 w-5 text-primary" />
            Settings
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure platform preferences and integrations
          </p>
        </div>
        <div className="flex items-center gap-2">
          {error && (
            <span className="text-[10px] text-red-400 flex items-center gap-1">
              <AlertCircle className="h-3 w-3" /> {error}
            </span>
          )}
          {activeSection !== "ai" && (
          <button
            onClick={handleSave}
            disabled={saving || loading}
            className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {saving ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : saved ? (
              <Check className="h-3.5 w-3.5" />
            ) : (
              <Save className="h-3.5 w-3.5" />
            )}
            {saving ? "Saving..." : saved ? "Saved!" : "Save Changes"}
          </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Sidebar nav */}
        <div className="space-y-1">
          {visibleSections.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveSection(s.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-md text-xs transition-colors text-left ${
                activeSection === s.id
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted/40 hover:text-foreground"
              }`}
            >
              {s.icon}
              <div>
                <p className="font-medium">{s.title}</p>
                <p className="text-[10px] opacity-70 mt-0.5">{s.description}</p>
              </div>
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          {loading ? (
            <Card>
              <CardContent className="py-12 flex items-center justify-center">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </CardContent>
            </Card>
          ) : (
            <>
              {activeSection === "general" && (
                <GeneralSettings settings={settings} onChange={updateSetting} />
              )}
              {activeSection === "security" && (
                <SecuritySettings settings={settings} onChange={updateSetting} />
              )}
              {activeSection === "notifications" && <NotificationSettings />}
              {activeSection === "appearance" && (
                <AppearanceSettings settings={settings} onChange={updateSetting} />
              )}
              {activeSection === "data" && (
                <DataSettings settings={settings} onChange={updateSetting} />
              )}
              {activeSection === "api" && <APISettings />}
              {activeSection === "org" && (
                <OrgProfileSettings settings={settings} onChange={updateSetting} />
              )}
              {activeSection === "ai" && isAdmin && <AIConfigSettings />}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Shared Components ─── */

function SettingField({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between py-3 border-b border-border/30 last:border-0">
      <div className="pr-4">
        <p className="text-xs font-medium">{label}</p>
        {description && (
          <p className="text-[10px] text-muted-foreground mt-0.5">{description}</p>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function ToggleSwitch({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`w-9 h-5 rounded-full transition-colors relative ${
        checked ? "bg-primary" : "bg-muted"
      }`}
    >
      <div
        className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

/* ─── Section Components ─── */

interface SettingsProps {
  settings: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
}

function GeneralSettings({ settings, onChange }: SettingsProps) {
  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">General Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        <SettingField
          label="Platform Name"
          description="Display name shown in header and notifications"
        >
          <input
            type="text"
            value={(settings.platform_name as string) || "IntelWatch"}
            onChange={(e) => onChange("platform_name", e.target.value)}
            className="w-48 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="Timezone"
          description="Default timezone for all timestamps"
        >
          <select
            value={(settings.timezone as string) || "UTC"}
            onChange={(e) => onChange("timezone", e.target.value)}
            className="w-48 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="UTC">UTC</option>
            <option value="US/Eastern">US/Eastern</option>
            <option value="US/Pacific">US/Pacific</option>
            <option value="Europe/London">Europe/London</option>
            <option value="Asia/Kolkata">Asia/Kolkata</option>
            <option value="Asia/Tokyo">Asia/Tokyo</option>
          </select>
        </SettingField>
        <SettingField
          label="Default Risk Threshold"
          description="Minimum risk score to flag as high priority"
        >
          <input
            type="number"
            value={(settings.default_risk_threshold as number) ?? 70}
            onChange={(e) => onChange("default_risk_threshold", parseInt(e.target.value) || 70)}
            className="w-24 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="Auto-refresh Dashboard"
          description="Automatically refresh dashboard data"
        >
          <ToggleSwitch
            checked={settings.auto_refresh !== false}
            onChange={(v) => onChange("auto_refresh", v)}
          />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function SecuritySettings({ settings, onChange }: SettingsProps) {
  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">Security Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        <SettingField
          label="API Authentication"
          description="Require authentication for API endpoints"
        >
          <ToggleSwitch
            checked={settings.api_auth_required !== false}
            onChange={(v) => onChange("api_auth_required", v)}
          />
        </SettingField>
        <SettingField
          label="Session Timeout"
          description="Automatically log out after inactivity"
        >
          <select
            value={(settings.session_timeout as string) || "4 hours"}
            onChange={(e) => onChange("session_timeout", e.target.value)}
            className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="15 minutes">15 minutes</option>
            <option value="30 minutes">30 minutes</option>
            <option value="1 hour">1 hour</option>
            <option value="4 hours">4 hours</option>
            <option value="never">Never</option>
          </select>
        </SettingField>
        <SettingField
          label="Rate Limiting"
          description="Limit API requests per minute"
        >
          <input
            type="number"
            value={(settings.rate_limit as number) ?? 100}
            onChange={(e) => onChange("rate_limit", parseInt(e.target.value) || 100)}
            className="w-24 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="PII Redaction"
          description="Automatically redact personal data in logs"
        >
          <ToggleSwitch
            checked={settings.pii_redaction !== false}
            onChange={(v) => onChange("pii_redaction", v)}
          />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function NotificationSettings() {
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [webhookTestResult, setWebhookTestResult] = useState<{ success?: boolean; error?: string } | null>(null);
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [newRule, setNewRule] = useState({
    name: "",
    description: "",
    rule_type: "threshold",
    conditions: {} as Record<string, any>,
    channels: ["in_app"] as string[],
    cooldown_minutes: 15,
  });

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/v1/notifications/rules", { credentials: "include" });
      if (res.ok) {
        setRules(await res.json());
      }
    } catch {
      // silent
    }
    setLoading(false);
  };

  const handleToggle = async (ruleId: string) => {
    try {
      await fetch(`/api/v1/notifications/rules/${ruleId}/toggle`, {
        method: "POST",
        credentials: "include",
      });
      loadRules();
    } catch {
      // silent
    }
  };

  const handleDelete = async (ruleId: string) => {
    try {
      await fetch(`/api/v1/notifications/rules/${ruleId}`, {
        method: "DELETE",
        credentials: "include",
      });
      loadRules();
    } catch {
      // silent
    }
  };

  const handleCreate = async () => {
    if (!newRule.name.trim()) return;
    try {
      await fetch("/api/v1/notifications/rules", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newRule),
      });
      setShowCreate(false);
      setNewRule({ name: "", description: "", rule_type: "threshold", conditions: {}, channels: ["in_app"], cooldown_minutes: 15 });
      loadRules();
    } catch {
      // silent
    }
  };

  const RULE_TYPE_LABELS: Record<string, string> = {
    threshold: "Threshold",
    feed_error: "Feed Health",
    correlation: "Cross-Feed",
    keyword: "Keyword",
    risk_change: "Risk Change",
  };

  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold">Notification Rules</CardTitle>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="text-[10px] font-medium px-2.5 py-1.5 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
          >
            {showCreate ? "Cancel" : "+ New Rule"}
          </button>
        </div>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        {/* Create form */}
        {showCreate && (
          <div className="p-3 rounded-lg bg-muted/20 border border-border/30 mb-4 space-y-3">
            <input
              type="text"
              placeholder="Rule name"
              value={newRule.name}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              className="w-full h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <input
              type="text"
              placeholder="Description (optional)"
              value={newRule.description}
              onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
              className="w-full h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <div className="flex gap-2">
              <select
                value={newRule.rule_type}
                onChange={(e) => setNewRule({ ...newRule, rule_type: e.target.value })}
                className="h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="threshold">Threshold</option>
                <option value="keyword">Keyword</option>
                <option value="feed_error">Feed Health</option>
                <option value="risk_change">Risk Change</option>
                <option value="correlation">Cross-Feed Correlation</option>
              </select>
              <input
                type="number"
                placeholder="Cooldown (min)"
                value={newRule.cooldown_minutes}
                onChange={(e) => setNewRule({ ...newRule, cooldown_minutes: parseInt(e.target.value) || 15 })}
                className="w-28 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            {/* Condition builder for threshold rules */}
            {newRule.rule_type === "threshold" && (
              <div className="space-y-2">
                <p className="text-[10px] text-muted-foreground font-medium">Conditions</p>
                <div className="flex flex-wrap gap-2">
                  <label className="flex items-center gap-1.5 text-[10px]">
                    <input
                      type="checkbox"
                      className="rounded border-border"
                      checked={!!(newRule.conditions as any).severity?.includes("critical")}
                      onChange={(e) => {
                        const existing: string[] = (newRule.conditions as any).severity || [];
                        const sevs = e.target.checked
                          ? [...existing.filter((s: string) => s !== "critical"), "critical"]
                          : existing.filter((s: string) => s !== "critical");
                        setNewRule({ ...newRule, conditions: { ...newRule.conditions, severity: sevs } });
                      }}
                    />
                    Critical
                  </label>
                  <label className="flex items-center gap-1.5 text-[10px]">
                    <input
                      type="checkbox"
                      className="rounded border-border"
                      checked={!!(newRule.conditions as any).severity?.includes("high")}
                      onChange={(e) => {
                        const existing: string[] = (newRule.conditions as any).severity || [];
                        const sevs = e.target.checked
                          ? [...existing.filter((s: string) => s !== "high"), "high"]
                          : existing.filter((s: string) => s !== "high");
                        setNewRule({ ...newRule, conditions: { ...newRule.conditions, severity: sevs } });
                      }}
                    />
                    High
                  </label>
                  <label className="flex items-center gap-1.5 text-[10px]">
                    <input
                      type="checkbox"
                      className="rounded border-border"
                      checked={!!(newRule.conditions as any).is_kev}
                      onChange={(e) => {
                        setNewRule({ ...newRule, conditions: { ...newRule.conditions, is_kev: e.target.checked || undefined } });
                      }}
                    />
                    KEV only
                  </label>
                </div>
                <div className="flex gap-2">
                  <input
                    type="number"
                    placeholder="Min risk score"
                    value={(newRule.conditions as any).min_risk_score || ""}
                    onChange={(e) => {
                      const val = e.target.value ? parseInt(e.target.value) : undefined;
                      setNewRule({ ...newRule, conditions: { ...newRule.conditions, min_risk_score: val } });
                    }}
                    className="w-32 h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <input
                    type="text"
                    placeholder="CVE IDs (comma-separated)"
                    value={((newRule.conditions as any).cve_ids || []).join(", ")}
                    onChange={(e) => {
                      const cves = e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean);
                      setNewRule({ ...newRule, conditions: { ...newRule.conditions, cve_ids: cves.length ? cves : undefined } });
                    }}
                    className="flex-1 h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
            )}

            {/* Keyword rule conditions */}
            {newRule.rule_type === "keyword" && (
              <div className="space-y-2">
                <p className="text-[10px] text-muted-foreground font-medium">Keywords to match</p>
                <input
                  type="text"
                  placeholder="Keywords (comma-separated, e.g. ransomware, APT28, zero-day)"
                  value={((newRule.conditions as any).keywords || []).join(", ")}
                  onChange={(e) => {
                    const kws = e.target.value.split(",").map((s: string) => s.trim()).filter(Boolean);
                    setNewRule({ ...newRule, conditions: { ...newRule.conditions, keywords: kws.length ? kws : undefined } });
                  }}
                  className="w-full h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            )}

            {/* Risk change conditions */}
            {newRule.rule_type === "risk_change" && (
              <div className="space-y-2">
                <p className="text-[10px] text-muted-foreground font-medium">Minimum score change</p>
                <input
                  type="number"
                  placeholder="Min score change (e.g. 20)"
                  value={(newRule.conditions as any).risk_change_min || ""}
                  onChange={(e) => {
                    const val = e.target.value ? parseInt(e.target.value) : undefined;
                    setNewRule({ ...newRule, conditions: { ...newRule.conditions, risk_change_min: val } });
                  }}
                  className="w-40 h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            )}

            {/* Delivery channels */}
            <div className="space-y-2 pt-1 border-t border-border/20">
              <p className="text-[10px] text-muted-foreground font-medium">Delivery Channels</p>
              <div className="flex flex-wrap gap-3">
                <label className="flex items-center gap-1.5 text-[10px]">
                  <input type="checkbox" className="rounded border-border" checked disabled />
                  In-App (always)
                </label>
                <label className="flex items-center gap-1.5 text-[10px]">
                  <input
                    type="checkbox"
                    className="rounded border-border"
                    checked={newRule.channels.includes("webhook")}
                    onChange={(e) => {
                      const ch = e.target.checked
                        ? [...newRule.channels, "webhook"]
                        : newRule.channels.filter((c) => c !== "webhook");
                      setNewRule({ ...newRule, channels: ch });
                    }}
                  />
                  Webhook
                </label>
                <label className="flex items-center gap-1.5 text-[10px]">
                  <input
                    type="checkbox"
                    className="rounded border-border"
                    checked={newRule.channels.includes("slack")}
                    onChange={(e) => {
                      const ch = e.target.checked
                        ? [...newRule.channels, "slack"]
                        : newRule.channels.filter((c) => c !== "slack");
                      setNewRule({ ...newRule, channels: ch });
                    }}
                  />
                  Slack
                </label>
              </div>

              {/* Webhook URL config */}
              {(newRule.channels.includes("webhook") || newRule.channels.includes("slack")) && (
                <div className="space-y-2">
                  <input
                    type="url"
                    placeholder="Webhook URL (https://...)"
                    value={(newRule.conditions as any).webhook_url || ""}
                    onChange={(e) =>
                      setNewRule({ ...newRule, conditions: { ...newRule.conditions, webhook_url: e.target.value || undefined } })
                    }
                    className="w-full h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <input
                    type="text"
                    placeholder="HMAC Secret (optional, for signature verification)"
                    value={(newRule.conditions as any).webhook_secret || ""}
                    onChange={(e) =>
                      setNewRule({ ...newRule, conditions: { ...newRule.conditions, webhook_secret: e.target.value || undefined } })
                    }
                    className="w-full h-7 px-2 rounded-md bg-muted/40 border border-border/50 text-[10px] focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <button
                    type="button"
                    disabled={!(newRule.conditions as any).webhook_url || testingWebhook}
                    onClick={async () => {
                      setTestingWebhook(true);
                      setWebhookTestResult(null);
                      try {
                        const url = (newRule.conditions as any).webhook_url;
                        const secret = (newRule.conditions as any).webhook_secret || "";
                        const res = await fetch(
                          `/api/v1/notifications/webhook-test?url=${encodeURIComponent(url)}${secret ? `&secret=${encodeURIComponent(secret)}` : ""}`,
                          { method: "POST", credentials: "include" }
                        );
                        const data = await res.json();
                        setWebhookTestResult(data);
                      } catch {
                        setWebhookTestResult({ success: false, error: "Request failed" });
                      }
                      setTestingWebhook(false);
                    }}
                    className="h-7 px-3 rounded-md bg-blue-600/20 text-blue-400 text-[10px] font-medium hover:bg-blue-600/30 transition-colors disabled:opacity-50"
                  >
                    {testingWebhook ? "Testing..." : "Test Webhook"}
                  </button>
                  {webhookTestResult && (
                    <div className={`text-[10px] flex items-center gap-1 ${webhookTestResult.success ? "text-emerald-400" : "text-red-400"}`}>
                      {webhookTestResult.success ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                      {webhookTestResult.success ? `Webhook delivered (${(webhookTestResult as any).status_code})` : `Failed: ${webhookTestResult.error || "Error"}`}
                    </div>
                  )}
                </div>
              )}
            </div>

            <button
              onClick={handleCreate}
              disabled={!newRule.name.trim()}
              className="h-8 px-4 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              Create Rule
            </button>
          </div>
        )}

        {/* Rules list */}
        {loading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 rounded-lg bg-muted/20 animate-pulse" />
            ))}
          </div>
        ) : rules.length === 0 ? (
          <p className="text-xs text-muted-foreground py-6 text-center">
            No notification rules configured. System defaults will be created automatically.
          </p>
        ) : (
          <div className="space-y-2">
            {rules.map((rule: any) => (
              <div
                key={rule.id}
                className="flex items-center justify-between p-3 rounded-lg bg-muted/10 border border-border/20 hover:border-border/40 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-xs font-medium truncate">{rule.name}</p>
                    {rule.is_system && (
                      <Badge variant="outline" className="text-[8px] px-1 py-0">
                        System
                      </Badge>
                    )}
                    <Badge
                      variant="outline"
                      className="text-[8px] px-1 py-0"
                      style={{
                        borderColor: rule.is_active ? "#22c55e" : "#6b7280",
                        color: rule.is_active ? "#22c55e" : "#6b7280",
                      }}
                    >
                      {rule.is_active ? "Active" : "Paused"}
                    </Badge>
                    <span className="text-[9px] text-muted-foreground/50">
                      {RULE_TYPE_LABELS[rule.rule_type] || rule.rule_type}
                    </span>
                  </div>
                  {rule.description && (
                    <p className="text-[10px] text-muted-foreground mt-0.5 truncate">
                      {rule.description}
                    </p>
                  )}
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-[9px] text-muted-foreground/40">
                      Triggered {rule.trigger_count}x
                    </span>
                    <span className="text-[9px] text-muted-foreground/40">
                      Cooldown: {rule.cooldown_minutes}m
                    </span>
                    {rule.channels?.filter((c: string) => c !== "in_app").map((ch: string) => (
                      <Badge key={ch} variant="outline" className="text-[8px] px-1 py-0 border-blue-500/40 text-blue-400">
                        {ch}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0 ml-3">
                  <button
                    onClick={() => handleToggle(rule.id)}
                    className={`w-9 h-5 rounded-full transition-colors relative ${
                      rule.is_active ? "bg-primary" : "bg-muted"
                    }`}
                  >
                    <div
                      className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                        rule.is_active ? "translate-x-4" : "translate-x-0.5"
                      }`}
                    />
                  </button>
                  {!rule.is_system && (
                    <button
                      onClick={() => handleDelete(rule.id)}
                      className="p-1.5 rounded hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors"
                      title="Delete rule"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AppearanceSettings({ settings, onChange }: SettingsProps) {
  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">Appearance Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        <SettingField label="Theme" description="Visual theme preference">
          <select
            value={(settings.theme as string) || "dark"}
            onChange={(e) => onChange("theme", e.target.value)}
            className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="dark">Dark (Default)</option>
            <option value="light">Light</option>
            <option value="system">System</option>
          </select>
        </SettingField>
        <SettingField
          label="Compact Mode"
          description="Reduce spacing for denser layout"
        >
          <ToggleSwitch
            checked={!!settings.compact_mode}
            onChange={(v) => onChange("compact_mode", v)}
          />
        </SettingField>
        <SettingField
          label="Show Risk Scores"
          description="Display risk scores in item lists"
        >
          <ToggleSwitch
            checked={settings.show_risk_scores !== false}
            onChange={(v) => onChange("show_risk_scores", v)}
          />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function DataSettings({ settings, onChange }: SettingsProps) {
  const [feedMsg, setFeedMsg] = useState<string | null>(null);
  const [feedRunning, setFeedRunning] = useState(false);

  const handleRunAllFeeds = async () => {
    setFeedRunning(true);
    setFeedMsg(null);
    try {
      await api.triggerAllFeeds();
      setFeedMsg("All feed jobs queued successfully");
      setTimeout(() => setFeedMsg(null), 4000);
    } catch {
      setFeedMsg("Failed to queue feed jobs");
      setTimeout(() => setFeedMsg(null), 4000);
    }
    setFeedRunning(false);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2 pt-4 px-5">
          <CardTitle className="text-sm font-semibold">Data & Storage</CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-4">
          <SettingField
            label="Data Retention"
            description="Automatically delete items older than"
          >
            <select
              value={(settings.data_retention as string) || "never"}
              onChange={(e) => onChange("data_retention", e.target.value)}
              className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="30 days">30 days</option>
              <option value="90 days">90 days</option>
              <option value="180 days">180 days</option>
              <option value="1 year">1 year</option>
              <option value="never">Never</option>
            </select>
          </SettingField>
          <SettingField
            label="Deduplication"
            description="Skip duplicate intel items during ingestion"
          >
            <ToggleSwitch
              checked={settings.deduplication !== false}
              onChange={(v) => onChange("deduplication", v)}
            />
          </SettingField>
          <SettingField
            label="OpenSearch Sync"
            description="Sync ingested items to OpenSearch index"
          >
            <ToggleSwitch
              checked={settings.opensearch_sync !== false}
              onChange={(v) => onChange("opensearch_sync", v)}
            />
          </SettingField>
        </CardContent>
      </Card>

      {/* Feed Ingestion Actions */}
      <Card>
        <CardHeader className="pb-2 pt-4 px-5">
          <CardTitle className="text-sm font-semibold">Feed Ingestion</CardTitle>
        </CardHeader>
        <CardContent className="px-5 pb-4">
          <SettingField
            label="Run All Feeds"
            description="Manually queue all feed ingestion jobs now"
          >
            <div className="flex items-center gap-2">
              {feedMsg && (
                <span className={`text-[10px] flex items-center gap-1 ${feedMsg.includes("Failed") ? "text-red-400" : "text-emerald-400"}`}>
                  {feedMsg.includes("Failed") ? <XCircle className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
                  {feedMsg}
                </span>
              )}
              <button
                onClick={handleRunAllFeeds}
                disabled={feedRunning}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary/10 text-primary text-xs font-medium hover:bg-primary/20 transition-colors disabled:opacity-50"
              >
                {feedRunning ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Database className="h-3.5 w-3.5" />
                )}
                {feedRunning ? "Queuing..." : "Run All Feeds"}
              </button>
            </div>
          </SettingField>
        </CardContent>
      </Card>
    </div>
  );
}

function APISettings() {
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [platform, setPlatform] = useState<any>(null);

  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    setLoading(true);
    try {
      const [keyData, platformData] = await Promise.all([
        api.getApiKeyStatus(),
        api.getPlatformInfo(),
      ]);
      setKeys(keyData.keys);
      setPlatform(platformData);
    } catch {
      // silent
    }
    setLoading(false);
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="py-12 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Platform info card */}
      {platform && (
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold">Platform Info</CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-muted-foreground">Version:</span>{" "}
                <span className="font-medium">{platform.version}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Environment:</span>{" "}
                <Badge variant="outline" className="text-[10px] ml-1">
                  {platform.environment}
                </Badge>
              </div>
              <div>
                <span className="text-muted-foreground">Domain:</span>{" "}
                <span className="font-mono text-[10px]">{platform.domain}</span>
              </div>
              <div>
                <span className="text-muted-foreground">AI:</span>{" "}
                {platform.ai_enabled ? (
                  <span className="text-green-400 text-[10px]">
                    {platform.ai_model}
                  </span>
                ) : (
                  <span className="text-muted-foreground/50">Disabled</span>
                )}
              </div>
              <div>
                <span className="text-muted-foreground">Feeds:</span>{" "}
                <span className="font-medium">
                  {platform.active_feeds}/{platform.total_feeds} active
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* API Keys status */}
      <Card>
        <CardHeader className="pb-2 pt-4 px-5">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold">API Keys</CardTitle>
            <span className="text-[10px] text-muted-foreground">
              {keys.filter((k) => k.configured).length}/{keys.length} configured
            </span>
          </div>
          <p className="text-[10px] text-muted-foreground mt-0.5">
            API keys are managed via environment variables on the server. Status shown below is live.
          </p>
        </CardHeader>
        <CardContent className="px-5 pb-4">
          {keys.map((k) => (
            <SettingField
              key={k.name}
              label={k.name}
              description={
                k.configured
                  ? k.masked + (k.model ? ` (${k.model})` : "")
                  : "Not configured — set in .env on server"
              }
            >
              <div className="flex items-center gap-2">
                {k.configured ? (
                  <Badge
                    variant="outline"
                    className="text-[10px] gap-1"
                    style={{ borderColor: "#22c55e", color: "#22c55e" }}
                  >
                    <CheckCircle2 className="h-2.5 w-2.5" />
                    Active
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    className="text-[10px] gap-1"
                    style={{ borderColor: "#6b7280", color: "#6b7280" }}
                  >
                    <XCircle className="h-2.5 w-2.5" />
                    Missing
                  </Badge>
                )}
              </div>
            </SettingField>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

/* ─── Organization Profile ────────────────────────────── */

const SECTOR_OPTIONS = [
  "Finance", "Healthcare", "Government", "Technology", "Energy",
  "Education", "Retail", "Manufacturing", "Telecom", "Defense",
  "Transportation", "Media", "Legal", "Aerospace", "Pharmaceuticals",
];

const REGION_OPTIONS = [
  "North America", "Europe", "Asia Pacific", "Middle East",
  "South America", "Africa", "Central Asia", "Southeast Asia",
];

const COMPLIANCE_OPTIONS = [
  "PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST CSF", "ISO 27001", "SOC 2", "FedRAMP",
];

const CRITICALITY_OPTIONS = ["Critical Infrastructure", "Financial Systems", "PII/PHI Data", "Public-Facing Services", "Internal Only"];

interface AssetEntry { name: string; version?: string; type: "software" | "ip" | "domain" }

function OrgProfileSettings({
  settings,
  onChange,
}: {
  settings: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
}) {
  const prefs = (settings.preferences as Record<string, unknown>) || {};
  const orgSectors = (prefs.org_sectors as string[]) || [];
  const orgRegions = (prefs.org_regions as string[]) || [];
  const orgTechStack = (prefs.org_tech_stack as string[]) || [];
  const orgCompliance = (prefs.org_compliance as string[]) || [];
  const orgCriticality = (prefs.org_criticality as string[]) || [];
  const orgAssets = (prefs.org_assets as AssetEntry[]) || [];
  const [techInput, setTechInput] = useState("");
  const [assetInput, setAssetInput] = useState("");
  const [assetType, setAssetType] = useState<"software" | "ip" | "domain">("software");
  const [exposure, setExposure] = useState<Record<string, any> | null>(null);
  const [loadingExposure, setLoadingExposure] = useState(false);

  const updatePrefs = (key: string, value: unknown) => {
    onChange("preferences", { ...prefs, [key]: value });
  };

  const toggleItem = (key: string, current: string[], item: string) => {
    updatePrefs(key, current.includes(item) ? current.filter((s) => s !== item) : [...current, item]);
  };

  const addTech = () => {
    const v = techInput.trim();
    if (v && !orgTechStack.includes(v)) {
      updatePrefs("org_tech_stack", [...orgTechStack, v]);
    }
    setTechInput("");
  };

  const removeTech = (t: string) => {
    updatePrefs("org_tech_stack", orgTechStack.filter((x) => x !== t));
  };

  const addAsset = () => {
    const v = assetInput.trim();
    if (!v) return;
    const parts = v.split(/\s+/);
    const entry: AssetEntry = { name: parts[0], version: parts[1] || undefined, type: assetType };
    if (!orgAssets.some((a) => a.name === entry.name && a.type === entry.type)) {
      updatePrefs("org_assets", [...orgAssets, entry]);
    }
    setAssetInput("");
  };

  const removeAsset = (idx: number) => {
    updatePrefs("org_assets", orgAssets.filter((_, i) => i !== idx));
  };

  const handleAssetUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      const lines = text.split(/\r?\n/).filter((l) => l.trim());
      const newAssets: AssetEntry[] = [];
      for (const line of lines) {
        const [name, version, type] = line.split(",").map((s) => s.trim());
        if (name) {
          const t = (type === "ip" || type === "domain") ? type : "software";
          if (!orgAssets.some((a) => a.name === name && a.type === t) && !newAssets.some((a) => a.name === name && a.type === t)) {
            newAssets.push({ name, version: version || undefined, type: t as AssetEntry["type"] });
          }
        }
      }
      if (newAssets.length > 0) updatePrefs("org_assets", [...orgAssets, ...newAssets]);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const downloadAssetList = () => {
    const header = "name,version,type";
    const rows = orgAssets.map((a) => `${a.name},${a.version || ""},${a.type}`);
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "asset_list.csv"; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  };

  const checkExposure = async () => {
    setLoadingExposure(true);
    try {
      const data = await api.getOrgExposure(orgSectors, orgRegions, orgTechStack);
      setExposure(data);
    } catch {
      setExposure(null);
    }
    setLoadingExposure(false);
  };

  const downloadExposureExcel = () => {
    if (!exposure) return;
    const lines: string[] = ["Category,Item,Severity,Details"];
    (exposure.targeting_campaigns || []).forEach((c: any) => {
      lines.push(`Campaign,"${c.campaign_name || ""}",${c.severity || ""},Actor: ${c.actor_name || "N/A"}`);
    });
    (exposure.vulnerable_products || []).forEach((p: any) => {
      lines.push(`Vulnerability,"${p.product_name || ""} - ${p.cve_id || ""}",${p.severity || ""},CVSS: ${p.cvss_score ?? "N/A"} KEV: ${p.is_kev ? "Yes" : "No"}`);
    });
    const csv = lines.join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "threat_exposure_report.csv"; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Building2 className="h-4 w-4 text-primary" />
            Organization Profile
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Define your org&apos;s sectors, regions, compliance, and asset inventory for personalized threat exposure scoring.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Sectors */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Industry Sectors</label>
            <div className="flex flex-wrap gap-1.5">
              {SECTOR_OPTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => toggleItem("org_sectors", orgSectors, s)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                    orgSectors.includes(s)
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border/40 text-muted-foreground hover:bg-muted/30"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Regions */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Operating Regions</label>
            <div className="flex flex-wrap gap-1.5">
              {REGION_OPTIONS.map((r) => (
                <button
                  key={r}
                  onClick={() => toggleItem("org_regions", orgRegions, r)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                    orgRegions.includes(r)
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border/40 text-muted-foreground hover:bg-muted/30"
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          {/* Compliance Frameworks */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Compliance Frameworks</label>
            <div className="flex flex-wrap gap-1.5">
              {COMPLIANCE_OPTIONS.map((c) => (
                <button
                  key={c}
                  onClick={() => toggleItem("org_compliance", orgCompliance, c)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                    orgCompliance.includes(c)
                      ? "bg-amber-500 text-white border-amber-500"
                      : "border-border/40 text-muted-foreground hover:bg-muted/30"
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          {/* Criticality */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Asset Criticality</label>
            <div className="flex flex-wrap gap-1.5">
              {CRITICALITY_OPTIONS.map((c) => (
                <button
                  key={c}
                  onClick={() => toggleItem("org_criticality", orgCriticality, c)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                    orgCriticality.includes(c)
                      ? "bg-red-500/80 text-white border-red-500"
                      : "border-border/40 text-muted-foreground hover:bg-muted/30"
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          {/* Tech Stack */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Technology Stack</label>
            <div className="flex items-center gap-2 mb-2">
              <input
                type="text"
                value={techInput}
                onChange={(e) => setTechInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTech(); } }}
                placeholder="Add product or vendor (e.g., Apache, Windows Server, Cisco)"
                className="flex-1 h-8 px-3 rounded-md bg-muted/30 border border-border/40 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
              />
              <button onClick={addTech} className="text-xs px-3 py-1.5 rounded-md bg-primary/10 text-primary hover:bg-primary/20">
                Add
              </button>
            </div>
            {orgTechStack.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {orgTechStack.map((t) => (
                  <span key={t} className="inline-flex items-center gap-1 text-[10px] bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded">
                    {t}
                    <button onClick={() => removeTech(t)} className="hover:text-red-400 ml-0.5">×</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Asset Inventory */}
          <div className="pt-2 border-t border-border/30">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-muted-foreground">Asset Inventory</label>
              <div className="flex items-center gap-1.5">
                <label className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 cursor-pointer transition-colors">
                  <Upload className="h-3 w-3" /> Upload CSV
                  <input type="file" accept=".csv,.txt" onChange={handleAssetUpload} className="hidden" />
                </label>
                {orgAssets.length > 0 && (
                  <button onClick={downloadAssetList} className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-green-500/10 text-green-400 hover:bg-green-500/20 transition-colors">
                    <Download className="h-3 w-3" /> Download CSV
                  </button>
                )}
              </div>
            </div>
            <p className="text-[10px] text-muted-foreground mb-2">CSV format: name,version,type (software/ip/domain). One per line.</p>
            <div className="flex items-center gap-2 mb-2">
              <select value={assetType} onChange={(e) => setAssetType(e.target.value as AssetEntry["type"])} className="h-8 px-2 rounded-md bg-muted/30 border border-border/40 text-xs">
                <option value="software">Software</option>
                <option value="ip">External IP</option>
                <option value="domain">Domain</option>
              </select>
              <input
                type="text"
                value={assetInput}
                onChange={(e) => setAssetInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addAsset(); } }}
                placeholder={assetType === "software" ? "name version (e.g., Apache 2.4.51)" : assetType === "ip" ? "IP address" : "domain.com"}
                className="flex-1 h-8 px-3 rounded-md bg-muted/30 border border-border/40 text-xs placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
              />
              <button onClick={addAsset} className="text-xs px-3 py-1.5 rounded-md bg-primary/10 text-primary hover:bg-primary/20">Add</button>
            </div>
            {orgAssets.length > 0 && (
              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                {orgAssets.map((a, i) => (
                  <span key={i} className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded ${
                    a.type === "ip" ? "bg-orange-500/10 text-orange-400" : a.type === "domain" ? "bg-purple-500/10 text-purple-400" : "bg-blue-500/10 text-blue-400"
                  }`}>
                    {a.type === "ip" ? <Globe className="h-2.5 w-2.5" /> : a.type === "domain" ? <Globe className="h-2.5 w-2.5" /> : <Server className="h-2.5 w-2.5" />}
                    {a.name}{a.version ? ` v${a.version}` : ""}
                    <button onClick={() => removeAsset(i)} className="hover:text-red-400 ml-0.5">×</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Exposure Score */}
          <div className="pt-2 border-t border-border/30">
            <div className="flex items-center gap-3 flex-wrap">
              <button
                onClick={checkExposure}
                disabled={loadingExposure || (orgSectors.length === 0 && orgTechStack.length === 0)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-amber-500/10 text-amber-400 text-xs font-medium hover:bg-amber-500/20 transition-colors disabled:opacity-50"
              >
                {loadingExposure ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Shield className="h-3.5 w-3.5" />}
                Check Threat Exposure
              </button>
              {exposure && (
                <>
                  <div className="flex items-center gap-2">
                    <span className={`text-lg font-bold ${
                      exposure.exposure_score >= 70 ? "text-red-400" : exposure.exposure_score >= 40 ? "text-amber-400" : "text-green-400"
                    }`}>
                      {exposure.exposure_score}/100
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {exposure.stats?.active_campaigns} campaigns · {exposure.stats?.vulnerable_products} products · {exposure.stats?.kev_count} KEV
                    </span>
                  </div>
                  <button
                    onClick={downloadExposureExcel}
                    className="flex items-center gap-1 text-[10px] px-2.5 py-1 rounded bg-green-500/10 text-green-400 hover:bg-green-500/20 transition-colors"
                  >
                    <FileSpreadsheet className="h-3 w-3" /> Export Report
                  </button>
                </>
              )}
            </div>

            {/* Detailed Exposure Breakdown */}
            {exposure && (
              <div className="mt-3 space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2 rounded-md bg-red-500/5 border border-red-500/10 text-center">
                    <div className="text-lg font-bold text-red-400">{exposure.stats?.critical_campaigns ?? 0}</div>
                    <div className="text-[9px] text-muted-foreground">Critical Campaigns</div>
                  </div>
                  <div className="p-2 rounded-md bg-orange-500/5 border border-orange-500/10 text-center">
                    <div className="text-lg font-bold text-orange-400">{exposure.stats?.exploitable_count ?? 0}</div>
                    <div className="text-[9px] text-muted-foreground">Exploitable Vulns</div>
                  </div>
                  <div className="p-2 rounded-md bg-amber-500/5 border border-amber-500/10 text-center">
                    <div className="text-lg font-bold text-amber-400">{exposure.stats?.kev_count ?? 0}</div>
                    <div className="text-[9px] text-muted-foreground">KEV Entries</div>
                  </div>
                  <div className="p-2 rounded-md bg-blue-500/5 border border-blue-500/10 text-center">
                    <div className="text-lg font-bold text-blue-400">{exposure.stats?.vulnerable_products ?? 0}</div>
                    <div className="text-[9px] text-muted-foreground">Exposed Products</div>
                  </div>
                </div>

                {/* Targeting Campaigns */}
                {exposure.targeting_campaigns?.length > 0 && (
                  <div>
                    <h5 className="text-[10px] font-semibold text-muted-foreground mb-1">Targeting Campaigns</h5>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {exposure.targeting_campaigns.slice(0, 8).map((c: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-muted/20">
                          <span className={`px-1.5 py-0.5 rounded font-semibold ${
                            c.severity === "critical" ? "bg-red-500/10 text-red-400" : c.severity === "high" ? "bg-orange-500/10 text-orange-400" : "bg-yellow-500/10 text-yellow-400"
                          }`}>{c.severity}</span>
                          <span className="font-medium">{c.campaign_name}</span>
                          {c.actor_name && <span className="text-red-400">by {c.actor_name}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Vulnerable Products */}
                {exposure.vulnerable_products?.length > 0 && (
                  <div>
                    <h5 className="text-[10px] font-semibold text-muted-foreground mb-1">Vulnerable Products</h5>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {exposure.vulnerable_products.slice(0, 8).map((p: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-muted/20">
                          <span className="font-medium text-blue-400">{p.product_name}</span>
                          <span className="text-primary font-mono">{p.cve_id}</span>
                          {p.is_kev && <span className="bg-red-500/10 text-red-400 px-1 rounded text-[8px] font-bold">KEV</span>}
                          {p.exploit_available && <span className="bg-orange-500/10 text-orange-400 px-1 rounded text-[8px]">Exploit</span>}
                          {p.patch_available && <span className="bg-green-500/10 text-green-400 px-1 rounded text-[8px]">Patch</span>}
                          {p.cvss_score && <span className="text-muted-foreground">CVSS {p.cvss_score}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ─── AI Configuration (Admin) ────────────────────────── */

const AI_FEATURES = [
  {
    key: "intel_summary",
    label: "Intel Summary",
    tip: "Auto-generates a concise AI summary for each intelligence item. Helps analysts quickly understand new threats without reading full descriptions.",
    limitTip: "Max AI summaries per day. Set 0 for unlimited. Each new intel item may trigger one summary call.",
    effects: "Intel list auto-summary, Intel detail page",
    modelTip: "Fast 8B model recommended — outputs are short summaries (~150 tokens).",
  },
  {
    key: "intel_enrichment",
    label: "Intel Enrichment",
    tip: "Deep AI analysis that extracts threat actors, TTPs, MITRE mappings, and actionable recommendations from intel items on demand.",
    limitTip: "Max enrichment requests per day. Enrichment is heavier than summaries (~3000 tokens). Set 0 for unlimited.",
    effects: "Intel detail page \u2018Enrich\u2019 button",
    modelTip: "Large 70B model recommended — complex structured JSON extraction needs higher reasoning.",
  },
  {
    key: "news_enrichment",
    label: "News AI Extraction",
    tip: "Extracts IOCs, CVEs, threat actors, and structured intelligence from ingested news articles automatically.",
    limitTip: "Max news articles processed by AI per day. Each article uses ~3500 tokens. Set 0 for unlimited.",
    effects: "News pipeline ingestion, News detail page",
    modelTip: "Large 70B model recommended — multi-field entity extraction requires strong comprehension.",
  },
  {
    key: "live_lookup",
    label: "Live Lookup",
    tip: "Real-time AI-powered indicator lookups that provide context, risk assessment, and recommendations for IPs, domains, and hashes.",
    limitTip: "Max live lookup queries per day. Each query triggers a provider call. Set 0 for unlimited.",
    effects: "Investigate page, Search results context",
    modelTip: "Fast 8B model recommended — quick response time is critical for interactive lookups.",
  },
  {
    key: "report_gen",
    label: "Report Generation",
    tip: "AI drafts executive threat reports, export summaries, and briefing documents for stakeholder communication.",
    limitTip: "Max AI-generated reports per day. Reports use higher token counts (~4000). Set 0 for unlimited.",
    effects: "Reports page, Report builder AI draft",
    modelTip: "Large 70B model recommended — long-form generation requires coherent multi-paragraph output.",
  },
  {
    key: "briefing_gen",
    label: "Threat Briefing",
    tip: "Generates periodic threat briefings that synthesize recent intelligence into an executive-ready summary with key findings and recommendations.",
    limitTip: "Max threat briefings generated per day. Each briefing analyzes many items at once. Set 0 for unlimited.",
    effects: "Briefings page, Scheduled daily briefings",
    modelTip: "Large 70B model recommended — synthesizes multiple intel items into cohesive narrative.",
  },
] as const;

const PROVIDER_OPTIONS = [
  { value: "groq", label: "Groq" },
  { value: "cerebras", label: "Cerebras" },
  { value: "huggingface", label: "HuggingFace" },
  { value: "gemini", label: "Google Gemini" },
  { value: "openai", label: "OpenAI" },
  { value: "anthropic", label: "Anthropic" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "custom", label: "Custom OpenAI-compatible" },
];

const PROVIDER_INFO: Record<string, { freeLimit: string; models: string[]; note: string }> = {
  groq: {
    freeLimit: "Free: 30 req/min, 14.4K req/day, 6K tokens/min",
    models: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama-3.2-3b-preview", "gemma2-9b-it", "mixtral-8x7b-32768"],
    note: "Fastest free inference. Best for high-volume summarization.",
  },
  cerebras: {
    freeLimit: "Free: 30 req/min, 1K req/day, 60K tokens/min",
    models: ["llama3.1-8b", "llama3.1-70b"],
    note: "Very fast inference. Good fallback for Groq rate limits.",
  },
  huggingface: {
    freeLimit: "Free: 1K req/day (rate varies by model popularity)",
    models: ["mistralai/Mistral-7B-Instruct-v0.3", "meta-llama/Meta-Llama-3-8B-Instruct", "HuggingFaceH4/zephyr-7b-beta"],
    note: "Wide model variety. Slower inference, best as last fallback.",
  },
  gemini: {
    freeLimit: "Free: 15 req/min, 1M tokens/day (Gemini 2.0 Flash)",
    models: ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash", "gemini-1.5-pro"],
    note: "Google AI. Generous free tier via OpenAI-compatible endpoint.",
  },
  openai: {
    freeLimit: "Paid: ~$0.50-$15 per 1M tokens (varies by model)",
    models: ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
    note: "Highest quality. Paid API, no free tier.",
  },
  anthropic: {
    freeLimit: "Paid: ~$3-$15 per 1M tokens (varies by model)",
    models: ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"],
    note: "Strong analysis quality. Paid API, no free tier.",
  },
  ollama: {
    freeLimit: "Local: Unlimited (runs on your hardware)",
    models: ["llama3.1:8b", "llama3.1:70b", "mistral:7b", "phi3:medium"],
    note: "Self-hosted, no API costs. Requires GPU for good performance.",
  },
  custom: {
    freeLimit: "Varies by provider",
    models: [],
    note: "Any OpenAI-compatible API endpoint.",
  },
};

function Tooltip({ text }: { text: string }) {
  const [show, setShow] = useState(false);
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onClick={() => setShow(!show)}
        className="text-muted-foreground hover:text-foreground transition-colors"
      >
        <Info className="h-3 w-3" />
      </button>
      {show && (
        <span className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-1.5 w-56 p-2 rounded-md bg-zinc-900 border border-zinc-700 text-[10px] text-zinc-100 shadow-xl leading-relaxed backdrop-blur-none">
          {text}
        </span>
      )}
    </span>
  );
}

type AISubSection = "provider" | "features" | "limits" | "prompts" | "advanced" | "health";

function getModelGuidance(model: string): { size: string; tempRange: string; tokensRange: string; bestFor: string; note: string } {
  const m = model.toLowerCase();
  if (m.includes("70b") || m.includes("72b") || m.includes("mixtral") || m.includes("32b") || m.includes("405b")) {
    return {
      size: "Large",
      tempRange: "0.2 \u2013 0.4",
      tokensRange: "800 \u2013 4000",
      bestFor: "Enrichment, Reports, Briefings, Complex analysis",
      note: "Higher quality output. Consider using a faster model for summaries and lookups via per-feature overrides.",
    };
  }
  if (m.includes("8b") || m.includes("7b") || m.includes("9b") || m.includes("instant") || m.includes("mini")) {
    return {
      size: "Small / Fast",
      tempRange: "0.1 \u2013 0.3",
      tokensRange: "300 \u2013 800",
      bestFor: "Summaries, Lookups, Quick analysis",
      note: "Fast inference but lower quality for complex tasks. Consider a larger model for enrichment and reports.",
    };
  }
  return {
    size: "Standard",
    tempRange: "0.2 \u2013 0.5",
    tokensRange: "500 \u2013 2000",
    bestFor: "General purpose",
    note: "Adjust temperature and max tokens based on output quality.",
  };
}

function AIConfigSettings() {
  const [cfg, setCfg] = useState<AISettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; status: number; response?: string; error?: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [healthData, setHealthData] = useState<import("@/types").AIHealthProvider[] | null>(null);
  const [usageData, setUsageData] = useState<Record<string, number>>({});
  const [activeSubSection, setActiveSubSection] = useState<AISubSection>("provider");
  const [expandedPrompt, setExpandedPrompt] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [fbTestResults, setFbTestResults] = useState<Record<number, { success: boolean; status: number; response?: string; error?: string } | null>>({});
  const [fbTesting, setFbTesting] = useState<Record<number, boolean>>({});
  const [defaultPrompts, setDefaultPrompts] = useState<Record<string, string>>({});
  const [showDefaultPrompt, setShowDefaultPrompt] = useState<string | null>(null);

  useEffect(() => {
    loadAll();
  }, []);

  const loadAll = async () => {
    setLoading(true);
    try {
      const [settingsData, usage, prompts] = await Promise.all([
        api.getAISettings(),
        api.getAIUsage().catch(() => ({})),
        api.getAIDefaultPrompts().catch(() => ({})),
      ]);
      setCfg(settingsData);
      setUsageData(usage as Record<string, number>);
      setDefaultPrompts(prompts as Record<string, string>);
    } catch (err: any) {
      setError(err?.message === "Forbidden" ? "Admin access required" : "Failed to load AI settings");
    }
    setLoading(false);
  };

  const update = (key: keyof AISettings, value: unknown) => {
    setCfg((prev) => prev ? { ...prev, [key]: value } : prev);
  };

  const handleSave = async () => {
    if (!cfg) return;
    setSaving(true);
    setError(null);
    try {
      const result = await api.updateAISettings(cfg);
      // Preserve real keys — server returns masked values
      result.primary_api_key = cfg.primary_api_key;
      if (result.fallback_providers && cfg.fallback_providers) {
        result.fallback_providers = result.fallback_providers.map((fb, i) => ({
          ...fb,
          key: cfg.fallback_providers[i]?.key || fb.key,
        }));
      }
      setCfg(result);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err: any) {
      setError(err?.message || "Save failed");
    }
    setSaving(false);
  };

  const handleTestProvider = async () => {
    if (!cfg) return;
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testAIProvider({
        url: cfg.primary_api_url,
        key: cfg.primary_api_key,
        model: cfg.primary_model,
        provider_type: "primary",
      });
      setTestResult(result);
    } catch (err: any) {
      setTestResult({ success: false, status: 0, error: err?.message || "Connection failed" });
    }
    setTesting(false);
  };

  const handleCheckHealth = async () => {
    try {
      const result = await api.getAIHealth();
      setHealthData(result.providers);
    } catch {
      setHealthData([{ name: "error", model: "", healthy: false }]);
    }
  };

  const handleResetUsage = async () => {
    try {
      await api.resetAIUsage();
      setUsageData({});
    } catch { /* silent */ }
  };

  const handleResetDefaults = async () => {
    if (!showResetConfirm) {
      setShowResetConfirm(true);
      setTimeout(() => setShowResetConfirm(false), 5000);
      return;
    }
    setResetting(true);
    setShowResetConfirm(false);
    setError(null);
    try {
      const result = await api.resetAIDefaults();
      setCfg(result);
      setSaved(false);
    } catch (err: unknown) {
      setError((err as Error)?.message || "Reset failed");
    }
    setResetting(false);
  };

  const addFallback = () => {
    if (!cfg) return;
    const newFb: FallbackProvider = { name: "groq", url: "", key: "", model: "", timeout: 30, enabled: true };
    update("fallback_providers", [...(cfg.fallback_providers || []), newFb]);
  };

  const handleTestFallback = async (idx: number) => {
    if (!cfg) return;
    const fb = cfg.fallback_providers[idx];
    if (!fb) return;
    setFbTesting((prev) => ({ ...prev, [idx]: true }));
    setFbTestResults((prev) => ({ ...prev, [idx]: null }));
    try {
      const result = await api.testAIProvider({
        url: fb.url,
        key: fb.key,
        model: fb.model.includes(",") ? fb.model.split(",")[0].trim() : fb.model,
        provider_type: String(idx),
      });
      setFbTestResults((prev) => ({ ...prev, [idx]: result }));
    } catch (err: any) {
      setFbTestResults((prev) => ({ ...prev, [idx]: { success: false, status: 0, error: err?.message || "Connection failed" } }));
    }
    setFbTesting((prev) => ({ ...prev, [idx]: false }));
  };

  const updateFallback = (idx: number, field: keyof FallbackProvider, value: unknown) => {
    if (!cfg) return;
    const list = [...(cfg.fallback_providers || [])];
    list[idx] = { ...list[idx], [field]: value };
    update("fallback_providers", list);
  };

  const removeFallback = (idx: number) => {
    if (!cfg) return;
    const list = [...(cfg.fallback_providers || [])];
    list.splice(idx, 1);
    update("fallback_providers", list);
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="py-12 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (error && !cfg) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertCircle className="h-6 w-6 text-red-400 mx-auto mb-2" />
          <p className="text-xs text-red-400">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!cfg) return null;

  const SUB_SECTIONS: { id: AISubSection; label: string; icon: React.ReactNode }[] = [
    { id: "provider", label: "Provider", icon: <Server className="h-3 w-3" /> },
    { id: "features", label: "Features", icon: <Zap className="h-3 w-3" /> },
    { id: "limits", label: "Limits & Usage", icon: <Gauge className="h-3 w-3" /> },
    { id: "prompts", label: "Custom Prompts", icon: <MessageSquare className="h-3 w-3" /> },
    { id: "advanced", label: "Advanced", icon: <FlaskConical className="h-3 w-3" /> },
    { id: "health", label: "Health & Stats", icon: <Activity className="h-3 w-3" /> },
  ];

  return (
    <div className="space-y-4">
      {/* Header bar with save */}
      <Card>
        <CardContent className="py-3 px-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold">AI Configuration</span>
            <Tooltip text="Global AI settings that control all AI-powered features across the platform. Changes take effect within 60 seconds." />
          </div>
          <div className="flex items-center gap-2">
            {/* Master toggle */}
            <span className="text-[10px] text-muted-foreground mr-1">AI Engine</span>
            <ToggleSwitch checked={cfg.ai_enabled} onChange={(v) => update("ai_enabled", v)} />
            {error && (
              <span className="text-[10px] text-red-400 flex items-center gap-1">
                <AlertCircle className="h-3 w-3" /> {error}
              </span>
            )}
            <button
              onClick={handleResetDefaults}
              disabled={resetting}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors disabled:opacity-50 ${
                showResetConfirm
                  ? "bg-red-500/15 text-red-400 hover:bg-red-500/25 border border-red-500/30"
                  : "bg-muted hover:bg-muted/80 text-muted-foreground"
              }`}
            >
              {resetting ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />}
              {resetting ? "Resetting..." : showResetConfirm ? "Confirm Reset?" : "Reset to Defaults"}
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : <Save className="h-3 w-3" />}
              {saving ? "Saving..." : saved ? "Saved!" : "Save"}
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Sub-section tabs */}
      <div className="flex gap-1 flex-wrap">
        {SUB_SECTIONS.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveSubSection(s.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] transition-colors ${
              activeSubSection === s.id
                ? "bg-primary/10 text-primary font-medium"
                : "text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            }`}
          >
            {s.icon} {s.label}
          </button>
        ))}
      </div>

      {/* ── Provider Config ── */}
      {activeSubSection === "provider" && (
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Server className="h-3.5 w-3.5" /> Primary Provider
                <Tooltip text="The main AI provider used for all requests. Fallback providers are tried in order if the primary fails with a rate limit (429) error." />
              </CardTitle>
            </CardHeader>
            <CardContent className="px-5 pb-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-muted-foreground mb-1 block">Provider</label>
                  <select
                    value={cfg.primary_provider}
                    onChange={(e) => update("primary_provider", e.target.value)}
                    className="w-full px-2 py-1.5 rounded-md bg-muted/30 border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    {PROVIDER_OPTIONS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                    Model(s) <Tooltip text="Primary model name. You can enter comma-separated model names; the first is used as default, others as in-provider fallbacks." />
                  </label>
                  <input
                    type="text"
                    value={cfg.primary_model}
                    onChange={(e) => update("primary_model", e.target.value)}
                    placeholder={PROVIDER_INFO[cfg.primary_provider]?.models[0] || "e.g. llama-3.3-70b-versatile"}
                    className="w-full px-2 py-1.5 rounded-md bg-muted/30 border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground mb-1 block">API URL</label>
                <input
                  type="text"
                  value={cfg.primary_api_url}
                  onChange={(e) => update("primary_api_url", e.target.value)}
                  placeholder="https://api.groq.com/openai/v1/chat/completions"
                  className="w-full px-2 py-1.5 rounded-md bg-muted/30 border border-border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-muted-foreground mb-1 block">API Key</label>
                  <input
                    type="password"
                    value={cfg.primary_api_key}
                    onChange={(e) => update("primary_api_key", e.target.value)}
                    placeholder="••••••••"
                    className="w-full px-2 py-1.5 rounded-md bg-muted/30 border border-border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                    Timeout (sec) <Tooltip text="How long to wait for a response before timing out and trying the next provider." />
                  </label>
                  <input
                    type="number"
                    value={cfg.primary_timeout}
                    onChange={(e) => update("primary_timeout", Number(e.target.value))}
                    min={5}
                    max={120}
                    className="w-full px-2 py-1.5 rounded-md bg-muted/30 border border-border text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>
              <div className="flex items-center gap-2 pt-1">
                <button
                  onClick={handleTestProvider}
                  disabled={testing}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-muted hover:bg-muted/80 text-xs transition-colors disabled:opacity-50"
                >
                  {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                  Test Connection
                </button>
                {testResult && (
                  <span className={`text-[10px] flex items-center gap-1 ${testResult.success ? "text-green-400" : "text-red-400"}`}>
                    {testResult.success ? <CheckCircle2 className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                    {testResult.success ? testResult.response || "OK" : testResult.error || `HTTP ${testResult.status}`}
                  </span>
                )}
              </div>
              {PROVIDER_INFO[cfg.primary_provider] && (
                <div className="mt-1 p-2 rounded-md bg-primary/5 border border-primary/10">
                  <p className="text-[10px] text-primary font-medium">{PROVIDER_INFO[cfg.primary_provider].freeLimit}</p>
                  <p className="text-[9px] text-muted-foreground mt-0.5">{PROVIDER_INFO[cfg.primary_provider].note}</p>
                  {PROVIDER_INFO[cfg.primary_provider].models.length > 0 && (
                    <p className="text-[9px] text-muted-foreground mt-0.5">
                      Available models: <span className="font-mono text-foreground/70">{PROVIDER_INFO[cfg.primary_provider].models.join(", ")}</span>
                    </p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Fallback Providers */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  Fallback Chain
                  <Tooltip text="When the primary provider returns a 429 rate limit error, the system automatically tries these providers in order. Disabled providers are skipped." />
                </CardTitle>
                <button onClick={addFallback} className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80">
                  <Plus className="h-3 w-3" /> Add Provider
                </button>
              </div>
            </CardHeader>
            <CardContent className="px-5 pb-4 space-y-3">
              {(!cfg.fallback_providers || cfg.fallback_providers.length === 0) && (
                <p className="text-[10px] text-muted-foreground text-center py-4">No fallback providers configured. The primary provider will be the only option.</p>
              )}
              {(cfg.fallback_providers || []).map((fb, idx) => (
                <div key={idx} className="p-3 rounded-md border border-border/50 bg-muted/10 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-muted-foreground font-medium">Fallback #{idx + 1}</span>
                    <div className="flex items-center gap-2">
                      <ToggleSwitch checked={fb.enabled} onChange={(v) => updateFallback(idx, "enabled", v)} />
                      <button onClick={() => removeFallback(idx)} className="text-red-400 hover:text-red-300">
                        <X className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-muted-foreground mb-0.5 block">Provider</label>
                      <select
                        value={fb.name}
                        onChange={(e) => updateFallback(idx, "name", e.target.value)}
                        className="w-full px-2 py-1 rounded bg-muted/30 border border-border text-[11px] focus:outline-none focus:ring-1 focus:ring-primary"
                      >
                        {PROVIDER_OPTIONS.map((p) => (
                          <option key={p.value} value={p.value}>{p.label}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="text-[10px] text-muted-foreground mb-0.5 flex items-center gap-1">
                        Model(s) <Tooltip text="Enter one model name, or comma-separated for multiple models. First model is used for testing." />
                      </label>
                      <input
                        type="text"
                        value={fb.model}
                        onChange={(e) => updateFallback(idx, "model", e.target.value)}
                        placeholder={PROVIDER_INFO[fb.name]?.models[0] || "model-name"}
                        className="w-full px-2 py-1 rounded bg-muted/30 border border-border text-[11px] focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-muted-foreground mb-0.5 block">API URL</label>
                      <input
                        type="text"
                        value={fb.url}
                        onChange={(e) => updateFallback(idx, "url", e.target.value)}
                        className="w-full px-2 py-1 rounded bg-muted/30 border border-border text-[11px] font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-muted-foreground mb-0.5 block">API Key</label>
                      <input
                        type="password"
                        value={fb.key}
                        onChange={(e) => updateFallback(idx, "key", e.target.value)}
                        className="w-full px-2 py-1 rounded bg-muted/30 border border-border text-[11px] font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <button
                      onClick={() => handleTestFallback(idx)}
                      disabled={fbTesting[idx] || !fb.url || !fb.key || !fb.model}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-muted hover:bg-muted/80 text-[10px] transition-colors disabled:opacity-50"
                    >
                      {fbTesting[idx] ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Zap className="h-2.5 w-2.5" />}
                      Test
                    </button>
                    {fbTestResults[idx] && (
                      <span className={`text-[10px] flex items-center gap-1 ${fbTestResults[idx]!.success ? "text-green-400" : "text-red-400"}`}>
                        {fbTestResults[idx]!.success ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
                        {fbTestResults[idx]!.success ? fbTestResults[idx]!.response || "OK" : fbTestResults[idx]!.error || `HTTP ${fbTestResults[idx]!.status}`}
                      </span>
                    )}
                  </div>
                  {PROVIDER_INFO[fb.name] && (
                    <div className="p-1.5 rounded bg-primary/5 border border-primary/10">
                      <p className="text-[9px] text-primary font-medium">{PROVIDER_INFO[fb.name].freeLimit}</p>
                      <p className="text-[9px] text-muted-foreground">{PROVIDER_INFO[fb.name].note}</p>
                    </div>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Feature Toggles ── */}
      {activeSubSection === "features" && (
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="h-3.5 w-3.5" /> Feature Toggles &amp; Model Overrides
              <Tooltip text="Enable or disable individual AI features. Disabled features return gracefully without calling any AI provider, saving quota and cost. Optionally assign a different model per feature." />
            </CardTitle>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              The master AI toggle must be ON for any feature to work. Leave model blank to use the primary model ({cfg.primary_model}).
            </p>
          </CardHeader>
          <CardContent className="px-5 pb-4">
            {!cfg.ai_enabled && (
              <div className="mb-3 p-2 rounded-md bg-yellow-500/10 border border-yellow-500/20 text-[10px] text-yellow-400 flex items-center gap-1.5">
                <AlertCircle className="h-3 w-3" /> Master AI toggle is OFF. All features are disabled regardless of individual settings.
              </div>
            )}
            {AI_FEATURES.map((f) => {
              const featureKey = `feature_${f.key}` as keyof AISettings;
              const modelKey = `model_${f.key}` as keyof AISettings;
              return (
                <div key={f.key} className="py-3 border-b border-border/30 last:border-0">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium">{f.label}</span>
                      <Tooltip text={f.tip} />
                    </div>
                    <ToggleSwitch
                      checked={cfg[featureKey] as boolean}
                      onChange={(v) => update(featureKey, v)}
                    />
                  </div>
                  <p className="text-[9px] text-muted-foreground mt-1">Effects: {f.effects}</p>
                  <div className="mt-1.5 flex items-center gap-2">
                    <input
                      type="text"
                      value={(cfg[modelKey] as string) || ""}
                      onChange={(e) => update(modelKey, e.target.value)}
                      placeholder={cfg.primary_model || "Primary model"}
                      className="flex-1 max-w-[280px] px-2 py-1 rounded bg-muted/30 border border-border text-[10px] font-mono focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/50"
                    />
                    <Tooltip text={f.modelTip} />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      {/* ── Limits & Usage ── */}
      {/* ── Daily Limits ── */}
      {activeSubSection === "limits" && (
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Gauge className="h-3.5 w-3.5" /> Daily Limits & Usage
              <Tooltip text="Set maximum daily AI calls per feature. Counters reset at midnight UTC. Set 0 for unlimited. Limits prevent runaway costs and quota exhaustion." />
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 pb-4 space-y-3">
            {AI_FEATURES.map((f) => {
              const limitKey = `daily_limit_${f.key}` as keyof AISettings;
              const usageKey = f.key;
              const currentUsage = usageData[usageKey] || 0;
              const limit = (cfg[limitKey] as number) || 0;
              const pct = limit > 0 ? Math.min(100, (currentUsage / limit) * 100) : 0;
              return (
                <div key={f.key} className="flex items-center gap-3 py-2 border-b border-border/30 last:border-0">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium">{f.label}</span>
                      <Tooltip text={f.limitTip} />
                    </div>
                    {limit > 0 && (
                      <div className="mt-1 flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${pct > 90 ? "bg-red-500" : pct > 70 ? "bg-yellow-500" : "bg-primary"}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                          {currentUsage}/{limit}
                        </span>
                      </div>
                    )}
                  </div>
                  <input
                    type="number"
                    value={cfg[limitKey] as number}
                    onChange={(e) => update(limitKey, Number(e.target.value))}
                    min={0}
                    max={100000}
                    className="w-20 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                    placeholder="0"
                  />
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      {/* ── Custom Prompts ── */}
      {activeSubSection === "prompts" && (
        <Card>
          <CardHeader className="pb-2 pt-4 px-5">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <MessageSquare className="h-3.5 w-3.5" /> Custom Prompts
              <Tooltip text="Override the built-in system prompts for each AI feature. Leave empty to use defaults." />
            </CardTitle>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              Use &quot;View Default&quot; to see the built-in prompt for reference.
            </p>
          </CardHeader>
          <CardContent className="px-5 pb-4 space-y-2">
            {AI_FEATURES.map((f) => {
              const promptKey = `prompt_${f.key}` as keyof AISettings;
              const isExpanded = expandedPrompt === f.key;
              const hasCustom = Boolean(cfg[promptKey]);
              const isShowingDefault = showDefaultPrompt === f.key;
              const defaultPrompt = defaultPrompts[f.key] || "";
              return (
                <div key={f.key} className="border border-border/30 rounded-md overflow-hidden">
                  <button
                    onClick={() => setExpandedPrompt(isExpanded ? null : f.key)}
                    className="w-full flex items-center justify-between px-3 py-2 hover:bg-muted/20 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium">{f.label}</span>
                      {hasCustom && (
                        <Badge variant="outline" className="text-[9px] gap-0.5" style={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>
                          Custom
                        </Badge>
                      )}
                    </div>
                    {isExpanded ? <ChevronUp className="h-3 w-3 text-muted-foreground" /> : <ChevronDown className="h-3 w-3 text-muted-foreground" />}
                  </button>
                  {isExpanded && (
                    <div className="px-3 pb-3 space-y-2">
                      <textarea
                        value={(cfg[promptKey] as string) || ""}
                        onChange={(e) => update(promptKey, e.target.value)}
                        placeholder="Leave empty to use default prompt. Enter your custom system prompt here..."
                        rows={6}
                        className="w-full px-2.5 py-2 rounded-md bg-muted/20 border border-border text-[11px] font-mono leading-relaxed focus:outline-none focus:ring-1 focus:ring-primary resize-y"
                      />
                      <div className="flex items-center gap-3">
                        {hasCustom && (
                          <button
                            onClick={() => update(promptKey, "")}
                            className="text-[10px] text-red-400 hover:text-red-300 flex items-center gap-1"
                          >
                            <Trash2 className="h-2.5 w-2.5" /> Clear custom prompt
                          </button>
                        )}
                        {defaultPrompt && (
                          <button
                            onClick={() => setShowDefaultPrompt(isShowingDefault ? null : f.key)}
                            className="text-[10px] text-primary hover:text-primary/80 flex items-center gap-1"
                          >
                            <Info className="h-2.5 w-2.5" />
                            {isShowingDefault ? "Hide Default" : "View Default Prompt"}
                          </button>
                        )}
                      </div>
                      {isShowingDefault && defaultPrompt && (
                        <div className="mt-1 p-2.5 rounded-md bg-muted/30 border border-border/50 max-h-64 overflow-y-auto">
                          <p className="text-[9px] text-muted-foreground font-semibold mb-1.5 uppercase tracking-wider">Built-in Default Prompt (read-only)</p>
                          <pre className="text-[10px] text-muted-foreground font-mono whitespace-pre-wrap leading-relaxed">{defaultPrompt}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      {/* ── Advanced ── */}
      {activeSubSection === "advanced" && (
        <div className="space-y-4">
          {/* Model Guidance Card */}
          {(() => {
            const guidance = getModelGuidance(cfg.primary_model);
            return (
              <Card>
                <CardContent className="px-5 py-3">
                  <div className="flex items-start gap-3">
                    <Brain className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold">
                        Model Guidance: <span className="text-primary font-mono">{cfg.primary_model}</span>{" "}
                        <Badge variant="outline" className="text-[9px] ml-1" style={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}>{guidance.size}</Badge>
                      </p>
                      <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-[10px] text-muted-foreground">
                        <span>Recommended Temperature: <span className="text-foreground font-medium">{guidance.tempRange}</span></span>
                        <span>Recommended Max Tokens: <span className="text-foreground font-medium">{guidance.tokensRange}</span></span>
                        <span>Best For: <span className="text-foreground font-medium">{guidance.bestFor}</span></span>
                      </div>
                      <p className="text-[10px] text-muted-foreground/80">{guidance.note}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FlaskConical className="h-3.5 w-3.5" /> Generation Parameters
                <Tooltip text="Control how the AI generates responses. Temperature affects creativity (0 = deterministic, 1 = creative). Max tokens limits response length." />
              </CardTitle>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                These parameters apply to all AI features globally. Changes take effect within 60 seconds.
              </p>
            </CardHeader>
            <CardContent className="px-5 pb-4 space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[10px] text-muted-foreground flex items-center gap-1">
                    Temperature <Tooltip text="Controls randomness. Lower = more focused and deterministic. Higher = more creative but less predictable. 0.3 is recommended for threat intelligence." />
                  </label>
                  <span className="text-xs font-mono text-primary">{cfg.default_temperature}</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={cfg.default_temperature}
                  onChange={(e) => update("default_temperature", Number(e.target.value))}
                  className="w-full h-1.5 rounded-full appearance-none bg-muted [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:cursor-pointer"
                />
                <div className="flex justify-between text-[9px] text-muted-foreground mt-0.5">
                  <span>Precise (0)</span>
                  <span>Balanced (0.5)</span>
                  <span>Creative (1)</span>
                </div>
              </div>
              <SettingField label="Max Tokens" description="Maximum response length in tokens (~4 chars per token)">
                <input
                  type="number"
                  value={cfg.default_max_tokens}
                  onChange={(e) => update("default_max_tokens", Number(e.target.value))}
                  min={100}
                  max={16000}
                  className="w-24 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </SettingField>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Rate Limiting
                <Tooltip text="Controls how fast the platform sends requests to AI providers. Prevents hitting provider rate limits during batch processing." />
              </CardTitle>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Affects: All AI batch operations (news ingestion, bulk enrichment). Groq free tier allows ~30 req/min.
              </p>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              <SettingField label="Requests per Minute" description="Max AI requests per minute (0 = unlimited)">
                <input
                  type="number"
                  value={cfg.requests_per_minute}
                  onChange={(e) => update("requests_per_minute", Number(e.target.value))}
                  min={0}
                  max={1000}
                  className="w-24 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </SettingField>
              <SettingField label="Batch Delay (ms)" description="Delay between batch AI calls to avoid rate limits">
                <input
                  type="number"
                  value={cfg.batch_delay_ms}
                  onChange={(e) => update("batch_delay_ms", Number(e.target.value))}
                  min={0}
                  max={60000}
                  step={100}
                  className="w-24 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </SettingField>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                Cache TTLs
                <Tooltip text="How long AI responses are cached before regeneration. Longer TTLs reduce API calls but may show stale results. Values in seconds." />
              </CardTitle>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Affects: Intel summaries, enrichments, and lookup results are cached in Redis. 0 = no caching.
              </p>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              <SettingField label="Summary Cache" description="Time to cache AI summaries">
                <div className="flex items-center gap-1.5">
                  <input
                    type="number"
                    value={cfg.cache_ttl_summary}
                    onChange={(e) => update("cache_ttl_summary", Number(e.target.value))}
                    min={0}
                    max={604800}
                    className="w-20 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <span className="text-[10px] text-muted-foreground">{formatTTL(cfg.cache_ttl_summary)}</span>
                </div>
              </SettingField>
              <SettingField label="Enrichment Cache" description="Time to cache AI enrichment results">
                <div className="flex items-center gap-1.5">
                  <input
                    type="number"
                    value={cfg.cache_ttl_enrichment}
                    onChange={(e) => update("cache_ttl_enrichment", Number(e.target.value))}
                    min={0}
                    max={604800}
                    className="w-20 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <span className="text-[10px] text-muted-foreground">{formatTTL(cfg.cache_ttl_enrichment)}</span>
                </div>
              </SettingField>
              <SettingField label="Lookup Cache" description="Time to cache live lookup results">
                <div className="flex items-center gap-1.5">
                  <input
                    type="number"
                    value={cfg.cache_ttl_lookup}
                    onChange={(e) => update("cache_ttl_lookup", Number(e.target.value))}
                    min={0}
                    max={604800}
                    className="w-20 px-2 py-1 rounded-md bg-muted/30 border border-border text-xs text-right focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <span className="text-[10px] text-muted-foreground">{formatTTL(cfg.cache_ttl_lookup)}</span>
                </div>
              </SettingField>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Health & Stats ── */}
      {activeSubSection === "health" && (
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5" /> Provider Health
                  <Tooltip text="Tests connectivity to all configured AI providers and reports their status." />
                </CardTitle>
                <button
                  onClick={handleCheckHealth}
                  className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80"
                >
                  <RefreshCw className="h-3 w-3" /> Check Now
                </button>
              </div>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              {!healthData ? (
                <p className="text-[10px] text-muted-foreground text-center py-4">Click &quot;Check Now&quot; to test provider connectivity.</p>
              ) : (
                <div className="space-y-2">
                  {healthData.map((p) => (
                    <div key={p.name} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                      <div>
                        <span className="text-xs font-medium capitalize">{p.name}</span>
                        {p.model && <span className="text-[10px] text-muted-foreground ml-1.5">({p.model})</span>}
                      </div>
                      <Badge
                        variant="outline"
                        className="text-[10px] gap-1"
                        style={{
                          borderColor: p.healthy ? "#22c55e" : "#ef4444",
                          color: p.healthy ? "#22c55e" : "#ef4444",
                        }}
                      >
                        {p.healthy ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
                        {p.healthy ? "Healthy" : "Unreachable"}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2 pt-4 px-5">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <BarChart3 className="h-3.5 w-3.5" /> Today&apos;s Usage
                  <Tooltip text="Daily AI call counters for each feature. Counters reset at midnight UTC." />
                </CardTitle>
                <button
                  onClick={handleResetUsage}
                  className="flex items-center gap-1 text-[10px] text-red-400 hover:text-red-300 transition-colors"
                >
                  <RefreshCw className="h-3 w-3" /> Reset
                </button>
              </div>
            </CardHeader>
            <CardContent className="px-5 pb-4">
              <div className="space-y-2">
                {AI_FEATURES.map((f) => {
                  const count = usageData[f.key] || 0;
                  const limitKey = `daily_limit_${f.key}` as keyof AISettings;
                  const limit = (cfg[limitKey] as number) || 0;
                  return (
                    <div key={f.key} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                      <span className="text-xs">{f.label}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-medium">{count}</span>
                        {limit > 0 && (
                          <span className="text-[10px] text-muted-foreground">/ {limit}</span>
                        )}
                        {limit > 0 && count >= limit && (
                          <Badge variant="outline" className="text-[9px]" style={{ borderColor: "#ef4444", color: "#ef4444" }}>
                            Limit Reached
                          </Badge>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              {Object.keys(usageData).length === 0 && (
                <p className="text-[10px] text-muted-foreground text-center py-4">No AI usage recorded today.</p>
              )}
            </CardContent>
          </Card>

          {cfg.updated_at && (
            <p className="text-[10px] text-muted-foreground text-center">
              Last updated: {new Date(cfg.updated_at).toLocaleString()}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function formatTTL(seconds: number): string {
  if (seconds <= 0) return "disabled";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}
