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
} from "lucide-react";
import * as api from "@/lib/api";

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
];

export default function SettingsPage() {
  const searchParams = useSearchParams();
  const [activeSection, setActiveSection] = useState(searchParams.get("tab") || "general");
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Sidebar nav */}
        <div className="space-y-1">
          {SECTIONS.map((s) => (
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
