"use client";

import React, { useState, useEffect, useCallback } from "react";
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
];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState("general");
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
  return (
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
