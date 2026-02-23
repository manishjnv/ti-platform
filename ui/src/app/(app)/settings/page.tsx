"use client";

import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Settings as SettingsIcon,
  Shield,
  Bell,
  Palette,
  Database,
  Key,
  Globe,
  Save,
  Check,
} from "lucide-react";

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
    description: "API keys, authentication, and access controls",
  },
  {
    id: "notifications",
    title: "Notifications",
    icon: <Bell className="h-4 w-4" />,
    description: "Alerts, email, and webhook integrations",
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
    description: "Manage external API integrations",
  },
];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState("general");
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
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
        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-colors"
        >
          {saved ? <Check className="h-3.5 w-3.5" /> : <Save className="h-3.5 w-3.5" />}
          {saved ? "Saved" : "Save Changes"}
        </button>
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
          {activeSection === "general" && <GeneralSettings />}
          {activeSection === "security" && <SecuritySettings />}
          {activeSection === "notifications" && <NotificationSettings />}
          {activeSection === "appearance" && <AppearanceSettings />}
          {activeSection === "data" && <DataSettings />}
          {activeSection === "api" && <APISettings />}
        </div>
      </div>
    </div>
  );
}

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

function ToggleSwitch({ defaultChecked = false }: { defaultChecked?: boolean }) {
  const [on, setOn] = useState(defaultChecked);
  return (
    <button
      onClick={() => setOn(!on)}
      className={`w-9 h-5 rounded-full transition-colors relative ${
        on ? "bg-primary" : "bg-muted"
      }`}
    >
      <div
        className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
          on ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

function GeneralSettings() {
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
            defaultValue="TI Platform"
            className="w-48 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="Timezone"
          description="Default timezone for all timestamps"
        >
          <select className="w-48 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
            <option>UTC</option>
            <option>US/Eastern</option>
            <option>US/Pacific</option>
            <option>Europe/London</option>
            <option>Asia/Tokyo</option>
          </select>
        </SettingField>
        <SettingField
          label="Default Risk Threshold"
          description="Minimum risk score to flag as high priority"
        >
          <input
            type="number"
            defaultValue="70"
            className="w-24 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="Auto-refresh Dashboard"
          description="Automatically refresh dashboard data"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function SecuritySettings() {
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
          <ToggleSwitch defaultChecked />
        </SettingField>
        <SettingField
          label="Session Timeout"
          description="Automatically log out after inactivity"
        >
          <select className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
            <option>15 minutes</option>
            <option>30 minutes</option>
            <option>1 hour</option>
            <option>4 hours</option>
            <option>Never</option>
          </select>
        </SettingField>
        <SettingField
          label="Rate Limiting"
          description="Limit API requests per minute"
        >
          <input
            type="number"
            defaultValue="100"
            className="w-24 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="PII Redaction"
          description="Automatically redact personal data in logs"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function NotificationSettings() {
  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">Notification Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        <SettingField
          label="Critical Alerts"
          description="Get notified for critical severity items"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
        <SettingField
          label="Feed Failures"
          description="Alert when a feed connector fails"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
        <SettingField
          label="Webhook URL"
          description="Send notifications to an external webhook"
        >
          <input
            type="text"
            placeholder="https://..."
            className="w-56 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </SettingField>
        <SettingField
          label="Email Digest"
          description="Daily summary email"
        >
          <ToggleSwitch />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function AppearanceSettings() {
  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">Appearance Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        <SettingField label="Theme" description="Visual theme preference">
          <select className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
            <option>Dark (Default)</option>
            <option>Light</option>
            <option>System</option>
          </select>
        </SettingField>
        <SettingField
          label="Compact Mode"
          description="Reduce spacing for denser layout"
        >
          <ToggleSwitch />
        </SettingField>
        <SettingField
          label="Show Risk Scores"
          description="Display risk scores in item lists"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function DataSettings() {
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
          <select className="w-36 h-8 px-3 rounded-md bg-muted/40 border border-border/50 text-xs focus:outline-none focus:ring-1 focus:ring-primary">
            <option>30 days</option>
            <option>90 days</option>
            <option>180 days</option>
            <option>1 year</option>
            <option>Never</option>
          </select>
        </SettingField>
        <SettingField
          label="Deduplication"
          description="Skip duplicate intel items during ingestion"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
        <SettingField
          label="OpenSearch Sync"
          description="Sync ingested items to OpenSearch index"
        >
          <ToggleSwitch defaultChecked />
        </SettingField>
      </CardContent>
    </Card>
  );
}

function APISettings() {
  const keys = [
    { name: "AbuseIPDB", masked: "••••••••••3f2a", status: "active" },
    { name: "NVD", masked: "••••••••••7b91", status: "active" },
    { name: "VirusTotal", masked: "Not configured", status: "missing" },
    { name: "Shodan", masked: "Not configured", status: "missing" },
  ];

  return (
    <Card>
      <CardHeader className="pb-2 pt-4 px-5">
        <CardTitle className="text-sm font-semibold">API Keys</CardTitle>
      </CardHeader>
      <CardContent className="px-5 pb-4">
        {keys.map((k) => (
          <SettingField
            key={k.name}
            label={k.name}
            description={k.masked}
          >
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className="text-[10px]"
                style={{
                  borderColor: k.status === "active" ? "#22c55e" : "#6b7280",
                  color: k.status === "active" ? "#22c55e" : "#6b7280",
                }}
              >
                {k.status === "active" ? "Active" : "Missing"}
              </Badge>
              <button className="px-2 py-1 rounded text-[10px] bg-muted/40 hover:bg-muted/60 transition-colors">
                {k.status === "active" ? "Update" : "Configure"}
              </button>
            </div>
          </SettingField>
        ))}
      </CardContent>
    </Card>
  );
}
