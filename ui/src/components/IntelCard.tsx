"use client";

import React, { useState } from "react";
import Link from "next/link";
import type { IntelItem } from "@/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { DataTooltip } from "@/components/ui/tooltip";
import {
  cn,
  formatDate,
  severityColor,
  severityBorder,
  riskColor,
  riskBg,
} from "@/lib/utils";
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Shield,
  AlertTriangle,
  Clock,
  Tag,
  Globe,
  Lock,
  Zap,
  Cpu,
  Package,
  Bug,
  Link2,
} from "lucide-react";

interface IntelCardProps {
  item: IntelItem;
}

export function IntelCard({ item }: IntelCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card
      className={cn(
        "border-l-4 transition-all hover:shadow-md cursor-pointer",
        severityBorder(item.severity)
      )}
    >
      <CardContent className="p-4">
        {/* Top Section */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <Badge variant={item.severity as any}>{item.severity.toUpperCase()}</Badge>
              {item.is_kev && (
                <Badge variant="destructive" className="gap-1">
                  <AlertTriangle className="h-3 w-3" /> KEV
                </Badge>
              )}
              {item.exploit_available && (
                <Badge variant="outline" className="text-orange-500 border-orange-500 gap-1">
                  <Zap className="h-3 w-3" /> Exploit
                </Badge>
              )}
              <Badge variant="outline" className="text-xs">{item.feed_type}</Badge>
              <Badge variant="outline" className="text-xs">{item.asset_type}</Badge>
            </div>

            <Link href={`/intel/${item.id}`} className="group">
              <h3 className="text-sm font-semibold leading-tight group-hover:text-primary transition-colors line-clamp-2">
                {item.title}
              </h3>
            </Link>

            {/* AI Summary or regular summary */}
            {(item.ai_summary || item.summary) && (
              <p className="mt-1.5 text-xs text-muted-foreground line-clamp-2">
                {item.ai_summary ? (
                  <span className="inline-flex items-center gap-1">
                    <Cpu className="h-3 w-3 text-purple-400" />
                    {item.ai_summary}
                  </span>
                ) : (
                  item.summary
                )}
              </p>
            )}
          </div>

          {/* Risk Score */}
          <DataTooltip
            label="Risk Score"
            details={{
              "Score": `${item.risk_score}/100`,
              "Scoring": "5-factor weighted: KEV, severity, reliability, freshness, prevalence",
              "Severity": item.severity,
              "Confidence": `${item.confidence}%`,
              "Source": item.source_name,
              "KEV Listed": item.is_kev ? "Yes" : "No",
            }}
            side="left"
          >
            <div
              className={cn(
                "flex flex-col items-center justify-center rounded-lg p-2 min-w-[56px]",
                riskBg(item.risk_score)
              )}
            >
              <span className={cn("text-2xl font-bold", riskColor(item.risk_score))}>
                {item.risk_score}
              </span>
              <span className="text-[10px] text-muted-foreground">RISK</span>
            </div>
          </DataTooltip>
        </div>

        {/* Quick meta row */}
        <div className="flex items-center gap-3 mt-3 text-xs text-muted-foreground flex-wrap">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {formatDate(item.published_at || item.ingested_at, { relative: true })}
          </span>
          <span className="flex items-center gap-1">
            <Shield className="h-3 w-3" />
            {item.source_name}
          </span>
          {item.cve_ids.length > 0 && (
            <span className="text-primary font-medium">{item.cve_ids[0]}</span>
          )}
          {item.cve_ids.length > 1 && (
            <span className="text-muted-foreground">+{item.cve_ids.length - 1}</span>
          )}
          {item.confidence > 0 && (
            <span className="flex items-center gap-1">
              <Shield className="h-3 w-3" /> {item.confidence}%
            </span>
          )}
          {item.related_ioc_count > 0 && (
            <span className="flex items-center gap-1">
              <Link2 className="h-3 w-3" /> {item.related_ioc_count} IOCs
            </span>
          )}
        </div>

        {/* Compact data indicators */}
        {(item.affected_products.length > 0 || (item.exploitability_score != null && item.exploitability_score > 0) || item.tags.length > 0 || item.industries?.length > 0) && (
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            {item.affected_products.length > 0 && (
              <span className="inline-flex items-center gap-1 text-[10px] bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded">
                <Package className="h-2.5 w-2.5" />
                {item.affected_products.slice(0, 2).join(", ")}
                {item.affected_products.length > 2 && ` +${item.affected_products.length - 2}`}
              </span>
            )}
            {item.exploitability_score != null && item.exploitability_score > 0 && (
              <span className={cn(
                "inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded font-mono",
                item.exploitability_score >= 7 ? "bg-red-500/15 text-red-400" :
                item.exploitability_score >= 4 ? "bg-yellow-500/15 text-yellow-400" :
                "bg-green-500/15 text-green-400"
              )}>
                <Bug className="h-2.5 w-2.5" /> CVSS: {item.exploitability_score.toFixed(1)}
              </span>
            )}
            {item.tags.length > 0 && item.tags.slice(0, 3).map((tag) => (
              <span key={tag} className="inline-flex items-center gap-0.5 text-[10px] bg-muted text-muted-foreground px-1.5 py-0.5 rounded">
                <Tag className="h-2 w-2" /> {tag}
              </span>
            ))}
            {item.tags.length > 3 && (
              <span className="text-[10px] text-muted-foreground">+{item.tags.length - 3}</span>
            )}
          </div>
        )}

        {/* Expand toggle */}
        <button
          onClick={(e) => {
            e.preventDefault();
            setExpanded(!expanded);
          }}
          className="flex items-center gap-1 mt-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          {expanded ? "Less" : "More details"}
        </button>

        {/* Collapsible Metadata */}
        {expanded && (
          <div className="mt-3 pt-3 border-t grid grid-cols-2 gap-2 text-xs">
            <MetaField label="Published" value={formatDate(item.published_at)} icon={Clock} />
            <MetaField label="Ingested" value={formatDate(item.ingested_at)} icon={Clock} />
            <MetaField label="Source" value={item.source_name} icon={Shield} />
            <MetaField label="Asset Type" value={item.asset_type} icon={Cpu} />
            <MetaField label="TLP" value={item.tlp} icon={Lock} />
            <MetaField label="Confidence" value={`${item.confidence}%`} icon={Shield} />
            <MetaField label="Reliability" value={`${item.source_reliability}/100`} icon={Shield} />
            <MetaField label="Related IOCs" value={String(item.related_ioc_count)} icon={AlertTriangle} />

            {item.exploitability_score != null && (
              <MetaField label="CVSS" value={String(item.exploitability_score)} icon={Zap} />
            )}

            {item.tags.length > 0 && (
              <div className="col-span-2">
                <span className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Tag className="h-3 w-3" /> Tags
                </span>
                <div className="flex flex-wrap gap-1">
                  {item.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-[10px]">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {item.geo.length > 0 && (
              <div className="col-span-2">
                <span className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Globe className="h-3 w-3" /> Geo
                </span>
                <div className="flex flex-wrap gap-1">
                  {item.geo.map((g) => (
                    <Badge key={g} variant="outline" className="text-[10px]">
                      {g}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {item.affected_products.length > 0 && (
              <div className="col-span-2">
                <span className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Cpu className="h-3 w-3" /> Affected Products
                </span>
                <ul className="list-disc list-inside text-muted-foreground">
                  {item.affected_products.slice(0, 5).map((p) => (
                    <li key={p} className="truncate">{p}</li>
                  ))}
                </ul>
              </div>
            )}

            {item.source_url && (
              <div className="col-span-2">
                <a
                  href={item.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3" /> View Source
                </a>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MetaField({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div>
      <span className="text-muted-foreground flex items-center gap-1">
        <Icon className="h-3 w-3" /> {label}
      </span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
