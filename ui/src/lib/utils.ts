import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateStr: string | null, opts?: { relative?: boolean }): string {
  if (!dateStr) return "N/A";
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return "Invalid date";

  if (opts?.relative) {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
  }

  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

export function severityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "bg-red-500 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-green-500 text-white",
    info: "bg-blue-500 text-white",
    unknown: "bg-gray-400 text-white",
  };
  return colors[severity] || colors.unknown;
}

export function severityBorder(severity: string): string {
  const colors: Record<string, string> = {
    critical: "border-l-red-500",
    high: "border-l-orange-500",
    medium: "border-l-yellow-500",
    low: "border-l-green-500",
    info: "border-l-blue-500",
    unknown: "border-l-gray-400",
  };
  return colors[severity] || colors.unknown;
}

export function riskColor(score: number): string {
  if (score >= 80) return "text-red-500";
  if (score >= 60) return "text-orange-500";
  if (score >= 40) return "text-yellow-500";
  if (score >= 20) return "text-green-500";
  return "text-gray-400";
}

export function riskBg(score: number): string {
  if (score >= 80) return "bg-red-500/10";
  if (score >= 60) return "bg-orange-500/10";
  if (score >= 40) return "bg-yellow-500/10";
  if (score >= 20) return "bg-green-500/10";
  return "bg-gray-500/10";
}
