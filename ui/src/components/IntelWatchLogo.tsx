import React from "react";
import { cn } from "@/lib/utils";

interface IntelWatchLogoProps {
  className?: string;
  /** Width/height in Tailwind class, e.g. "h-7 w-7" */
  size?: string;
}

export function IntelWatchLogo({ className, size = "h-7 w-7" }: IntelWatchLogoProps) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn(size, className)}
    >
      {/* Shield body */}
      <path
        d="M32 4L8 16v16c0 14.4 10.24 27.84 24 32 13.76-4.16 24-17.6 24-32V16L32 4z"
        fill="#0f172a"
        stroke="#3b82f6"
        strokeWidth="2.5"
      />
      {/* Inner glow ring */}
      <circle cx="32" cy="30" r="14" fill="none" stroke="#3b82f6" strokeWidth="2" opacity="0.3" />
      {/* Eye outer */}
      <ellipse cx="32" cy="30" rx="12" ry="8" fill="none" stroke="#60a5fa" strokeWidth="2" />
      {/* Iris */}
      <circle cx="32" cy="30" r="5" fill="#3b82f6" />
      {/* Pupil */}
      <circle cx="32" cy="30" r="2.2" fill="#0f172a" />
      {/* Light reflection */}
      <circle cx="33.5" cy="28.5" r="1.2" fill="#bfdbfe" opacity="0.8" />
      {/* Scan lines */}
      <line x1="20" y1="30" x2="14" y2="30" stroke="#3b82f6" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
      <line x1="44" y1="30" x2="50" y2="30" stroke="#3b82f6" strokeWidth="1.5" strokeLinecap="round" opacity="0.5" />
    </svg>
  );
}
