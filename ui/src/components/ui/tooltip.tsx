"use client";

import * as React from "react";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";

const TooltipProvider = TooltipPrimitive.Provider;
const TooltipRoot = TooltipPrimitive.Root;
const TooltipTrigger = TooltipPrimitive.Trigger;

const TooltipContent = React.forwardRef<
  React.ElementRef<typeof TooltipPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>
>(({ className, sideOffset = 4, ...props }, ref) => (
  <TooltipPrimitive.Portal>
    <TooltipPrimitive.Content
      ref={ref}
      sideOffset={sideOffset}
      className={cn(
        "z-50 overflow-hidden rounded-md border border-border/50 bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
        className
      )}
      {...props}
    />
  </TooltipPrimitive.Portal>
));
TooltipContent.displayName = TooltipPrimitive.Content.displayName;

/**
 * Simple Tooltip wrapper component.
 * Per Instruction.md: every data-driven UI element showing a score/status
 * must have a tooltip displaying data source, scoring logic, etc.
 */
interface TooltipProps {
  children: React.ReactNode;
  content: React.ReactNode;
  side?: "top" | "right" | "bottom" | "left";
  delayDuration?: number;
}

export function Tooltip({
  children,
  content,
  side = "top",
  delayDuration = 200,
}: TooltipProps) {
  return (
    <TooltipProvider delayDuration={delayDuration}>
      <TooltipRoot>
        <TooltipTrigger asChild>{children}</TooltipTrigger>
        <TooltipContent side={side} className="max-w-xs">
          {content}
        </TooltipContent>
      </TooltipRoot>
    </TooltipProvider>
  );
}

/**
 * Data tooltip for displaying score/enrichment metadata.
 * Shows structured data in a consistent format per Instruction.md Tooltip System.
 */
interface DataTooltipProps {
  children: React.ReactNode;
  label: string;
  details: Record<string, string | number | boolean | null | undefined>;
  side?: "top" | "right" | "bottom" | "left";
}

export function DataTooltip({
  children,
  label,
  details,
  side = "top",
}: DataTooltipProps) {
  return (
    <Tooltip
      side={side}
      content={
        <div className="space-y-1.5">
          <p className="font-semibold text-xs">{label}</p>
          <div className="space-y-0.5">
            {Object.entries(details).map(([key, value]) =>
              value != null ? (
                <div key={key} className="flex justify-between gap-3 text-[10px]">
                  <span className="text-muted-foreground">{key}:</span>
                  <span className="font-medium text-foreground">
                    {String(value)}
                  </span>
                </div>
              ) : null
            )}
          </div>
        </div>
      }
    >
      {children}
    </Tooltip>
  );
}

export { TooltipProvider, TooltipRoot, TooltipTrigger, TooltipContent };
