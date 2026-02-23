"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAppStore } from "@/store";
import { Loader2, Shield } from "lucide-react";

/**
 * AuthGuard — wraps authenticated pages.
 * Checks session on mount; redirects to /login if not authenticated.
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { isAuthenticated, authChecked, authLoading, checkAuth } = useAppStore();

  useEffect(() => {
    if (!authChecked) {
      checkAuth().then((ok) => {
        if (!ok) {
          router.push("/login");
        }
      });
    }
  }, [authChecked, checkAuth, router]);

  // Redirect if auth check completed and user is not authenticated
  useEffect(() => {
    if (authChecked && !isAuthenticated) {
      router.push("/login");
    }
  }, [authChecked, isAuthenticated, router]);

  // Loading state
  if (!authChecked || authLoading) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4">
        <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-primary/10 border border-primary/20">
          <Shield className="h-6 w-6 text-primary" />
        </div>
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
          <span className="text-sm text-muted-foreground">Loading IntelWatch...</span>
        </div>
      </div>
    );
  }

  // Not authenticated — show nothing (redirect happening)
  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
