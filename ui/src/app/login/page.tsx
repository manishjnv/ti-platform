"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Shield, LogIn, Loader2 } from "lucide-react";
import { useAppStore } from "@/store";
import * as api from "@/lib/api";

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: any) => void;
          renderButton: (element: HTMLElement, config: any) => void;
          prompt: () => void;
        };
      };
    };
  }
}

export default function LoginPage() {
  const router = useRouter();
  const { isAuthenticated, authChecked, performLogin, performGoogleLogin, checkAuth, authLoading, authError } = useAppStore();
  const [authConfig, setAuthConfig] = useState<{
    auth_method: string;
    google_client_id: string | null;
    cf_team_domain: string | null;
    app_name: string;
    environment: string;
    dev_bypass: boolean;
  } | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [googleLoading, setGoogleLoading] = useState(false);

  // Fetch auth config on mount
  useEffect(() => {
    api.getAuthConfig()
      .then(setAuthConfig)
      .catch(() => {})
      .finally(() => setConfigLoading(false));
  }, []);

  // Check existing session
  useEffect(() => {
    if (!authChecked) {
      checkAuth();
    }
  }, [authChecked, checkAuth]);

  // Redirect if already authenticated
  useEffect(() => {
    if (authChecked && isAuthenticated) {
      router.push("/dashboard");
    }
  }, [authChecked, isAuthenticated, router]);

  // Google Sign-In callback
  const handleGoogleCallback = useCallback(async (response: any) => {
    setGoogleLoading(true);
    const success = await performGoogleLogin(response.credential);
    setGoogleLoading(false);
    if (success) {
      router.push("/dashboard");
    }
  }, [performGoogleLogin, router]);

  // Load Google Identity Services script
  useEffect(() => {
    if (!authConfig?.google_client_id) return;

    const existingScript = document.getElementById("google-gsi");
    if (existingScript) return;

    const script = document.createElement("script");
    script.id = "google-gsi";
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => {
      window.google?.accounts.id.initialize({
        client_id: authConfig.google_client_id,
        callback: handleGoogleCallback,
        auto_select: false,
        cancel_on_tap_outside: true,
      });
      // Render the button
      const btnContainer = document.getElementById("google-signin-btn");
      if (btnContainer) {
        window.google?.accounts.id.renderButton(btnContainer, {
          type: "standard",
          theme: "filled_blue",
          size: "large",
          text: "signin_with",
          shape: "rectangular",
          width: 400,
        });
      }
    };
    document.head.appendChild(script);
  }, [authConfig?.google_client_id, handleGoogleCallback]);

  const handleLogin = async () => {
    const success = await performLogin();
    if (success) {
      router.push("/dashboard");
    }
  };

  if (configLoading || (!authChecked && authLoading)) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (isAuthenticated) {
    return null; // Will redirect
  }

  const isDevMode = authConfig?.dev_bypass || authConfig?.environment === "development";
  const isGoogle = authConfig?.auth_method === "google";

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Background pattern */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/3 rounded-full blur-[100px]" />
      </div>

      <div className="flex-1 flex items-center justify-center px-4 relative z-10">
        <div className="w-full max-w-md">
          {/* Logo & Branding */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 mb-4">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">IntelWatch</h1>
            <p className="text-sm text-muted-foreground mt-1">Threat Intelligence Platform</p>
          </div>

          {/* Login Card */}
          <div className="rounded-xl border border-border/50 bg-card/80 backdrop-blur-sm p-6 shadow-xl">
            <div className="text-center mb-6">
              <h2 className="text-lg font-semibold">Welcome back</h2>
              <p className="text-sm text-muted-foreground mt-1">
                Sign in to access your threat intelligence dashboard
              </p>
            </div>

            {/* Error display */}
            {authError && (
              <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-sm text-red-400">
                {authError}
              </div>
            )}

            {/* Google loading state */}
            {googleLoading && (
              <div className="mb-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Signing in with Google...
              </div>
            )}

            {/* Google Sign-In Button (Production) */}
            {isGoogle && (
              <div className="space-y-4">
                <div id="google-signin-btn" className="flex justify-center" />
                <p className="text-[11px] text-muted-foreground text-center">
                  Sign in with your Google account to continue
                </p>
              </div>
            )}

            {/* Divider between Google and Dev */}
            {isGoogle && isDevMode && (
              <div className="relative my-5">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-border/30" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-card px-3 text-muted-foreground/50">or</span>
                </div>
              </div>
            )}

            {/* Dev / Local Login */}
            {(isDevMode || (!isGoogle)) && (
              <div className="space-y-4">
                <button
                  onClick={handleLogin}
                  disabled={authLoading}
                  className="w-full flex items-center justify-center gap-2 h-11 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {authLoading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <LogIn className="h-4 w-4" />
                  )}
                  {isDevMode ? "Sign in (Dev Mode)" : "Sign in"}
                </button>

                {isDevMode && (
                  <div className="flex items-center gap-2 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <div className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
                    <p className="text-[11px] text-amber-400">
                      Development mode — authentication bypass enabled
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Divider */}
            <div className="mt-6 pt-4 border-t border-border/30">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground/60">
                <span>IntelWatch v1.0.0</span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                  {authConfig?.environment || "unknown"}
                </span>
              </div>
            </div>
          </div>

          {/* Footer links */}
          <div className="text-center mt-6 space-y-2">
            <p className="text-[11px] text-muted-foreground/50">
              Protected by IntelWatch Auth
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
