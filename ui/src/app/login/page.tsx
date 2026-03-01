"use client";

import React, { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Mail, ArrowRight, Loader2, KeyRound } from "lucide-react";
import { useAppStore } from "@/store";
import * as api from "@/lib/api";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { isAuthenticated, authChecked, checkAuth, authLoading } = useAppStore();

  const [authConfig, setAuthConfig] = useState<{
    google_configured: boolean;
    email_otp_enabled: boolean;
    app_name: string;
  } | null>(null);
  const [configLoading, setConfigLoading] = useState(true);

  // OTP flow state
  const [otpStep, setOtpStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpLoading, setOtpLoading] = useState(false);
  const [otpError, setOtpError] = useState("");
  const [otpMessage, setOtpMessage] = useState("");

  // Error from URL (e.g., Google OAuth failure)
  const urlError = searchParams.get("error");

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

  const handleGoogleLogin = async () => {
    try {
      const data = await api.getGoogleAuthUrl();
      window.location.href = data.url;
    } catch {
      setOtpError("Failed to initiate Google login. Please try again.");
    }
  };

  const handleSendOTP = async () => {
    if (!email.trim() || !email.includes("@")) {
      setOtpError("Please enter a valid email address.");
      return;
    }
    setOtpLoading(true);
    setOtpError("");
    setOtpMessage("");
    try {
      const data = await api.sendOTP(email.trim().toLowerCase());
      setOtpMessage(data.message);
      setOtpStep("code");
    } catch (e: any) {
      setOtpError(e.message || "Failed to send verification code.");
    } finally {
      setOtpLoading(false);
    }
  };

  const handleVerifyOTP = async () => {
    if (!otpCode.trim() || otpCode.trim().length !== 6) {
      setOtpError("Please enter the 6-digit code.");
      return;
    }
    setOtpLoading(true);
    setOtpError("");
    try {
      const data = await api.verifyOTP(email.trim().toLowerCase(), otpCode.trim());
      // Session cookie is set by the API response — update store
      useAppStore.setState({
        isAuthenticated: true,
        authChecked: true,
        user: data.user,
      });
      router.push("/dashboard");
    } catch (e: any) {
      setOtpError(e.message || "Invalid or expired code.");
    } finally {
      setOtpLoading(false);
    }
  };

  if (configLoading || (!authChecked && authLoading)) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
        </div>
      </div>
    );
  }

  if (isAuthenticated) {
    return null;
  }

  const errorMessages: Record<string, string> = {
    oauth_denied: "Google sign-in was cancelled.",
    oauth_failed: "Google sign-in failed. Please try again.",
    no_code: "Authentication error. Please try again.",
  };

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

            {/* URL error display */}
            {urlError && (
              <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-sm text-red-400">
                {errorMessages[urlError] || "An authentication error occurred."}
              </div>
            )}

            {/* OTP error display */}
            {otpError && (
              <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-sm text-red-400">
                {otpError}
              </div>
            )}

            {/* OTP success message */}
            {otpMessage && !otpError && (
              <div className="mb-4 p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400">
                {otpMessage}
              </div>
            )}

            {/* Google OAuth Button */}
            {authConfig?.google_configured && (
              <div className="space-y-4">
                <button
                  onClick={handleGoogleLogin}
                  className="w-full flex items-center justify-center gap-3 h-11 rounded-lg bg-white text-gray-700 font-medium text-sm border border-gray-300 hover:bg-gray-50 transition-colors shadow-sm"
                >
                  <svg className="h-5 w-5" viewBox="0 0 24 24">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                  </svg>
                  Sign in with Google
                </button>
              </div>
            )}

            {/* Divider */}
            {authConfig?.google_configured && authConfig?.email_otp_enabled && (
              <div className="relative my-5">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-border/30" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-card px-3 text-muted-foreground/50">or</span>
                </div>
              </div>
            )}

            {/* Email OTP Login */}
            {authConfig?.email_otp_enabled && (
              <div className="space-y-3">
                {otpStep === "email" ? (
                  <>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <input
                        type="email"
                        placeholder="Enter your email address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && handleSendOTP()}
                        className="w-full h-11 pl-10 pr-4 rounded-lg bg-background border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50"
                      />
                    </div>
                    <button
                      onClick={handleSendOTP}
                      disabled={otpLoading}
                      className="w-full flex items-center justify-center gap-2 h-11 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors disabled:opacity-50"
                    >
                      {otpLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <ArrowRight className="h-4 w-4" />
                      )}
                      Send Login Code
                    </button>
                  </>
                ) : (
                  <>
                    <div className="flex items-center gap-2 p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 mb-1">
                      <Mail className="h-4 w-4 text-blue-400 shrink-0" />
                      <p className="text-[12px] text-blue-300 truncate">
                        Code sent to <span className="font-medium">{email}</span>
                      </p>
                    </div>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Enter 6-digit code"
                        value={otpCode}
                        onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                        onKeyDown={(e) => e.key === "Enter" && handleVerifyOTP()}
                        maxLength={6}
                        className="w-full h-11 pl-10 pr-4 rounded-lg bg-background border border-border/50 text-sm text-center tracking-[0.3em] font-mono focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary/50"
                        autoFocus
                      />
                    </div>
                    <button
                      onClick={handleVerifyOTP}
                      disabled={otpLoading}
                      className="w-full flex items-center justify-center gap-2 h-11 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors disabled:opacity-50"
                    >
                      {otpLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <ArrowRight className="h-4 w-4" />
                      )}
                      Verify & Sign In
                    </button>
                    <button
                      onClick={() => {
                        setOtpStep("email");
                        setOtpCode("");
                        setOtpError("");
                        setOtpMessage("");
                      }}
                      className="w-full text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Use a different email
                    </button>
                  </>
                )}
              </div>
            )}

            {/* No auth methods configured */}
            {authConfig && !authConfig.google_configured && !authConfig.email_otp_enabled && (
              <div className="text-center p-4">
                <p className="text-sm text-muted-foreground">
                  No authentication methods are configured. Contact your administrator.
                </p>
              </div>
            )}

            {/* Footer */}
            <div className="mt-6 pt-4 border-t border-border/30">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground/60">
                <span>IntelWatch v1.0.0</span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                  Secure
                </span>
              </div>
            </div>
          </div>

          {/* Footer links */}
          <div className="text-center mt-6 space-y-2">
            <p className="text-[11px] text-muted-foreground/50">
              End-to-end encrypted with TLS
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    }>
      <LoginContent />
    </Suspense>
  );
}
