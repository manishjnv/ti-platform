import { create } from "zustand";
import type { IntelItem, DashboardData, User, SearchResponse, IntelListResponse, SearchFilters, Notification, NotificationListResponse } from "@/types";
import * as api from "@/lib/api";

interface AppState {
  // Auth
  isAuthenticated: boolean;
  authChecked: boolean;
  authLoading: boolean;
  authError: string | null;
  checkAuth: () => Promise<boolean>;
  performLogin: () => Promise<boolean>;
  performGoogleLogin: (credential: string) => Promise<boolean>;
  performLogout: () => Promise<void>;

  // User
  user: User | null;
  userLoading: boolean;
  fetchUser: () => Promise<void>;

  // Intel Feed
  intelData: IntelListResponse | null;
  intelLoading: boolean;
  intelPage: number;
  intelFilters: Record<string, string>;
  fetchIntel: (page?: number, filters?: Record<string, string>) => Promise<void>;
  setIntelPage: (page: number) => void;
  setIntelFilters: (filters: Record<string, string>) => void;

  // Dashboard
  dashboard: DashboardData | null;
  dashboardLoading: boolean;
  fetchDashboard: () => Promise<void>;

  // Search
  searchResult: SearchResponse | null;
  searchLoading: boolean;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  executeSearch: (filters: SearchFilters) => Promise<void>;

  // Selected Item
  selectedItem: IntelItem | null;
  selectedLoading: boolean;
  fetchItem: (id: string) => Promise<void>;
  clearSelectedItem: () => void;

  // UI
  sidebarOpen: boolean;
  toggleSidebar: () => void;

  // Notifications
  notifications: Notification[];
  unreadCount: number;
  notificationsLoading: boolean;
  fetchNotifications: (params?: { unread_only?: boolean; limit?: number }) => Promise<void>;
  fetchUnreadCount: () => Promise<void>;
  markRead: (ids: string[]) => Promise<void>;
  markAllRead: () => Promise<void>;

  // Error
  error: string | null;
  clearError: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  // Auth
  isAuthenticated: false,
  authChecked: false,
  authLoading: false,
  authError: null,
  checkAuth: async () => {
    set({ authLoading: true, authError: null });
    try {
      const data = await api.checkSession();
      set({
        isAuthenticated: true,
        authChecked: true,
        authLoading: false,
        user: data.user,
      });
      return true;
    } catch {
      set({
        isAuthenticated: false,
        authChecked: true,
        authLoading: false,
        user: null,
      });
      return false;
    }
  },
  performLogin: async () => {
    set({ authLoading: true, authError: null });
    try {
      const data = await api.login();
      set({
        isAuthenticated: true,
        authChecked: true,
        authLoading: false,
        user: data.user,
      });
      return true;
    } catch (e: any) {
      set({ authLoading: false, authError: e.message });
      return false;
    }
  },
  performGoogleLogin: async (credential: string) => {
    set({ authLoading: true, authError: null });
    try {
      const data = await api.googleLogin(credential);
      set({
        isAuthenticated: true,
        authChecked: true,
        authLoading: false,
        user: data.user,
      });
      return true;
    } catch (e: any) {
      set({ authLoading: false, authError: e.message });
      return false;
    }
  },
  performLogout: async () => {
    try {
      await api.logout();
    } catch {
      // ignore
    }
    // Clear any SSO state so next login requires fresh Google auth
    if (typeof window !== "undefined") {
      localStorage.removeItem("sso_pending");
    }
    set({ isAuthenticated: false, user: null, authChecked: true });
  },

  // User
  user: null,
  userLoading: false,
  fetchUser: async () => {
    set({ userLoading: true });
    try {
      const user = await api.getCurrentUser();
      set({ user, userLoading: false });
    } catch (e: any) {
      set({ userLoading: false, error: e.message });
    }
  },

  // Intel Feed
  intelData: null,
  intelLoading: false,
  intelPage: 1,
  intelFilters: {},
  fetchIntel: async (page, filters) => {
    const p = page ?? get().intelPage;
    const f = filters ?? get().intelFilters;
    set({ intelLoading: true });
    try {
      const data = await api.getIntelItems({ page: p, page_size: 20, ...f });
      set({ intelData: data, intelLoading: false, intelPage: p, intelFilters: f });
    } catch (e: any) {
      set({ intelLoading: false, error: e.message });
    }
  },
  setIntelPage: (page) => set({ intelPage: page }),
  setIntelFilters: (filters) => set({ intelFilters: filters }),

  // Dashboard
  dashboard: null,
  dashboardLoading: false,
  fetchDashboard: async () => {
    set({ dashboardLoading: true });
    try {
      const data = await api.getDashboard();
      set({ dashboard: data, dashboardLoading: false });
    } catch (e: any) {
      set({ dashboardLoading: false, error: e.message });
    }
  },

  // Search
  searchResult: null,
  searchLoading: false,
  searchQuery: "",
  setSearchQuery: (q) => set({ searchQuery: q }),
  executeSearch: async (filters) => {
    set({ searchLoading: true });
    try {
      const data = await api.searchIntel(filters);
      set({ searchResult: data, searchLoading: false });
    } catch (e: any) {
      set({ searchLoading: false, error: e.message });
    }
  },

  // Selected Item
  selectedItem: null,
  selectedLoading: false,
  fetchItem: async (id) => {
    set({ selectedLoading: true });
    try {
      const item = await api.getIntelItem(id);
      set({ selectedItem: item, selectedLoading: false });
    } catch (e: any) {
      set({ selectedLoading: false, error: e.message });
    }
  },
  clearSelectedItem: () => set({ selectedItem: null }),

  // UI
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

  // Notifications
  notifications: [],
  unreadCount: 0,
  notificationsLoading: false,
  fetchNotifications: async (params) => {
    set({ notificationsLoading: true });
    try {
      const data = await api.getNotifications(params);
      set({
        notifications: data.notifications,
        unreadCount: data.unread_count,
        notificationsLoading: false,
      });
    } catch (e: any) {
      set({ notificationsLoading: false });
    }
  },
  fetchUnreadCount: async () => {
    try {
      const data = await api.getUnreadCount();
      set({ unreadCount: data.unread_count });
    } catch {
      // silent
    }
  },
  markRead: async (ids) => {
    try {
      await api.markNotificationsRead(ids);
      set((s) => ({
        notifications: s.notifications.map((n) =>
          ids.includes(n.id) ? { ...n, is_read: true } : n
        ),
        unreadCount: Math.max(0, s.unreadCount - ids.length),
      }));
    } catch {
      // silent
    }
  },
  markAllRead: async () => {
    try {
      await api.markAllNotificationsRead();
      set((s) => ({
        notifications: s.notifications.map((n) => ({ ...n, is_read: true })),
        unreadCount: 0,
      }));
    } catch {
      // silent
    }
  },

  // Error
  error: null,
  clearError: () => set({ error: null }),
}));
