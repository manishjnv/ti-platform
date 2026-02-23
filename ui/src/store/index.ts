import { create } from "zustand";
import type { IntelItem, DashboardData, User, SearchResponse, IntelListResponse, SearchFilters } from "@/types";
import * as api from "@/lib/api";

interface AppState {
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

  // Error
  error: string | null;
  clearError: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
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

  // Error
  error: null,
  clearError: () => set({ error: null }),
}));
