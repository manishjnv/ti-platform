"use client";

import React, { useState, useCallback, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { useAppStore } from "@/store";
import { IntelCard } from "@/components/IntelCard";
import { Pagination } from "@/components/Pagination";
import { Loading, IntelCardSkeleton } from "@/components/Loading";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { SearchFilters } from "@/types";
import {
  Search as SearchIcon,
  Loader2,
  Target,
  Fingerprint,
  Globe,
  Link,
  Mail,
  Hash,
  AlertCircle,
} from "lucide-react";

const TYPE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  ip: Globe,
  domain: Globe,
  url: Link,
  email: Mail,
  cve: AlertCircle,
  hash_md5: Fingerprint,
  hash_sha1: Fingerprint,
  hash_sha256: Fingerprint,
};

export default function SearchPage() {
  const { searchResult, searchLoading, executeSearch } = useAppStore();
  const searchParams = useSearchParams();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);

  const handleSearch = useCallback(
    (p: number = 1) => {
      if (!query.trim()) return;
      setPage(p);
      const filters: SearchFilters = {
        query: query.trim(),
        page: p,
        page_size: 20,
      };
      executeSearch(filters);
    },
    [query, executeSearch]
  );

  // Read ?q= from URL on mount (from header search)
  useEffect(() => {
    const q = searchParams.get("q");
    if (q && q.trim()) {
      setQuery(q.trim());
      executeSearch({ query: q.trim(), page: 1, page_size: 20 });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch(1);
  };

  const DetectedIcon = searchResult?.detected_type
    ? TYPE_ICONS[searchResult.detected_type] || Target
    : Target;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <SearchIcon className="h-6 w-6 text-primary" />
          Global IOC Search
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Search by CVE, IP, domain, URL, hash, email — auto-detected
        </p>
      </div>

      {/* Search Bar */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search CVE-2024-xxxxx, 8.8.8.8, example.com, SHA256 hash..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="pl-10 h-10"
          />
        </div>
        <Button onClick={() => handleSearch(1)} disabled={searchLoading || !query.trim()}>
          {searchLoading ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <SearchIcon className="h-4 w-4 mr-1" />
          )}
          Search
        </Button>
      </div>

      {/* Results */}
      {searchResult && (
        <div className="space-y-4">
          {/* Result info */}
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted-foreground">
              {searchResult.total.toLocaleString()} results for{" "}
              <span className="font-medium text-foreground">&quot;{searchResult.query}&quot;</span>
            </span>
            {searchResult.detected_type && (
              <Badge variant="secondary" className="gap-1">
                <DetectedIcon className="h-3 w-3" />
                Detected: {searchResult.detected_type}
              </Badge>
            )}
          </div>

          {/* Results list */}
          <div className="space-y-3">
            {searchLoading ? (
              Array.from({ length: 3 }).map((_, i) => <IntelCardSkeleton key={i} />)
            ) : searchResult.results.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center text-muted-foreground">
                  <SearchIcon className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p className="text-lg">No results found</p>
                  <p className="text-sm">
                    Try a different query or check the format of your IOC.
                  </p>
                </CardContent>
              </Card>
            ) : (
              searchResult.results.map((item) => (
                <IntelCard key={item.id} item={item} />
              ))
            )}
          </div>

          {/* Pagination */}
          <Pagination
            page={searchResult.page}
            pages={searchResult.pages}
            onPageChange={(p) => handleSearch(p)}
          />
        </div>
      )}

      {/* Empty state */}
      {!searchResult && !searchLoading && (
        <Card>
          <CardContent className="py-16 text-center">
            <Target className="h-16 w-16 mx-auto mb-4 text-muted-foreground/30" />
            <p className="text-lg font-medium mb-2">Search Threat Intelligence</p>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Enter any indicator of compromise (IOC) — IP address, domain, URL,
              file hash, CVE ID, or email — and the platform will auto-detect the
              type and search across all ingested intelligence.
            </p>
            <div className="flex flex-wrap justify-center gap-2 mt-6">
              {["CVE-2024-3094", "8.8.8.8", "evil.com", "d41d8cd98f00b204e9800998ecf8427e"].map(
                (example) => (
                  <Badge
                    key={example}
                    variant="outline"
                    className="cursor-pointer hover:bg-accent"
                    onClick={() => {
                      setQuery(example);
                    }}
                  >
                    {example}
                  </Badge>
                )
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
