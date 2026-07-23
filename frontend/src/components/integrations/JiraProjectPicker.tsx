'use client';

import { useEffect, useRef, useState } from 'react';
import { Loader2, Search, Check } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { api, type JiraProject } from '@/lib/api';
import { cn } from '@/lib/utils';

interface JiraProjectPickerProps {
  /** Organization to scope the Jira integration (admin override). */
  orgId?: number;
  value: string;
  onChange: (projectKey: string, project?: JiraProject) => void;
  disabled?: boolean;
  placeholder?: string;
  /** Only fetch when true — use after credentials are saved. */
  enabled?: boolean;
}

/**
 * Searchable Jira project picker.
 * Uses server-side query against Jira so large instances (hundreds of projects)
 * can still find e.g. "IT: Vulnerability Management" / ITVM.
 */
export function JiraProjectPicker({
  orgId,
  value,
  onChange,
  disabled,
  placeholder = 'Search projects by name or key…',
  enabled = true,
}: JiraProjectPickerProps) {
  const [query, setQuery] = useState('');
  const [projects, setProjects] = useState<JiraProject[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const selected = projects.find((p) => p.key === value);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const handle = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getJiraProjects(orgId, query || undefined);
        if (!cancelled) setProjects(data.projects || []);
      } catch (err: any) {
        if (!cancelled) {
          setProjects([]);
          setError(err?.response?.status === 404
            ? 'Save Jira credentials first to load projects.'
            : 'Could not load projects from Jira.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, query ? 300 : 0);
    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [orgId, query, enabled]);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  if (!enabled) {
    return (
      <Input
        placeholder="e.g. ITVM"
        value={value}
        onChange={(e) => onChange(e.target.value.toUpperCase())}
        disabled={disabled}
      />
    );
  }

  return (
    <div ref={containerRef} className="relative space-y-1.5">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          className="pl-8"
          placeholder={placeholder}
          value={open ? query : (selected ? `${selected.key} — ${selected.name}` : value)}
          disabled={disabled}
          onFocus={() => {
            setOpen(true);
            setQuery('');
          }}
          onChange={(e) => {
            setOpen(true);
            setQuery(e.target.value);
            // Allow typing a raw key even if search hasn't resolved yet
            if (!open) onChange(e.target.value.toUpperCase());
          }}
        />
        {loading && (
          <Loader2 className="absolute right-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 animate-spin text-muted-foreground" />
        )}
      </div>

      {open && (
        <div className="absolute z-50 mt-1 w-full max-h-56 overflow-y-auto rounded-md border border-border bg-popover shadow-md">
          {error && (
            <p className="px-3 py-2 text-xs text-muted-foreground">{error}</p>
          )}
          {!error && !loading && projects.length === 0 && (
            <p className="px-3 py-2 text-xs text-muted-foreground">
              {query ? `No projects match “${query}”.` : 'No projects found.'}
            </p>
          )}
          {projects.map((p) => (
            <button
              key={p.key}
              type="button"
              className={cn(
                'w-full flex items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/60',
                value === p.key && 'bg-muted/40',
              )}
              onClick={() => {
                onChange(p.key, p);
                setQuery('');
                setOpen(false);
              }}
            >
              <span className="font-mono text-xs shrink-0 w-16">{p.key}</span>
              <span className="truncate flex-1">{p.name}</span>
              {value === p.key && <Check className="h-3.5 w-3.5 text-primary shrink-0" />}
            </button>
          ))}
          {projects.length >= 100 && (
            <p className="px-3 py-1.5 text-[10px] text-muted-foreground border-t border-border">
              Showing matches — type more of the name or key to narrow results.
            </p>
          )}
        </div>
      )}

      {value && !open && (
        <p className="text-[11px] text-muted-foreground">
          Selected key: <span className="font-mono">{value}</span>
          {selected ? ` — ${selected.name}` : ''}
        </p>
      )}
    </div>
  );
}
