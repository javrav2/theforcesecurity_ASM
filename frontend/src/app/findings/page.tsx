'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Shield,
  Search,
  Download,
  Loader2,
  ExternalLink,
  ChevronRight,
  Filter,
  AlertCircle,
  Clock,
  Tag,
  FileCode,
  Target,
  Activity,
  User,
  Calendar,
  Link as LinkIcon,
  Info,
  CheckCircle,
  XCircle,
  Users,
  Flame,
  TrendingUp,
  Sparkles,
  ArrowUpDown,
  RefreshCw,
  Ticket,
} from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV, cn } from '@/lib/utils';
import { RemediationPanel } from '@/components/remediation/RemediationPanel';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface DelphiKEV {
  cve_id: string;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  date_added?: string;
  short_description?: string;
  required_action?: string;
  due_date?: string;
  known_ransomware_use?: string;
  notes?: string;
}

interface DelphiEPSS {
  score: number;
  percentile: number;
  /** display_label replaced 'bucket' — informational only, not used in scoring */
  display_label?: string;
  /** Legacy field kept for backward-compat with old enrichment records */
  bucket?: string;
  date?: string;
  informational_only?: boolean;
  scoring_note?: string;
}

interface DelphiEnrichment {
  kev?: DelphiKEV | null;
  epss?: DelphiEPSS | null;
  priority?: 'critical' | 'high' | 'elevated' | 'moderate' | 'low' | 'none';
  priority_reason?: string;
  priority_signals?: string[];
  enriched_at?: string;
}

interface Finding {
  id: number;
  title: string;
  name?: string;
  template_id: string;
  severity: string;
  host: string;
  matched_at?: string;
  description?: string;
  references?: string[];
  reference?: string[];
  tags?: string[];
  created_at: string;
  updated_at?: string;
  first_detected?: string;
  last_detected?: string;
  // Extended metadata
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  status?: string;
  assigned_to?: string;
  evidence?: string;
  proof_of_concept?: string;
  remediation?: string;
  remediation_deadline?: string;
  detected_by?: string;
  matcher_name?: string;
  asset_id?: number;
  scan_id?: number;
  resolved_at?: string;
  // Delphi (CISA KEV + FIRST EPSS) enrichment
  delphi?: DelphiEnrichment;
  // Aegis Oracle enrichment — denormalised payload persisted by the
  // backend's oracle_enrichment_service. Either a full Phase A+B+OPES
  // analysis (mode='full'), Phase-A intrinsic only (mode='intrinsic'), or
  // ASM-native non-CVE analysis (mode='generic_finding').
  oracle?: OracleEnrichment;
}

interface OracleEnrichment {
  mode: 'full' | 'intrinsic' | 'generic_finding';
  enriched_at?: string;
  analysis_status?: string;
  analysis_error?: string;
  finding_class?: string;
  opes_score?: number;
  opes_category?: 'urgent' | 'critical' | 'high' | 'medium' | 'low' | 'informational';
  opes_label?: string;
  opes_confidence?: 'high' | 'medium' | 'low';
  attack_path_class?: string;
  recommendation_text?: string;
  analyst_brief?: {
    title?: string;
    attack_vector_summary?: string;
    real_world_likelihood?: string;
    exploitability_score?: number;
    exploitability_tier?: string;
  };
}

type SortMode = 'severity' | 'delphi' | 'recent' | 'cvss';

const delphiPriorityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
};

const delphiPriorityStyle: Record<string, { label: string; className: string }> = {
  critical: { label: 'Delphi Critical', className: 'bg-red-600/20 text-red-400 border-red-600/40' },
  high: { label: 'Delphi High', className: 'bg-orange-500/20 text-orange-400 border-orange-500/40' },
  medium: { label: 'Delphi Medium', className: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' },
  low: { label: 'Delphi Low', className: 'bg-blue-500/20 text-blue-400 border-blue-500/40' },
};

function isRansomwareKev(kev?: DelphiKEV | null): boolean {
  const v = (kev?.known_ransomware_use || '').toLowerCase();
  return v === 'known' || v === 'yes';
}

// OPES priority styles — match the colour scheme used on the dedicated
// /oracle page so badges read consistently across the app.
// "urgent" is a manual-only override; the engine never auto-assigns it.
const opesCategoryStyle: Record<string, { label: string; className: string }> = {
  urgent:       { label: 'OPES Urgent',       className: 'bg-purple-600/20 text-purple-300 border-purple-600/40' },
  critical:     { label: 'OPES Critical',     className: 'bg-red-600/20 text-red-300 border-red-600/40' },
  high:         { label: 'OPES High',         className: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
  medium:       { label: 'OPES Medium',       className: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' },
  low:          { label: 'OPES Low',          className: 'bg-blue-500/20 text-blue-300 border-blue-500/40' },
  informational:{ label: 'OPES Info',         className: 'bg-muted text-muted-foreground border-muted-foreground/30' },
};

function OracleBadge({ oracle, compact = false }: { oracle?: OracleEnrichment; compact?: boolean }) {
  if (!oracle || !oracle.opes_category) return null;
  const style = opesCategoryStyle[oracle.opes_category] ?? opesCategoryStyle.informational;
  const score = oracle.opes_score != null ? ` · ${oracle.opes_score.toFixed(1)}` : '';
  const title = [
    `${style.label}${score}`,
    oracle.opes_label,
    oracle.attack_path_class ? `Attack path: ${oracle.attack_path_class}` : null,
    oracle.opes_confidence ? `Confidence: ${oracle.opes_confidence}` : null,
  ].filter(Boolean).join(' · ');
  return (
    <Badge
      variant="outline"
      className={cn('text-[10px] px-1.5 py-0 h-5 border font-semibold', style.className, compact ? '' : '')}
      title={title}
    >
      <Sparkles className="h-3 w-3 mr-0.5" />
      {style.label}{score}
    </Badge>
  );
}

// OracleEnrichmentPanel renders the Aegis Oracle analysis attached to a
// vulnerability. Falls back to a small "no analysis yet" card with an
// "Analyze with Oracle" button so an analyst can request enrichment
// on demand. When enrichment already exists, the button refreshes it
// (force=true) so the analyst can re-run after asset signals change.
function OracleEnrichmentPanel({
  finding,
  onUpdate,
}: {
  finding: Finding | null;
  onUpdate: (oracle: OracleEnrichment) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  if (!finding) return null;

  const oracle = finding.oracle;
  const canEnrich = !!finding.id;

  async function runEnrich(force: boolean) {
    if (!finding || !finding.id) return;
    if (!canEnrich) {
      setError('Oracle cannot run analysis for this finding.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // The single-vuln route returns a summary, but the persisted payload
      // on the row carries the full narrative. Re-fetch the vulnerability
      // would be cleaner but we already get the most useful fields on the
      // response; merge them and trust the next list reload for the full
      // recommendation text.
      const summary = await api.oracleEnrichVulnerability(finding.id, force);
      // We optimistically reflect the new headline data; full narrative
      // becomes available the next time findings are reloaded from /api.
      onUpdate({
        ...(oracle ?? { mode: finding.cve_id ? 'intrinsic' : 'generic_finding' }),
        mode: (summary.mode as OracleEnrichment['mode']) || (finding.cve_id ? 'intrinsic' : 'generic_finding'),
        enriched_at: summary.enriched_at ?? new Date().toISOString(),
        analysis_status: summary.analysis_status ?? oracle?.analysis_status,
        analysis_error: summary.analysis_error ?? oracle?.analysis_error,
        opes_score: summary.opes_score ?? oracle?.opes_score,
        opes_category: (summary.opes_category as OracleEnrichment['opes_category']) ?? oracle?.opes_category,
        opes_label: summary.opes_label ?? oracle?.opes_label,
        attack_path_class: summary.attack_path_class ?? oracle?.attack_path_class,
      });
      toast({
        title: 'Oracle analysis updated',
        description: summary.opes_category
          ? `${summary.opes_category} · ${summary.opes_label ?? ''}`
          : 'Phase-A analysis fetched (no asset linked yet).',
      });
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable.';
      setError(msg);
      toast({ variant: 'destructive', title: 'Oracle enrichment failed', description: msg });
    } finally {
      setBusy(false);
    }
  }

  // No enrichment yet — show a call-to-action card.
  if (!oracle) {
    return (
      <div className="space-y-2">
        <p className="text-sm font-medium flex items-center gap-2 text-orange-300">
          <Sparkles className="h-4 w-4" /> Aegis Oracle
        </p>
        <div className="rounded-lg border bg-orange-500/5 border-orange-500/30 p-3 text-sm">
          <p className="text-muted-foreground">
            No Oracle analysis on this finding yet. Run Oracle to get an OPES
            priority, attack-path classification, analyst brief, and a
            recommendation narrative.
          </p>
          <div className="mt-3 flex items-center gap-2">
            <Button size="sm" disabled={busy || !canEnrich} onClick={() => runEnrich(false)}>
              {busy ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1.5" />}
              Analyze with Oracle
            </Button>
            {error && <span className="text-xs text-red-400">{error}</span>}
          </div>
        </div>
      </div>
    );
  }

  // Enrichment present — render the OPES headline, attack path, analyst brief
  // summary, and the recommendation narrative.
  const style = oracle.opes_category ? opesCategoryStyle[oracle.opes_category] : null;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-sm font-medium flex items-center gap-2 text-orange-300">
          <Sparkles className="h-4 w-4" /> Aegis Oracle
          {oracle.mode === 'intrinsic' && (
            <Badge variant="outline" className="text-[10px] border-yellow-500/40 text-yellow-300">
              Phase-A only (no asset)
            </Badge>
          )}
          {oracle.mode === 'generic_finding' && (
            <Badge variant="outline" className="text-[10px] border-blue-500/40 text-blue-300">
              ASM finding
            </Badge>
          )}
        </p>
        <Button size="sm" variant="outline" disabled={busy || !canEnrich} onClick={() => runEnrich(true)}>
          {busy ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
          Refresh
        </Button>
      </div>

      <div className="rounded-lg border bg-orange-500/5 border-orange-500/30 p-3 space-y-3">
        {oracle.analysis_status === 'failed' && oracle.analysis_error && (
          <div className="rounded border border-red-500/40 bg-red-500/5 p-2 text-xs text-red-300">
            {oracle.analysis_error}
          </div>
        )}

        {/* Headline row: OPES category + score + label + confidence */}
        <div className="flex items-center gap-2 flex-wrap">
          {style && oracle.opes_category && (
            <Badge variant="outline" className={cn('text-xs font-semibold', style.className)}>
              {style.label}
              {oracle.opes_score != null && ` · ${oracle.opes_score.toFixed(1)}`}
            </Badge>
          )}
          {oracle.opes_label && <span className="text-sm">{oracle.opes_label}</span>}
          {oracle.opes_confidence && (
            <span className="text-xs text-muted-foreground">{oracle.opes_confidence} confidence</span>
          )}
          {oracle.attack_path_class && (
            <Badge variant="outline" className="text-[10px]">
              {oracle.attack_path_class.replace(/_/g, ' ')}
            </Badge>
          )}
        </div>

        {/* Analyst brief highlights — single attack-vector summary + likelihood line */}
        {oracle.analyst_brief?.attack_vector_summary && (
          <div className="border-l-2 border-orange-500/50 pl-2 text-xs">
            <p className="text-foreground/90">{oracle.analyst_brief.attack_vector_summary}</p>
          </div>
        )}

        {/* Recommendation narrative — section-headed, monospace so the
            ATTACK PATH / EVIDENCE / NEXT STEPS structure stays legible. */}
        {oracle.recommendation_text && (
          <details className="text-xs" open>
            <summary className="text-muted-foreground cursor-pointer hover:text-foreground">
              Recommendation narrative
            </summary>
            <pre className="mt-2 whitespace-pre-wrap font-mono leading-relaxed text-foreground/80 text-[11px]">
              {oracle.recommendation_text}
            </pre>
          </details>
        )}

        {oracle.enriched_at && (
          <p className="text-[10px] text-muted-foreground">
            Enriched {formatDate(oracle.enriched_at)}
          </p>
        )}
      </div>
    </div>
  );
}

function DelphiBadges({ delphi, compact = false }: { delphi?: DelphiEnrichment; compact?: boolean }) {
  if (!delphi || (!delphi.kev && !delphi.epss)) return null;
  const ransomware = isRansomwareKev(delphi.kev);
  return (
    <div className={cn('flex items-center gap-1 flex-wrap', compact ? '' : 'mt-1')}>
      {delphi.kev && (
        <Badge
          variant="outline"
          className={cn(
            'text-[10px] px-1.5 py-0 h-5 border',
            ransomware
              ? 'bg-red-600/20 text-red-300 border-red-600/40'
              : 'bg-red-500/15 text-red-400 border-red-500/30'
          )}
          title={
            ransomware
              ? 'On CISA KEV — known ransomware use'
              : `On CISA KEV${delphi.kev.date_added ? ` (added ${delphi.kev.date_added})` : ''}`
          }
        >
          <Flame className="h-3 w-3 mr-0.5" />
          {ransomware ? 'KEV · Ransomware' : 'CISA KEV'}
        </Badge>
      )}
      {delphi.epss && (
        <Badge
          variant="outline"
          className="text-[10px] px-1.5 py-0 h-5 border bg-muted/40 text-muted-foreground border-muted-foreground/20"
          title={`EPSS (informational only — not used in scoring)\nScore: ${delphi.epss.score.toFixed(3)} · Percentile: ${(delphi.epss.percentile * 100).toFixed(1)}%\nEPSS is a probabilistic estimate. Priority is driven by KEV status and CVSS analysis.`}
        >
          <TrendingUp className="h-3 w-3 mr-0.5 opacity-60" />
          EPSS {(delphi.epss.percentile * 100).toFixed(0)}%
          <Info className="h-2.5 w-2.5 ml-0.5 opacity-60" />
        </Badge>
      )}
      {!compact && delphi.priority && delphi.priority !== 'none' && delphiPriorityStyle[delphi.priority] && (
        <Badge
          variant="outline"
          className={cn('text-[10px] px-1.5 py-0 h-5 border', delphiPriorityStyle[delphi.priority].className)}
          title={delphi.priority_reason || ''}
        >
          <Sparkles className="h-3 w-3 mr-0.5" />
          {delphiPriorityStyle[delphi.priority].label}
        </Badge>
      )}
    </div>
  );
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const severityConfig: Record<Severity, { color: string; bgColor: string; textColor: string; borderColor: string }> = {
  critical: { 
    color: 'bg-red-600', 
    bgColor: 'bg-red-600/10', 
    textColor: 'text-red-400',
    borderColor: 'border-red-600/30'
  },
  high: { 
    color: 'bg-orange-500', 
    bgColor: 'bg-orange-500/10', 
    textColor: 'text-orange-400',
    borderColor: 'border-orange-500/30'
  },
  medium: { 
    color: 'bg-yellow-500', 
    bgColor: 'bg-yellow-500/10', 
    textColor: 'text-yellow-400',
    borderColor: 'border-yellow-500/30'
  },
  low: { 
    color: 'bg-green-500', 
    bgColor: 'bg-green-500/10', 
    textColor: 'text-green-400',
    borderColor: 'border-green-500/30'
  },
  info: { 
    color: 'bg-blue-500', 
    bgColor: 'bg-blue-500/10', 
    textColor: 'text-blue-400',
    borderColor: 'border-blue-500/30'
  },
};

const statusConfig: Record<string, { label: string; color: string }> = {
  open: { label: 'Open', color: 'bg-red-600/20 text-red-400 border-red-600/30' },
  in_progress: { label: 'In Progress', color: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30' },
  resolved: { label: 'Resolved', color: 'bg-green-600/20 text-green-400 border-green-600/30' },
  mitigated: { label: 'Mitigated', color: 'bg-cyan-600/20 text-cyan-400 border-cyan-600/30' },
  accepted: { label: 'Risk Accepted', color: 'bg-blue-600/20 text-blue-400 border-blue-600/30' },
  false_positive: { label: 'False Positive', color: 'bg-gray-600/20 text-gray-400 border-gray-600/30' },
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [remediationData, setRemediationData] = useState<any>(null);
  const [loadingRemediation, setLoadingRemediation] = useState(false);
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<number>>(new Set());
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [assignee, setAssignee] = useState('');
  const [sortMode, setSortMode] = useState<SortMode>('severity');
  const [onlyKev, setOnlyKev] = useState(false);
  const [oracleBatchBusy, setOracleBatchBusy] = useState(false);
  const { toast } = useToast();

  // Generate Nuclei Template state
  const [generateTemplateOpen, setGenerateTemplateOpen] = useState(false);
  const [generatingTemplate, setGeneratingTemplate] = useState(false);
  const [generateTemplateCveId, setGenerateTemplateCveId] = useState('');
  const [generateTemplateEvidence, setGenerateTemplateEvidence] = useState('');
  const [firstOrgId, setFirstOrgId] = useState<number | null>(null);

  // Jira ticket creation state
  const [jiraDialogOpen, setJiraDialogOpen] = useState(false);
  const [jiraProjects, setJiraProjects] = useState<{ key: string; name: string }[]>([]);
  const [jiraIssueTypes, setJiraIssueTypes] = useState<{ id: string; name: string }[]>([]);
  const [jiraHasIntegration, setJiraHasIntegration] = useState<boolean | null>(null);
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [jiraIssueType, setJiraIssueType] = useState('Bug');
  const [jiraIncludeEvidence, setJiraIncludeEvidence] = useState(true);
  const [jiraIncludeRemediation, setJiraIncludeRemediation] = useState(true);
  const [jiraIncludeEnrichment, setJiraIncludeEnrichment] = useState(true);
  const [jiraCreating, setJiraCreating] = useState(false);
  const [jiraExistingTickets, setJiraExistingTickets] = useState<{ jira_issue_key: string; jira_issue_url: string }[]>([]);

  // Open Jira ticket dialog for a finding
  const openJiraDialog = async (finding: Finding) => {
    setJiraDialogOpen(true);
    setJiraProjectKey('');
    setJiraIssueType('Bug');
    setJiraExistingTickets([]);

    try {
      const [integrationData, projectsData, ticketsData] = await Promise.all([
        api.getJiraIntegration().catch(() => null),
        api.getJiraProjects(),
        api.getJiraTicketsForVulnerability(finding.id),
      ]);
      setJiraHasIntegration(true);
      setJiraProjects(projectsData.projects);
      setJiraExistingTickets(ticketsData);

      // Prefer the saved default project; fall back to the first project alphabetically
      const savedProject = integrationData?.default_project_key;
      const savedIssueType = integrationData?.default_issue_type || 'Bug';
      const initialKey =
        savedProject && projectsData.projects.some((p) => p.key === savedProject)
          ? savedProject
          : projectsData.projects[0]?.key ?? '';

      setJiraProjectKey(initialKey);
      setJiraIssueType(savedIssueType);

      if (initialKey) {
        const typesData = await api.getJiraIssueTypes(initialKey);
        setJiraIssueTypes(typesData.issue_types);
        // Keep the saved issue type if it exists in the project, otherwise use the first available
        const typeExists = typesData.issue_types.some((t) => t.name === savedIssueType);
        if (!typeExists && typesData.issue_types.length > 0) {
          setJiraIssueType(typesData.issue_types[0].name);
        }
      }
    } catch (err: any) {
      if (err?.response?.status === 404) {
        setJiraHasIntegration(false);
      } else {
        toast({ title: 'Could not load Jira projects', description: getApiErrorMessage(err), variant: 'destructive' });
        setJiraDialogOpen(false);
      }
    }
  };

  const handleJiraProjectChange = async (key: string) => {
    setJiraProjectKey(key);
    setJiraIssueTypes([]);
    if (!key) return;
    try {
      const data = await api.getJiraIssueTypes(key);
      setJiraIssueTypes(data.issue_types);
      if (data.issue_types.length > 0) setJiraIssueType(data.issue_types[0].name);
    } catch {
      // silently ignore; user can still type
    }
  };

  const handleCreateJiraTicket = async () => {
    if (!selectedFinding || !jiraProjectKey) return;
    setJiraCreating(true);
    try {
      const ticket = await api.createJiraTicket(selectedFinding.id, {
        project_key: jiraProjectKey,
        issue_type: jiraIssueType || 'Bug',
        include_evidence: jiraIncludeEvidence,
        include_remediation: jiraIncludeRemediation,
        include_enrichment: jiraIncludeEnrichment,
      });
      toast({
        title: `Jira ticket created: ${ticket.jira_issue_key}`,
        description: `View at ${ticket.jira_issue_url}`,
      });
      setJiraExistingTickets((prev) => [ticket, ...prev]);
    } catch (err) {
      toast({ title: 'Failed to create ticket', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setJiraCreating(false);
    }
  };

  // Fetch remediation playbook when a finding is selected
  const fetchRemediation = async (findingId: number) => {
    setLoadingRemediation(true);
    setRemediationData(null);
    try {
      const data = await api.getRemediationForFinding(findingId);
      setRemediationData(data);
    } catch (err) {
      console.error('Failed to fetch remediation:', err);
      // Silently fail - will show fallback remediation
    } finally {
      setLoadingRemediation(false);
    }
  };

  // Handle finding selection
  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    fetchRemediation(finding.id);
  };

  // Handle status change
  const [updatingStatus, setUpdatingStatus] = useState(false);
  
  const handleStatusChange = async (findingId: number, newStatus: string) => {
    setUpdatingStatus(true);
    try {
      await api.updateVulnerability(findingId, { status: newStatus });
      toast({
        title: 'Status Updated',
        description: `Finding marked as ${statusConfig[newStatus]?.label || newStatus}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        f.id === findingId ? { ...f, status: newStatus } : f
      ));
      // Update selected finding if it's the one being changed
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(prev => prev ? { ...prev, status: newStatus } : null);
      }
      // Refresh stats
      const summaryData = await api.getFindingsSummary();
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to update status:', err);
      toast({
        title: 'Error',
        description: `Failed to update status: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setUpdatingStatus(false);
    }
  };

  // Handle inline status change from table dropdown
  const handleInlineStatusChange = async (findingId: number, newStatus: string, e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation();
    }
    await handleStatusChange(findingId, newStatus);
  };

  // Handle bulk status change
  const handleBulkStatusChange = async (newStatus: string) => {
    if (selectedFindingIds.size === 0) return;
    
    setBulkUpdating(true);
    try {
      await api.bulkUpdateVulnerabilities({
        vulnerability_ids: Array.from(selectedFindingIds),
        status: newStatus,
      });
      toast({
        title: 'Bulk Update Complete',
        description: `Updated ${selectedFindingIds.size} findings to ${statusConfig[newStatus]?.label || newStatus}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        selectedFindingIds.has(f.id) ? { ...f, status: newStatus } : f
      ));
      setSelectedFindingIds(new Set());
      // Refresh stats
      const summaryData = await api.getFindingsSummary();
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to bulk update:', err);
      toast({
        title: 'Error',
        description: `Failed to bulk update: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setBulkUpdating(false);
    }
  };

  // Handle bulk assignment
  const handleBulkAssign = async () => {
    if (selectedFindingIds.size === 0 || !assignee.trim()) return;
    
    setBulkUpdating(true);
    try {
      await api.bulkUpdateVulnerabilities({
        vulnerability_ids: Array.from(selectedFindingIds),
        assigned_to: assignee.trim(),
      });
      toast({
        title: 'Assignment Complete',
        description: `Assigned ${selectedFindingIds.size} findings to ${assignee}`,
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        selectedFindingIds.has(f.id) ? { ...f, assigned_to: assignee.trim() } : f
      ));
      setSelectedFindingIds(new Set());
      setAssignDialogOpen(false);
      setAssignee('');
    } catch (err: any) {
      console.error('Failed to assign:', err);
      toast({
        title: 'Error',
        description: `Failed to assign: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setBulkUpdating(false);
    }
  };

  // Handle single assignment from dialog
  const handleAssignFinding = async (findingId: number, assigneeValue: string) => {
    try {
      await api.updateVulnerability(findingId, { assigned_to: assigneeValue || undefined });
      toast({
        title: 'Assignment Updated',
        description: assigneeValue ? `Assigned to ${assigneeValue}` : 'Assignment removed',
      });
      // Update local state
      setFindings(prev => prev.map(f => 
        f.id === findingId ? { ...f, assigned_to: assigneeValue || undefined } : f
      ));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(prev => prev ? { ...prev, assigned_to: assigneeValue || undefined } : null);
      }
    } catch (err: any) {
      toast({
        title: 'Error',
        description: `Failed to update assignment: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    }
  };

  // Toggle selection for a single finding
  const toggleFindingSelection = (findingId: number, e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation();
    }
    setSelectedFindingIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  // Toggle all visible findings
  const toggleAllFindings = () => {
    if (selectedFindingIds.size === filteredFindings.length) {
      setSelectedFindingIds(new Set());
    } else {
      setSelectedFindingIds(new Set(filteredFindings.map(f => f.id)));
    }
  };

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch findings and summary in parallel
      const [findingsData, summaryData] = await Promise.all([
        api.getFindings({
          severity: selectedSeverity || undefined,
          limit: 100,
        }),
        api.getFindingsSummary(),
      ]);

      // Handle both array and paginated responses
      const items = Array.isArray(findingsData) ? findingsData : (findingsData.items || []);
      setFindings(items);
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to fetch findings:', err);
      // Provide more specific error message
      const errorMessage = err.response?.data?.detail || err.message || 'Failed to fetch findings';
      setError(errorMessage);
      toast({
        title: 'Error',
        description: `Failed to fetch findings: ${errorMessage}`,
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Grab the first org for template generation
    api.getOrganizations().then((orgs: any[]) => {
      if (orgs?.length) setFirstOrgId(orgs[0].id);
    }).catch(() => {});
  }, [selectedSeverity]);

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const handleSeverityFilter = (severity: Severity | null) => {
    setSelectedSeverity(severity === selectedSeverity ? null : severity);
  };

  const handleOracleBatchEnrich = async () => {
    setOracleBatchBusy(true);
    try {
      const result = await api.oracleEnrichBatch(200, false);
      if (result.queued) {
        toast({
          title: 'Oracle batch enrichment queued',
          description: `${result.selected} vulnerabilities queued for background analysis. Results will appear as each completes — refresh the page in a minute.`,
        });
      } else if (result.selected === 0) {
        toast({ title: 'Nothing to enrich', description: result.message ?? 'All open vulnerabilities are already enriched.' });
      } else {
        toast({
          title: 'Oracle enrichment complete',
          description: `${result.enriched ?? 0} enriched · ${result.skipped_cached ?? 0} cached · ${result.errors ?? 0} errors. Refresh to see updated badges.`,
        });
        // Refresh in place so updated rows show their new OPES badges.
        try {
          const refreshed = await api.getVulnerabilities({ limit: 500 });
          if (Array.isArray(refreshed)) {
            setFindings(refreshed as Finding[]);
          }
        } catch {
          // Non-fatal — the user can refresh manually.
        }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable.';
      toast({ variant: 'destructive', title: 'Oracle batch failed', description: msg });
    } finally {
      setOracleBatchBusy(false);
    }
  };

  const handleExport = () => {
    if (filteredFindings.length === 0) {
      toast({
        title: 'No Data',
        description: 'No findings to export.',
        variant: 'destructive',
      });
      return;
    }

    downloadCSV(
      filteredFindings.map((f) => ({
        title: f.title || f.name || '',
        severity: f.severity,
        host: f.host || '',
        template_id: f.template_id || '',
        cve_id: f.cve_id || '',
        cvss_score: f.cvss_score || '',
        status: f.status || 'open',
        detected_by: f.detected_by || '',
        matched_at: f.matched_at || '',
        first_detected: f.first_detected || f.created_at,
        description: f.description || '',
      })),
      'findings'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  // Severity order for sorting (lower = higher priority)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  // Filter findings by search query
  const filteredFindings = findings
    .filter((f) => {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        (f.title || f.name || '').toLowerCase().includes(searchLower) ||
        (f.host || '').toLowerCase().includes(searchLower) ||
        (f.template_id || '').toLowerCase().includes(searchLower) ||
        (f.description || '').toLowerCase().includes(searchLower) ||
        (f.cve_id || '').toLowerCase().includes(searchLower);
      if (!matchesSearch) return false;
      if (onlyKev && !f.delphi?.kev) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortMode === 'delphi') {
        const aRansom = isRansomwareKev(a.delphi?.kev) ? 0 : 1;
        const bRansom = isRansomwareKev(b.delphi?.kev) ? 0 : 1;
        if (aRansom !== bRansom) return aRansom - bRansom;
        const aKev = a.delphi?.kev ? 0 : 1;
        const bKev = b.delphi?.kev ? 0 : 1;
        if (aKev !== bKev) return aKev - bKev;
        const aRank = delphiPriorityRank[a.delphi?.priority || 'none'] ?? 5;
        const bRank = delphiPriorityRank[b.delphi?.priority || 'none'] ?? 5;
        if (aRank !== bRank) return aRank - bRank;
        const aCvss = a.cvss_score ?? 0;
        const bCvss = b.cvss_score ?? 0;
        if (aCvss !== bCvss) return bCvss - aCvss;
        // Fall through to severity tie-break
      }
      if (sortMode === 'recent') {
        const aT = new Date(a.last_detected || a.first_detected || a.created_at).getTime();
        const bT = new Date(b.last_detected || b.first_detected || b.created_at).getTime();
        return bT - aT;
      }
      if (sortMode === 'cvss') {
        const aS = a.cvss_score ?? -1;
        const bS = b.cvss_score ?? -1;
        if (aS !== bS) return bS - aS;
      }
      const orderA = severityOrder[a.severity?.toLowerCase()] ?? 5;
      const orderB = severityOrder[b.severity?.toLowerCase()] ?? 5;
      return orderA - orderB;
    });

  const kevCount = findings.filter((f) => f.delphi?.kev).length;
  const ransomwareCount = findings.filter((f) => isRansomwareKev(f.delphi?.kev)).length;

  // Calculate severity counts
  const severityCounts: Record<Severity, number> = {
    critical: stats?.by_severity?.critical || 0,
    high: stats?.by_severity?.high || 0,
    medium: stats?.by_severity?.medium || 0,
    low: stats?.by_severity?.low || 0,
    info: stats?.by_severity?.info || 0,
  };

  const totalCount = stats?.total || findings.length;

  const getSeverityBadgeClass = (severity: string) => {
    const config = severityConfig[severity.toLowerCase() as Severity];
    return config 
      ? `${config.bgColor} ${config.textColor} ${config.borderColor} border` 
      : 'bg-gray-600/20 text-gray-400 border-gray-600/30 border';
  };

  const getStatusBadge = (status: string) => {
    const config = statusConfig[status] || statusConfig.open;
    return (
      <Badge className={`${config.color} border`}>
        {config.label}
      </Badge>
    );
  };

  return (
    <MainLayout>
      <Header title="Findings" subtitle="Security vulnerabilities and issues discovered in your assets" />

      <div className="p-6 space-y-6">
        {/* Severity Filter Pills */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleSeverityFilter(null)}
            className={cn(
              'rounded-full px-4 py-2 text-sm font-medium transition-all',
              !selectedSeverity
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
            )}
          >
            All ({totalCount})
          </button>
          {severities.map((severity) => {
            const config = severityConfig[severity];
            return (
              <button
                key={severity}
                onClick={() => handleSeverityFilter(severity)}
                className={cn(
                  'rounded-full px-4 py-2 text-sm font-medium transition-all flex items-center gap-2',
                  selectedSeverity === severity
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
                )}
              >
                <span className={cn('w-2 h-2 rounded-full', config.color)} />
                <span className="capitalize">{severity}</span>
                <span className={cn('text-xs px-1.5 py-0.5 rounded-full', config.bgColor, config.textColor)}>
                  {severityCounts[severity]}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search and Actions */}
        <div className="flex gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search findings by title, host, CVE, template..."
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              className="pl-10 bg-secondary/50 border-border"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={sortMode} onValueChange={(v) => setSortMode(v as SortMode)}>
              <SelectTrigger className="h-9 w-[200px] text-sm">
                <ArrowUpDown className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity">Sort: Severity</SelectItem>
                <SelectItem value="delphi">
                  <span className="flex items-center gap-2">
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    Sort: Delphi priority (KEV → CVSS)
                  </span>
                </SelectItem>
                <SelectItem value="cvss">Sort: CVSS score</SelectItem>
                <SelectItem value="recent">Sort: Most recent</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={onlyKev ? 'default' : 'outline'}
              size="sm"
              onClick={() => setOnlyKev((v) => !v)}
              title="Show only findings on the CISA Known Exploited Vulnerabilities catalog"
            >
              <Flame className="h-4 w-4 mr-2" />
              KEV only {kevCount > 0 && <span className="ml-1 text-xs opacity-70">({kevCount})</span>}
            </Button>
            <Button variant="outline" size="sm">
              <Filter className="h-4 w-4 mr-2" />
              More Filters
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleOracleBatchEnrich}
              disabled={oracleBatchBusy}
              title="Run Aegis Oracle analysis on open vulnerabilities in your organization"
            >
              {oracleBatchBusy ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Sparkles className="h-4 w-4 mr-2 text-orange-400" />
              )}
              Enrich with Oracle
            </Button>
          </div>
        </div>

        {/* Delphi summary strip */}
        {(kevCount > 0 || findings.some((f) => f.delphi?.epss)) && (
          <Card className="border-purple-500/20 bg-purple-500/5">
            <CardContent className="p-3 flex items-center gap-4 flex-wrap text-sm">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-purple-400" />
                <span className="font-medium">Delphi enrichment</span>
                <span className="text-muted-foreground">KEV · CVSS analysis · breach intel</span>
              </div>
              <div className="flex items-center gap-3 ml-auto flex-wrap">
                {ransomwareCount > 0 && (
                  <span className="flex items-center gap-1 text-red-300">
                    <Flame className="h-3.5 w-3.5" />
                    {ransomwareCount} known-ransomware
                  </span>
                )}
                {kevCount > 0 && (
                  <span className="flex items-center gap-1 text-red-400">
                    <Flame className="h-3.5 w-3.5" />
                    {kevCount} on CISA KEV
                  </span>
                )}
                <span className="flex items-center gap-1 text-muted-foreground" title="EPSS is fetched for reference but does not affect priority scoring">
                  <TrendingUp className="h-3.5 w-3.5 opacity-50" />
                  {findings.filter((f) => f.delphi?.epss).length} with EPSS (reference)
                </span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Error State */}
        {error && (
          <Card className="border-red-600/30 bg-red-600/10">
            <CardContent className="p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-red-400 font-medium">Failed to load findings</p>
                <p className="text-sm text-muted-foreground">{error}</p>
              </div>
              <Button variant="outline" size="sm" onClick={fetchData} className="ml-auto">
                Retry
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Bulk Actions Bar */}
        {selectedFindingIds.size > 0 && (
          <Card className="border-primary/30 bg-primary/5">
            <CardContent className="p-4 flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-primary" />
                <span className="font-medium">{selectedFindingIds.size} selected</span>
              </div>
              <div className="flex-1" />
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm text-muted-foreground mr-2">Change Status:</span>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('in_progress')}
                  disabled={bulkUpdating}
                  className="border-yellow-600/30 hover:bg-yellow-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  In Progress
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('resolved')}
                  disabled={bulkUpdating}
                  className="border-green-600/30 hover:bg-green-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Resolved
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('mitigated')}
                  disabled={bulkUpdating}
                  className="border-cyan-600/30 hover:bg-cyan-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Mitigated
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => handleBulkStatusChange('false_positive')}
                  disabled={bulkUpdating}
                  className="border-gray-600/30 hover:bg-gray-600/20"
                >
                  {bulkUpdating ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  False Positive
                </Button>
                <div className="h-6 w-px bg-border mx-2" />
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => setAssignDialogOpen(true)}
                  disabled={bulkUpdating}
                >
                  <Users className="h-4 w-4 mr-1" />
                  Assign
                </Button>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  onClick={() => setSelectedFindingIds(new Set())}
                >
                  <XCircle className="h-4 w-4 mr-1" />
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Findings Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40px]">
                  <Checkbox
                    checked={filteredFindings.length > 0 && selectedFindingIds.size === filteredFindings.length}
                    onCheckedChange={toggleAllFindings}
                    aria-label="Select all"
                  />
                </TableHead>
                <TableHead className="w-[100px]">Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Host</TableHead>
                <TableHead className="w-[140px]">Status</TableHead>
                <TableHead>Assigned</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Detected</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Loader2 className="h-8 w-8 animate-spin text-primary" />
                      <p className="text-muted-foreground">Loading findings...</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : filteredFindings.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="h-12 w-12 text-muted-foreground/50" />
                      <p className="text-muted-foreground">
                        {searchQuery 
                          ? 'No findings match your search criteria.' 
                          : 'No findings discovered yet. Run a scan to discover security issues.'}
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredFindings.map((finding) => (
                  <TableRow
                    key={finding.id}
                    className={cn(
                      "cursor-pointer hover:bg-muted/50",
                      selectedFindingIds.has(finding.id) && "bg-primary/5"
                    )}
                    onClick={() => handleSelectFinding(finding)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedFindingIds.has(finding.id)}
                        onCheckedChange={() => toggleFindingSelection(finding.id)}
                        aria-label={`Select finding ${finding.id}`}
                      />
                    </TableCell>
                    <TableCell>
                      <Badge className={getSeverityBadgeClass(finding.severity)}>
                        {finding.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
                          <span className="font-medium line-clamp-1">
                            {finding.title || finding.name || finding.template_id}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {finding.cve_id && (
                            <span className="text-xs text-primary font-mono">{finding.cve_id}</span>
                          )}
                          <OracleBadge oracle={finding.oracle} compact />
                          <DelphiBadges delphi={finding.delphi} compact />
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {finding.host ? (
                        <a
                          href={`https://${finding.host}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="truncate max-w-[200px]">{finding.host}</span>
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Select
                        value={finding.status || 'open'}
                        onValueChange={(value) => handleInlineStatusChange(finding.id, value)}
                      >
                        <SelectTrigger className="h-8 w-[130px] text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="open">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-red-500" />
                              Open
                            </span>
                          </SelectItem>
                          <SelectItem value="in_progress">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-yellow-500" />
                              In Progress
                            </span>
                          </SelectItem>
                          <SelectItem value="resolved">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-green-500" />
                              Resolved
                            </span>
                          </SelectItem>
                          <SelectItem value="mitigated">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-cyan-500" />
                              Mitigated
                            </span>
                          </SelectItem>
                          <SelectItem value="accepted">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-blue-500" />
                              Risk Accepted
                            </span>
                          </SelectItem>
                          <SelectItem value="false_positive">
                            <span className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full bg-gray-500" />
                              False Positive
                            </span>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell>
                      {finding.assigned_to ? (
                        <span className="text-sm flex items-center gap-1">
                          <User className="h-3 w-3" />
                          {finding.assigned_to}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-sm">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {finding.cvss_score ? (
                        <span className={cn(
                          'font-mono font-medium',
                          finding.cvss_score >= 9 ? 'text-red-400' :
                          finding.cvss_score >= 7 ? 'text-orange-400' :
                          finding.cvss_score >= 4 ? 'text-yellow-400' :
                          'text-green-400'
                        )}>
                          {finding.cvss_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(finding.first_detected || finding.created_at)}
                    </TableCell>
                    <TableCell>
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {/* Finding Detail Dialog */}
        <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className={getSeverityBadgeClass(selectedFinding?.severity || '')}>
                  {selectedFinding?.severity}
                </Badge>
                {selectedFinding?.status && getStatusBadge(selectedFinding.status)}
                {selectedFinding?.cvss_score && (
                  <Badge variant="outline" className="font-mono">
                    CVSS: {selectedFinding.cvss_score.toFixed(1)}
                  </Badge>
                )}
              </div>
              <div className="flex items-center justify-between mt-2 gap-2">
                <DialogTitle className="text-xl">
                  {selectedFinding?.title || selectedFinding?.name || selectedFinding?.template_id}
                </DialogTitle>
                <Button
                  size="sm"
                  variant="outline"
                  className="shrink-0 border-[#0052CC]/40 hover:bg-[#0052CC]/15 text-[#4C9AFF]"
                  onClick={() => selectedFinding && openJiraDialog(selectedFinding)}
                >
                  <Ticket className="h-4 w-4 mr-1.5" />
                  Jira
                </Button>
              </div>
              <DialogDescription>
                Complete finding details and remediation information
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-4">
              {/* Quick Info Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="flex items-start gap-2">
                  <Target className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Host</p>
                    {selectedFinding?.host ? (
                      <a
                        href={`https://${selectedFinding.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.host}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <p className="text-sm text-muted-foreground">-</p>
                    )}
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <FileCode className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Template ID</p>
                    <p className="text-sm font-mono">{selectedFinding?.template_id || '-'}</p>
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <Activity className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Detected By</p>
                    <p className="text-sm">{selectedFinding?.detected_by || 'Nuclei'}</p>
                  </div>
                </div>

                {selectedFinding?.cve_id && (
                  <div className="flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVE ID</p>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cve_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cwe_id && (
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CWE ID</p>
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cwe_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cvss_vector && (
                  <div className="flex items-start gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVSS Vector</p>
                      <p className="text-sm font-mono text-xs">{selectedFinding.cvss_vector}</p>
                    </div>
                  </div>
                )}

                <div className="flex items-start gap-2">
                  <User className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div className="flex-1">
                    <p className="text-xs text-muted-foreground mb-1">Assigned To</p>
                    <div className="flex items-center gap-2">
                      <Input
                        placeholder="Enter email or name..."
                        defaultValue={selectedFinding?.assigned_to || ''}
                        className="h-8 text-sm"
                        onBlur={(e) => {
                          if (selectedFinding && e.target.value !== (selectedFinding.assigned_to || '')) {
                            handleAssignFinding(selectedFinding.id, e.target.value);
                          }
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const input = e.target as HTMLInputElement;
                            if (selectedFinding && input.value !== (selectedFinding.assigned_to || '')) {
                              handleAssignFinding(selectedFinding.id, input.value);
                            }
                            input.blur();
                          }
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Timestamps */}
              <div className="flex flex-wrap gap-4 text-sm">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>First Detected: {formatDate(selectedFinding?.first_detected || selectedFinding?.created_at || '')}</span>
                </div>
                {selectedFinding?.last_detected && selectedFinding.last_detected !== selectedFinding.first_detected && (
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Calendar className="h-4 w-4" />
                    <span>Last Detected: {formatDate(selectedFinding.last_detected)}</span>
                  </div>
                )}
                {selectedFinding?.resolved_at && (
                  <div className="flex items-center gap-2 text-green-400">
                    <Clock className="h-4 w-4" />
                    <span>Resolved: {formatDate(selectedFinding.resolved_at)}</span>
                  </div>
                )}
              </div>

              {/* Delphi enrichment panel */}
              {selectedFinding?.delphi && (selectedFinding.delphi.kev || selectedFinding.delphi.epss) && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2 text-purple-300">
                    <Sparkles className="h-4 w-4" />
                    Delphi Priority
                    {selectedFinding.delphi.priority && selectedFinding.delphi.priority !== 'none' &&
                      delphiPriorityStyle[selectedFinding.delphi.priority] && (
                        <Badge
                          variant="outline"
                          className={cn('ml-1', delphiPriorityStyle[selectedFinding.delphi.priority].className)}
                        >
                          {delphiPriorityStyle[selectedFinding.delphi.priority].label}
                        </Badge>
                      )}
                  </p>
                  {selectedFinding.delphi.priority_reason && (
                    <p className="text-sm text-muted-foreground">{selectedFinding.delphi.priority_reason}</p>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {selectedFinding.delphi.kev && (
                      <div className={cn(
                        'rounded-lg border p-3 space-y-1',
                        isRansomwareKev(selectedFinding.delphi.kev)
                          ? 'border-red-600/40 bg-red-600/10'
                          : 'border-red-500/30 bg-red-500/5'
                      )}>
                        <div className="flex items-center gap-2">
                          <Flame className="h-4 w-4 text-red-400" />
                          <p className="text-sm font-medium text-red-300">CISA Known Exploited Vulnerabilities</p>
                        </div>
                        {selectedFinding.delphi.kev.vulnerability_name && (
                          <p className="text-sm">{selectedFinding.delphi.kev.vulnerability_name}</p>
                        )}
                        {(selectedFinding.delphi.kev.vendor_project || selectedFinding.delphi.kev.product) && (
                          <p className="text-xs text-muted-foreground">
                            {selectedFinding.delphi.kev.vendor_project} {selectedFinding.delphi.kev.product}
                          </p>
                        )}
                        {selectedFinding.delphi.kev.short_description && (
                          <p className="text-xs text-muted-foreground line-clamp-3">
                            {selectedFinding.delphi.kev.short_description}
                          </p>
                        )}
                        <div className="flex items-center gap-3 text-xs pt-1">
                          {selectedFinding.delphi.kev.date_added && (
                            <span className="text-muted-foreground">Added: {selectedFinding.delphi.kev.date_added}</span>
                          )}
                          {selectedFinding.delphi.kev.due_date && (
                            <span className="text-yellow-400">CISA Due: {selectedFinding.delphi.kev.due_date}</span>
                          )}
                          {isRansomwareKev(selectedFinding.delphi.kev) && (
                            <Badge variant="outline" className="bg-red-600/20 text-red-300 border-red-600/40 text-[10px]">
                              Known ransomware use
                            </Badge>
                          )}
                        </div>
                        {selectedFinding.delphi.kev.required_action && (
                          <p className="text-xs text-red-200/90 pt-1">
                            <span className="font-medium">Required action:</span> {selectedFinding.delphi.kev.required_action}
                          </p>
                        )}
                      </div>
                    )}
                    {selectedFinding.delphi.epss && (
                      <div className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <TrendingUp className="h-4 w-4 text-muted-foreground" />
                            <p className="text-sm font-medium text-muted-foreground">FIRST EPSS — Reference Only</p>
                          </div>
                          <Badge variant="outline" className="text-[10px] px-1.5 h-4 text-muted-foreground border-muted-foreground/30">
                            Not used in scoring
                          </Badge>
                        </div>
                        <div className="grid grid-cols-3 gap-2 text-center">
                          <div>
                            <p className="text-xs text-muted-foreground">Score</p>
                            <p className="text-lg font-mono text-muted-foreground">{selectedFinding.delphi.epss.score.toFixed(3)}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Percentile</p>
                            <p className="text-lg font-mono text-muted-foreground">{(selectedFinding.delphi.epss.percentile * 100).toFixed(1)}%</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Tier</p>
                            <p className="text-sm text-muted-foreground">
                              {selectedFinding.delphi.epss.display_label ?? selectedFinding.delphi.epss.bucket}
                            </p>
                          </div>
                        </div>
                        <div className="h-1 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-muted-foreground/40"
                            style={{ width: `${Math.min(100, selectedFinding.delphi.epss.percentile * 100)}%` }}
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          EPSS is a probabilistic 30-day exploit prediction. Priority is driven by CISA KEV status,
                          CVSS vector analysis, and breach intelligence — not EPSS.
                          {selectedFinding.delphi.epss.date && ` Score date: ${selectedFinding.delphi.epss.date}.`}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Aegis Oracle enrichment panel — OPES priority + analyst brief
                  + recommendation narrative. Includes an inline "Analyze" button
                  to run/refresh the enrichment on demand. */}
              <OracleEnrichmentPanel
                finding={selectedFinding}
                onUpdate={(updated) => {
                  if (!selectedFinding) return;
                  setSelectedFinding({ ...selectedFinding, oracle: updated });
                  setFindings((prev) =>
                    prev.map((f) => (f.id === selectedFinding.id ? { ...f, oracle: updated } : f)),
                  );
                }}
              />

              {/* Generate Nuclei Template CTA */}
              {selectedFinding && (selectedFinding.cve_id || selectedFinding.template_id) && (
                <div className="flex items-center gap-2 p-2.5 rounded-lg border border-purple-500/20 bg-purple-500/5">
                  <FileCode className="h-4 w-4 text-purple-400 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-purple-300 font-medium">Detection Coverage</p>
                    <p className="text-xs text-muted-foreground">
                      Generate or manage a custom Nuclei template for this finding
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="shrink-0 text-xs border-purple-500/30 text-purple-300 hover:bg-purple-500/10 gap-1"
                    onClick={() => {
                      setGenerateTemplateCveId(selectedFinding?.cve_id || '');
                      setGenerateTemplateEvidence(selectedFinding?.evidence || selectedFinding?.matched_at || '');
                      setGenerateTemplateOpen(true);
                    }}
                  >
                    <Sparkles className="h-3 w-3" />
                    Generate Template
                  </Button>
                </div>
              )}

              {/* Matched At / Evidence */}
              {selectedFinding?.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    Matched At
                  </p>
                  <div className="p-3 bg-secondary/50 rounded-lg">
                    <code className="text-sm break-all">{selectedFinding.matched_at}</code>
                  </div>
                </div>
              )}

              {/* Description */}
              {selectedFinding?.description && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Description</p>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

              {/* Evidence */}
              {selectedFinding?.evidence && selectedFinding.evidence !== selectedFinding.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Evidence</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                </div>
              )}

              {/* Proof of Concept */}
              {selectedFinding?.proof_of_concept && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Proof of Concept</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.proof_of_concept}
                    </pre>
                  </div>
                </div>
              )}

              {/* Remediation Panel */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-green-400 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Remediation Guidance
                  {selectedFinding?.remediation_deadline && (
                    <Badge variant="outline" className="text-yellow-400 border-yellow-400/30 ml-2">
                      Due: {formatDate(selectedFinding.remediation_deadline)}
                    </Badge>
                  )}
                </p>
                {loadingRemediation ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                  </div>
                ) : (
                  <RemediationPanel 
                    playbook={remediationData?.has_playbook ? remediationData.playbook : undefined}
                    fallbackRemediation={selectedFinding?.remediation || remediationData?.remediation}
                    cwe={remediationData?.cwe}
                    cweId={remediationData?.cwe_id || selectedFinding?.cwe_id}
                  />
                )}
              </div>

              {/* Status Actions */}
              <div className="space-y-2 pt-4 border-t border-border">
                <p className="text-sm font-medium flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Update Status
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'open' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'open')}
                    disabled={updatingStatus || selectedFinding?.status === 'open'}
                    className="flex-1 min-w-[120px]"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Open
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'in_progress' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'in_progress')}
                    disabled={updatingStatus || selectedFinding?.status === 'in_progress'}
                    className="flex-1 min-w-[120px] border-yellow-600/30 hover:bg-yellow-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    In Progress
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'resolved' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'resolved')}
                    disabled={updatingStatus || selectedFinding?.status === 'resolved'}
                    className="flex-1 min-w-[120px] border-green-600/30 hover:bg-green-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Resolved
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'mitigated' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'mitigated')}
                    disabled={updatingStatus || selectedFinding?.status === 'mitigated'}
                    className="flex-1 min-w-[120px] border-cyan-600/30 hover:bg-cyan-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Mitigated
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'accepted' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'accepted')}
                    disabled={updatingStatus || selectedFinding?.status === 'accepted'}
                    className="flex-1 min-w-[120px] border-blue-600/30 hover:bg-blue-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Accept Risk
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedFinding?.status === 'false_positive' ? 'default' : 'outline'}
                    onClick={() => selectedFinding && handleStatusChange(selectedFinding.id, 'false_positive')}
                    disabled={updatingStatus || selectedFinding?.status === 'false_positive'}
                    className="flex-1 min-w-[120px] border-gray-600/30 hover:bg-gray-600/20"
                  >
                    {updatingStatus ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    False Positive
                  </Button>
                </div>
              </div>

              {/* Tags */}
              {selectedFinding?.tags && selectedFinding.tags.length > 0 && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Tag className="h-4 w-4" />
                    Tags
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {selectedFinding.tags.map((tag, i) => (
                      <Badge key={i} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {((selectedFinding?.references && selectedFinding.references.length > 0) ||
                (selectedFinding?.reference && selectedFinding.reference.length > 0)) && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <LinkIcon className="h-4 w-4" />
                    References
                  </p>
                  <div className="space-y-1">
                    {(selectedFinding.references || selectedFinding.reference || []).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1 break-all"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* Bulk Assignment Dialog */}
        <Dialog open={assignDialogOpen} onOpenChange={setAssignDialogOpen}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Assign Findings
              </DialogTitle>
              <DialogDescription>
                Assign {selectedFindingIds.size} selected finding(s) to a team member.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Assignee</label>
                <Input
                  placeholder="Enter email or name..."
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  className="w-full"
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setAssignDialogOpen(false);
                    setAssignee('');
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleBulkAssign}
                  disabled={bulkUpdating || !assignee.trim()}
                >
                  {bulkUpdating ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Users className="h-4 w-4 mr-2" />
                  )}
                  Assign
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Create Jira Ticket Dialog */}
        <Dialog open={jiraDialogOpen} onOpenChange={(v) => { if (!jiraCreating) setJiraDialogOpen(v); }}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <div className="w-6 h-6 rounded bg-[#0052CC] flex items-center justify-center shrink-0">
                  <svg viewBox="0 0 24 24" fill="white" className="w-4 h-4">
                    <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
                  </svg>
                </div>
                Create Jira Ticket
              </DialogTitle>
              <DialogDescription>
                {selectedFinding?.title || selectedFinding?.name}
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              {jiraHasIntegration === false ? (
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm space-y-2">
                  <p className="text-yellow-300 font-medium flex items-center gap-2">
                    <AlertCircle className="h-4 w-4" />
                    Jira not configured
                  </p>
                  <p className="text-muted-foreground">
                    Set up the Jira integration on the{' '}
                    <a href="/integrations" className="text-primary underline">Integrations page</a>{' '}
                    to push findings to Jira.
                  </p>
                </div>
              ) : (
                <>
                  {/* Existing tickets */}
                  {jiraExistingTickets.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Existing tickets</p>
                      <div className="space-y-1">
                        {jiraExistingTickets.map((t) => (
                          <a
                            key={t.jira_issue_key}
                            href={t.jira_issue_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 text-sm text-[#4C9AFF] hover:underline"
                          >
                            <ExternalLink className="h-3 w-3" />
                            {t.jira_issue_key}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Project selection */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Project</label>
                    {jiraProjects.length > 0 ? (
                      <Select value={jiraProjectKey} onValueChange={handleJiraProjectChange}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select a project" />
                        </SelectTrigger>
                        <SelectContent>
                          {jiraProjects.map((p) => (
                            <SelectItem key={p.key} value={p.key}>
                              {p.key} — {p.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        placeholder="e.g. SEC"
                        value={jiraProjectKey}
                        onChange={(e) => setJiraProjectKey(e.target.value.toUpperCase())}
                      />
                    )}
                  </div>

                  {/* Issue type */}
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Issue type</label>
                    {jiraIssueTypes.length > 0 ? (
                      <Select value={jiraIssueType} onValueChange={setJiraIssueType}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {jiraIssueTypes.map((t) => (
                            <SelectItem key={t.id} value={t.name}>{t.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        placeholder="Bug"
                        value={jiraIssueType}
                        onChange={(e) => setJiraIssueType(e.target.value)}
                      />
                    )}
                  </div>

                  {/* Content toggles */}
                  <div className="space-y-2 pt-1">
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Include in ticket</p>
                    {[
                      { label: 'Evidence & Proof of Concept', value: jiraIncludeEvidence, set: setJiraIncludeEvidence },
                      { label: 'Remediation guidance', value: jiraIncludeRemediation, set: setJiraIncludeRemediation },
                      { label: 'Delphi + Oracle enrichment', value: jiraIncludeEnrichment, set: setJiraIncludeEnrichment },
                    ].map(({ label, value, set }) => (
                      <label key={label} className="flex items-center gap-2 cursor-pointer text-sm">
                        <Checkbox
                          checked={value}
                          onCheckedChange={(v) => set(!!v)}
                          className="shrink-0"
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setJiraDialogOpen(false)} disabled={jiraCreating}>
                {jiraHasIntegration === false ? 'Close' : 'Cancel'}
              </Button>
              {jiraHasIntegration !== false && (
                <Button
                  onClick={handleCreateJiraTicket}
                  disabled={jiraCreating || !jiraProjectKey}
                  className="bg-[#0052CC] hover:bg-[#0065FF] text-white"
                >
                  {jiraCreating ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Ticket className="h-4 w-4 mr-2" />
                  )}
                  Create issue
                </Button>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* Generate Nuclei Template Dialog */}
        <Dialog open={generateTemplateOpen} onOpenChange={setGenerateTemplateOpen}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-purple-400" />
                Generate Nuclei Template
              </DialogTitle>
              <DialogDescription>
                The AI will generate a Nuclei YAML detection template based on this finding. Saved as draft for your review.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <div className="space-y-1">
                <label className="text-xs font-medium">CVE ID</label>
                <Input
                  placeholder="CVE-2024-12345"
                  value={generateTemplateCveId}
                  onChange={e => setGenerateTemplateCveId(e.target.value.toUpperCase())}
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium">Affected URL / Matched Evidence <span className="text-muted-foreground">(optional)</span></label>
                <Input
                  placeholder="/path/to/vulnerable/endpoint"
                  value={generateTemplateEvidence}
                  onChange={e => setGenerateTemplateEvidence(e.target.value)}
                />
              </div>
              <p className="text-xs text-muted-foreground p-2 rounded border border-purple-500/20 bg-purple-500/5 text-purple-400">
                Template will be saved to <strong>Nuclei Templates</strong> as a draft. Review the YAML before activating.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setGenerateTemplateOpen(false)} disabled={generatingTemplate}>
                Cancel
              </Button>
              <Button
                onClick={async () => {
                  if (!firstOrgId) {
                    toast({ title: 'No organization found', variant: 'destructive' });
                    return;
                  }
                  setGeneratingTemplate(true);
                  try {
                    const resp = await api.post('/nuclei-templates/generate', {
                      organization_id: firstOrgId,
                      cve_id: generateTemplateCveId.trim() || undefined,
                      vulnerability_description: selectedFinding?.description || undefined,
                      affected_url: generateTemplateEvidence.trim() || undefined,
                      affected_product: selectedFinding?.detected_by || undefined,
                    });
                    toast({
                      title: 'Template generated',
                      description: `Saved as draft: ${resp.data.template_id} — view in Nuclei Templates`,
                    });
                    setGenerateTemplateOpen(false);
                  } catch (err: any) {
                    toast({ title: 'Generation failed', description: err?.response?.data?.detail || err.message, variant: 'destructive' });
                  } finally {
                    setGeneratingTemplate(false);
                  }
                }}
                disabled={generatingTemplate || (!generateTemplateCveId.trim() && !selectedFinding?.description)}
                className="gap-1.5 bg-purple-600 hover:bg-purple-700"
              >
                {generatingTemplate ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                {generatingTemplate ? 'Generating…' : 'Generate'}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}
