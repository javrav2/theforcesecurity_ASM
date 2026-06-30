'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  MessageSquare, Send, Loader2, AlertCircle, CheckCircle, CheckCircle2,
  Wifi, WifiOff, Clock, Trash2, Plus, History, Crosshair, Eye,
  ShieldAlert, HelpCircle, XCircle, AlertTriangle, Flame, TrendingUp,
  RefreshCw, BookOpen, Globe, BarChart2, Code2, ShieldCheck, Mail,
  ArrowRightLeft, Key, Package, MoveRight, Search, ChevronDown, ChevronUp,
} from 'lucide-react';
import { AttackScenarioPanel, ChainData } from '@/components/agent/AttackScenarioPanel';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

// ═══════════════════════════════════════════════════════
// Oracle types
// ═══════════════════════════════════════════════════════

interface AnalystBrief {
  title?: string;
  what_is_it: string;
  attack_scenario: string;
  attack_vector_summary: string;
  real_world_likelihood: string;
  affected_if: string;
  not_affected_if?: string;
  exploitability_score?: number;
  exploitability_tier?: 'push_button' | 'opportunistic' | 'moderate' | 'targeted' | 'theoretical';
}

interface OPESComponents { E: number; R: number; P: number; X: number; C: number; T: number; }

interface OPESScore {
  score: number;
  category: 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
  label: string;
  confidence: 'high' | 'medium' | 'low';
  components: OPESComponents;
  top_contributors: string[];
  dampener?: string;
  override?: string;
  evaluator_version: string;
}

interface PreconditionEval {
  precondition: {
    id: string;
    description: string;
    verification_signal: string;
    match_kind: string;
    match_value: string;
    verification_method: string;
    severity: 'blocker' | 'contributing';
  };
  status: 'satisfied' | 'unsatisfied' | 'unknown';
  reason: string;
  signal_value?: string;
}

interface VerificationTask {
  id: string;
  precondition_id: string;
  summary: string;
  task_kind: string;
  command?: string;
  expected_signal_path: string;
  resolves: string[];
  status: string;
}

type AttackPathClass =
  | 'exploit_public_facing'
  | 'phishing_delivery'
  | 'lateral_movement_required'
  | 'valid_credentials_required'
  | 'supply_chain'
  | 'unknown';

type LateralMovementPotential = 'high' | 'medium' | 'low';

interface OracleFinding {
  cve_id: string;
  asset_id: string;
  evaluated_at: string;
  opes: OPESScore;
  analyst_brief?: AnalystBrief;
  attack_path_class?: AttackPathClass;
  lateral_movement_potential?: LateralMovementPotential;
  preconditions_evaluated: PreconditionEval[];
  cvss_reconciliation: {
    correct_vector: string;
    correct_score: number;
    rationale: string;
    disagreements?: { source: string; their_vector: string; disagreement: string }[];
  };
  recommendation: string;
  verification_tasks?: VerificationTask[];
}

interface TraceStep {
  iteration: number;
  thought: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  observation?: string;
  elapsed_ms?: number;
}

// ═══════════════════════════════════════════════════════
// Agent types
// ═══════════════════════════════════════════════════════

type MessageRole = 'user' | 'agent';

interface Message {
  id: string;
  role: MessageRole;
  content: string;
  phase?: string;
  taskComplete?: boolean;
  traceSummary?: string;
  awaitingApproval?: boolean;
  approvalRequest?: Record<string, unknown>;
  awaitingQuestion?: boolean;
  questionRequest?: Record<string, unknown>;
}

interface ConversationSummary {
  session_id: string;
  title: string | null;
  mode: string;
  current_phase: string;
  is_active: boolean;
  message_count: number;
  created_at: string;
  updated_at: string;
}

interface StatusUpdate {
  type: string;
  iteration?: number;
  phase?: string;
  thought?: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  success?: boolean;
  output_summary?: string;
  action?: string;
}

type ConnectionMode = 'connecting' | 'websocket' | 'rest' | 'disconnected';

// ═══════════════════════════════════════════════════════
// Oracle helper constants
// ═══════════════════════════════════════════════════════

const CATEGORY_STYLES: Record<string, string> = {
  P0: 'bg-red-600 text-white',
  P1: 'bg-orange-500 text-white',
  P2: 'bg-yellow-500 text-black',
  P3: 'bg-blue-500 text-white',
  P4: 'bg-muted text-muted-foreground',
};

const STATUS_ICON: Record<string, React.ReactNode> = {
  satisfied:   <CheckCircle2 className="h-4 w-4 text-green-500" />,
  unsatisfied: <XCircle      className="h-4 w-4 text-red-500" />,
  unknown:     <HelpCircle   className="h-4 w-4 text-yellow-500" />,
};

const BRIEF_SECTIONS: { key: keyof Omit<AnalystBrief, 'title'>; label: string; icon: React.ReactNode; accent: string }[] = [
  { key: 'what_is_it',            label: 'What is this vulnerability?',        icon: <BookOpen className="h-4 w-4" />,    accent: 'border-blue-500/30 bg-blue-500/5' },
  { key: 'attack_vector_summary', label: 'Attack vector',                       icon: <Globe className="h-4 w-4" />,       accent: 'border-orange-500/30 bg-orange-500/5' },
  { key: 'attack_scenario',       label: 'How would an attacker exploit this?', icon: <Crosshair className="h-4 w-4" />,   accent: 'border-red-500/30 bg-red-500/5' },
  { key: 'real_world_likelihood', label: 'Real-world exploitation likelihood',  icon: <BarChart2 className="h-4 w-4" />,   accent: 'border-purple-500/30 bg-purple-500/5' },
  { key: 'affected_if',           label: 'You are affected if…',                icon: <Code2 className="h-4 w-4" />,       accent: 'border-yellow-500/30 bg-yellow-500/5' },
  { key: 'not_affected_if',       label: 'You are NOT affected if…',            icon: <ShieldCheck className="h-4 w-4" />, accent: 'border-green-500/30 bg-green-500/5' },
];

const EXPLOITABILITY_TIER_META: Record<string, { label: string; color: string; bg: string; border: string; bar: number }> = {
  push_button:   { label: 'Push-Button',   color: 'text-red-700 dark:text-red-400',       bg: 'bg-red-50 dark:bg-red-950/40',       border: 'border-red-200 dark:border-red-800',       bar: 5 },
  opportunistic: { label: 'Opportunistic', color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', bar: 4 },
  moderate:      { label: 'Moderate',      color: 'text-yellow-700 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-950/30', border: 'border-yellow-200 dark:border-yellow-800', bar: 3 },
  targeted:      { label: 'Targeted',      color: 'text-blue-700 dark:text-blue-400',     bg: 'bg-blue-50 dark:bg-blue-950/40',     border: 'border-blue-200 dark:border-blue-800',     bar: 2 },
  theoretical:   { label: 'Theoretical',   color: 'text-slate-600 dark:text-slate-400',   bg: 'bg-slate-50 dark:bg-slate-900/40',   border: 'border-slate-200 dark:border-slate-700',   bar: 1 },
};

const ATTACK_PATH_META: Record<AttackPathClass, { label: string; icon: React.ReactNode; color: string; bg: string; border: string; tooltip: string }> = {
  exploit_public_facing:      { label: 'Direct Exploit',       icon: <Globe className="h-3 w-3" />,          color: 'text-red-700 dark:text-red-400',       bg: 'bg-red-50 dark:bg-red-950/40',       border: 'border-red-200 dark:border-red-800',       tooltip: 'T1190 — Attacker directly exploits an internet-facing service.' },
  phishing_delivery:          { label: 'Phishing Delivery',    icon: <Mail className="h-3 w-3" />,            color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', tooltip: 'T1566 — Exploit is delivered via email or malicious link.' },
  lateral_movement_required:  { label: 'Lateral Movement',     icon: <ArrowRightLeft className="h-3 w-3" />,  color: 'text-purple-700 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-950/40', border: 'border-purple-200 dark:border-purple-800', tooltip: 'T1021/T1550 — Requires an existing foothold on another host.' },
  valid_credentials_required: { label: 'Credential-Dependent', icon: <Key className="h-3 w-3" />,             color: 'text-yellow-700 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-950/30', border: 'border-yellow-200 dark:border-yellow-800', tooltip: 'T1078 — Attack requires valid credentials.' },
  supply_chain:               { label: 'Supply Chain',          icon: <Package className="h-3 w-3" />,        color: 'text-blue-700 dark:text-blue-400',     bg: 'bg-blue-50 dark:bg-blue-950/40',     border: 'border-blue-200 dark:border-blue-800',     tooltip: 'T1195 — Compromise via a malicious dependency or update mechanism.' },
  unknown:                    { label: 'Unknown Path',           icon: <HelpCircle className="h-3 w-3" />,    color: 'text-slate-600 dark:text-slate-400',   bg: 'bg-slate-50 dark:bg-slate-900/40',   border: 'border-slate-200 dark:border-slate-700',   tooltip: 'Insufficient information to classify the initial access technique.' },
};

const LATERAL_MOVEMENT_META: Record<LateralMovementPotential, { label: string; color: string; bg: string; border: string; tooltip: string }> = {
  high:   { label: 'High Pivot Risk',   color: 'text-red-700 dark:text-red-400',       bg: 'bg-red-50 dark:bg-red-950/40',       border: 'border-red-200 dark:border-red-800',       tooltip: 'Exploitation enables wide lateral movement.' },
  medium: { label: 'Medium Pivot Risk', color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', tooltip: 'Limited pivot capability.' },
  low:    { label: 'Low Pivot Risk',    color: 'text-slate-600 dark:text-slate-400',   bg: 'bg-slate-50 dark:bg-slate-900/40',   border: 'border-slate-200 dark:border-slate-700',   tooltip: 'Isolated blast radius.' },
};

// ═══════════════════════════════════════════════════════
// Agent message renderer
// ═══════════════════════════════════════════════════════

const SECTION_LABELS = new Set([
  'WHAT TO DO:', 'WHY:', 'PRECONDITIONS ON THIS ASSET:', 'VERIFICATION STEPS:',
  'NEXT STEPS:', 'REMEDIATION:', 'DETECTION:',
]);

function AgentMessageContent({ content }: { content: string }) {
  const VERDICT_RE = /^VERDICT:\s*(.+)$/;
  const SECTION_RE = /^([A-Z][A-Z\s]+):$/;
  const BULLET_RE = /^[•\-]\s/;
  const STEP_RE = /^\d+\.\s/;
  const CHECK_RE = /^[✓✗?]\s/;

  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let key = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      elements.push(<div key={key++} className="h-1" />);
      continue;
    }

    const verdictMatch = trimmed.match(VERDICT_RE);
    if (verdictMatch) {
      const rest = verdictMatch[1];
      const cat = rest.match(/^(P[0-4])/)?.[1];
      const catStyle = cat ? (CATEGORY_STYLES[cat] ?? '') : '';
      elements.push(
        <div key={key++} className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Verdict</span>
          {cat && <span className={cn('px-2 py-0.5 rounded text-xs font-bold', catStyle)}>{cat}</span>}
          <span className="text-sm font-semibold">{rest.replace(/^P[0-4]\s*—?\s*/, '')}</span>
        </div>
      );
      continue;
    }

    const sectionMatch = trimmed.match(SECTION_RE);
    if (sectionMatch && SECTION_LABELS.has(trimmed)) {
      elements.push(
        <p key={key++} className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mt-2">
          {sectionMatch[1]}
        </p>
      );
      continue;
    }

    if (BULLET_RE.test(trimmed) || STEP_RE.test(trimmed)) {
      elements.push(
        <p key={key++} className="text-sm pl-2">{trimmed}</p>
      );
      continue;
    }

    if (CHECK_RE.test(trimmed)) {
      const icon = trimmed[0];
      const iconColor = icon === '✓' ? 'text-green-400' : icon === '✗' ? 'text-red-400' : 'text-yellow-400';
      elements.push(
        <p key={key++} className="text-sm pl-2">
          <span className={cn('font-bold', iconColor)}>{icon}</span>
          <span>{trimmed.slice(1)}</span>
        </p>
      );
      continue;
    }

    elements.push(<p key={key++} className="text-sm">{trimmed}</p>);
  }

  return <div className="space-y-0.5">{elements}</div>;
}

// ═══════════════════════════════════════════════════════
// Oracle helper components
// ═══════════════════════════════════════════════════════

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <span className={cn('px-2 py-0.5 rounded text-xs font-bold', CATEGORY_STYLES[cat] ?? 'bg-muted text-foreground')}>
      {cat}
    </span>
  );
}

function ConfidenceBadge({ c }: { c: string }) {
  const col = c === 'high' ? 'text-green-400' : c === 'medium' ? 'text-yellow-400' : 'text-muted-foreground';
  return <span className={cn('text-xs font-medium', col)}>{c} confidence</span>;
}

function ExploitabilityBadge({ score, tier }: { score: number; tier: string }) {
  const meta = EXPLOITABILITY_TIER_META[tier] ?? EXPLOITABILITY_TIER_META.moderate;
  return (
    <div className={cn('rounded-xl border px-4 py-3 flex items-center gap-4', meta.bg, meta.border)}>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-0.5">Exploitability Index</p>
        <p className={cn('text-lg font-bold leading-tight', meta.color)}>{meta.label}</p>
        <p className="text-xs text-muted-foreground mt-0.5">Practical exploitation difficulty · not CVSS severity</p>
      </div>
      <div className="flex flex-col items-center gap-1.5 shrink-0">
        <span className={cn('text-3xl font-black tabular-nums', meta.color)}>{score.toFixed(1)}</span>
        <div className="flex gap-0.5">
          {[1, 2, 3, 4, 5].map(p => (
            <div key={p} className={cn('h-1.5 w-5 rounded-full', p <= meta.bar ? meta.color.replace('text-', 'bg-').replace(' dark:text-', ' dark:bg-') : 'bg-muted')} />
          ))}
        </div>
        <span className="text-[9px] text-muted-foreground">out of 5</span>
      </div>
    </div>
  );
}

function AttackContextBadges({ attackPath, lateralMovement }: { attackPath?: AttackPathClass; lateralMovement?: LateralMovementPotential }) {
  if (!attackPath && !lateralMovement) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {attackPath && attackPath !== 'unknown' && (() => {
        const m = ATTACK_PATH_META[attackPath];
        return <span title={m.tooltip} className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', m.bg, m.border, m.color)}>{m.icon}{m.label}</span>;
      })()}
      {lateralMovement && (() => {
        const m = LATERAL_MOVEMENT_META[lateralMovement];
        return <span title={m.tooltip} className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', m.bg, m.border, m.color)}><MoveRight className="h-3 w-3" />{m.label}</span>;
      })()}
    </div>
  );
}

function AnalystBriefPanel({ brief }: { brief: AnalystBrief }) {
  return (
    <section>
      <div className="mb-3 space-y-1">
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-primary" />
          Vulnerability Intelligence
          <span className="text-[10px] font-normal text-muted-foreground ml-1">AI-generated · verify before citing</span>
        </h4>
        {brief.title && <p className="text-base font-semibold text-foreground leading-snug pl-6">{brief.title}</p>}
      </div>
      {brief.exploitability_score != null && brief.exploitability_tier && (
        <div className="mb-3"><ExploitabilityBadge score={brief.exploitability_score} tier={brief.exploitability_tier} /></div>
      )}
      <div className="space-y-2">
        {BRIEF_SECTIONS.map(({ key, label, icon, accent }) => {
          const value = brief[key as keyof AnalystBrief];
          if (!value) return null;
          return (
            <div key={key} className={cn('rounded-lg border p-3 space-y-1', accent)}>
              <p className="text-xs font-semibold flex items-center gap-1.5 text-foreground/80">{icon}{label}</p>
              <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">{value as string}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function FindingDetail({ f }: { f: OracleFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)} className="gap-1 mt-2">
        <Eye className="h-3.5 w-3.5" /> Full analysis
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-primary" />
              {f.cve_id} — {f.asset_id}
            </DialogTitle>
            <DialogDescription className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <CategoryBadge cat={f.opes.category} />
                <span className="text-sm">{f.opes.label}</span>
                <ConfidenceBadge c={f.opes.confidence} />
                <span className="text-xs text-muted-foreground ml-auto">OPES {f.opes.score.toFixed(1)} · {f.opes.evaluator_version}</span>
              </div>
              <AttackContextBadges attackPath={f.attack_path_class} lateralMovement={f.lateral_movement_potential} />
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-5 pt-2">
            {f.analyst_brief?.what_is_it && <AnalystBriefPanel brief={f.analyst_brief} />}
            <section>
              <h4 className="text-sm font-semibold mb-2">OPES Components</h4>
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-center">
                {(Object.entries(f.opes.components) as [string, number][]).map(([k, v]) => (
                  <div key={k} className="rounded-lg border p-2">
                    <div className="text-xs text-muted-foreground">{k}</div>
                    <div className="text-lg font-bold">{v.toFixed(1)}</div>
                  </div>
                ))}
              </div>
              {f.opes.dampener && <p className="mt-2 text-xs text-yellow-400 flex items-center gap-1"><AlertTriangle className="h-3.5 w-3.5" />{f.opes.dampener}</p>}
              {f.opes.override && <p className="mt-1 text-xs text-blue-400 font-medium">Override: {f.opes.override}</p>}
              <ul className="mt-2 space-y-0.5">
                {f.opes.top_contributors?.map((c, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex gap-1"><span className="text-primary">•</span> {c}</li>
                ))}
              </ul>
            </section>
            <section>
              <h4 className="text-sm font-semibold mb-2">CVSS Reconciliation</h4>
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <p>
                  <span className="text-muted-foreground">Reconciled: </span>
                  <code className="text-xs bg-muted px-1 rounded">{f.cvss_reconciliation.correct_vector}</code>
                  <span className="ml-2 font-bold">{f.cvss_reconciliation.correct_score.toFixed(1)}</span>
                </p>
                <p className="text-xs text-muted-foreground">{f.cvss_reconciliation.rationale}</p>
                {f.cvss_reconciliation.disagreements?.map((d, i) => (
                  <div key={i} className="mt-2 border-l-2 border-yellow-500 pl-2 text-xs">
                    <span className="font-medium text-yellow-400">{d.source}</span>{' '}
                    <code className="bg-muted px-1 rounded">{d.their_vector}</code>
                    <p className="text-muted-foreground mt-0.5">{d.disagreement}</p>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <h4 className="text-sm font-semibold mb-2">Preconditions</h4>
              <div className="space-y-2">
                {f.preconditions_evaluated.map((e) => (
                  <div key={e.precondition.id} className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 mb-1">
                      {STATUS_ICON[e.status]}
                      <span className="text-sm font-medium">{e.precondition.id}</span>
                      <Badge variant="outline" className="text-[10px]">{e.precondition.severity}</Badge>
                      <span className="ml-auto text-xs text-muted-foreground capitalize">{e.status}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{e.precondition.description}</p>
                    <p className="text-xs mt-1 text-foreground/70">{e.reason}</p>
                    {e.status === 'unknown' && (
                      <p className="text-xs mt-1 border-l-2 border-yellow-500 pl-2 text-yellow-400">Verify: {e.precondition.verification_method}</p>
                    )}
                  </div>
                ))}
              </div>
            </section>
            {f.verification_tasks && f.verification_tasks.length > 0 && (
              <section>
                <h4 className="text-sm font-semibold mb-2">Open Verification Tasks</h4>
                <div className="space-y-2">
                  {f.verification_tasks.map((t) => (
                    <div key={t.id} className="rounded-lg border p-3 text-xs space-y-1">
                      <p className="font-medium">{t.summary}</p>
                      {t.command && <code className="block bg-muted rounded px-2 py-1 font-mono">{t.command}</code>}
                      <p className="text-muted-foreground">Signal: {t.expected_signal_path}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}
            <section>
              <h4 className="text-sm font-semibold mb-1">Recommendation</h4>
              <p className="text-sm text-muted-foreground whitespace-pre-wrap">{f.recommendation}</p>
            </section>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function OpenFindingsTable({ findings, onSelect }: { findings: OracleFinding[]; onSelect: (f: OracleFinding) => void }) {
  const [selected, setSelected] = useState<OracleFinding | null>(null);
  return (
    <>
      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CVE</TableHead>
              <TableHead>Asset</TableHead>
              <TableHead>OPES</TableHead>
              <TableHead className="hidden md:table-cell">Label</TableHead>
              <TableHead className="hidden lg:table-cell">Confidence</TableHead>
              <TableHead className="w-8" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  No open findings yet.
                </TableCell>
              </TableRow>
            )}
            {findings.map((f) => (
              <TableRow key={`${f.cve_id}-${f.asset_id}`} className="cursor-pointer hover:bg-muted/50" onClick={() => { setSelected(f); onSelect(f); }}>
                <TableCell className="font-mono text-xs">{f.cve_id}</TableCell>
                <TableCell className="text-xs text-muted-foreground max-w-[120px] truncate">{f.asset_id}</TableCell>
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <CategoryBadge cat={f.opes.category} />
                    <span className="text-xs font-medium">{f.opes.score.toFixed(1)}</span>
                  </div>
                </TableCell>
                <TableCell className="hidden md:table-cell text-xs">{f.opes.label}</TableCell>
                <TableCell className="hidden lg:table-cell"><ConfidenceBadge c={f.opes.confidence} /></TableCell>
                <TableCell>
                  <Button size="icon" variant="ghost" className="h-6 w-6" onClick={(e) => { e.stopPropagation(); setSelected(f); }}>
                    <Eye className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {selected && (
        <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
          <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
            <DialogHeader><DialogTitle>{selected.cve_id} — {selected.asset_id}</DialogTitle></DialogHeader>
            <FindingDetail f={selected} />
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CveLookupResult({ data }: { data: { cve: any; analysis: any; exploitation: any; analysis_status?: string; analysis_error?: string } }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cve = data.cve ?? {} as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const a = data.analysis ?? {} as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e = data.exploitation ?? {} as any;
  const brief: AnalystBrief | undefined = a.analyst_brief;
  const tierMeta = brief?.exploitability_tier ? (EXPLOITABILITY_TIER_META[brief.exploitability_tier] ?? EXPLOITABILITY_TIER_META.moderate) : null;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border bg-card p-4 space-y-2">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="space-y-1">
            <p className="font-mono text-sm font-semibold">{cve.cve_id ?? cve.id ?? a.cve_id}</p>
            {brief?.title && <p className="text-base font-medium">{brief.title}</p>}
          </div>
          {brief?.exploitability_score != null && brief.exploitability_tier && tierMeta && (
            <div className={cn('rounded-full px-3 py-1 text-xs font-semibold border', tierMeta.bg, tierMeta.border, tierMeta.color)}>
              {tierMeta.label} · {brief.exploitability_score.toFixed(1)}/5
            </div>
          )}
        </div>
        <div className="flex items-center gap-2 flex-wrap text-xs text-muted-foreground">
          {a.attack_path_class && <Badge variant="outline" className="text-[10px]">{String(a.attack_path_class).replace(/_/g, ' ')}</Badge>}
          {a.lateral_movement_potential && <Badge variant="outline" className="text-[10px]">lateral: {a.lateral_movement_potential}</Badge>}
          {cve.in_kev && <Badge variant="destructive" className="text-[10px]">CISA KEV</Badge>}
          {a.cvss_reconciliation?.correct_score != null && <span className="font-semibold text-foreground">{Number(a.cvss_reconciliation.correct_score).toFixed(1)}</span>}
        </div>
      </div>

      {data.analysis_status === 'failed' && data.analysis_error && (
        <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/5 p-3 text-sm text-yellow-300 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
          <div>
            <p className="font-medium">CVE intelligence found, analysis incomplete</p>
            <p className="text-xs opacity-90">{data.analysis_error}</p>
          </div>
        </div>
      )}

      {brief?.what_is_it && <AnalystBriefPanel brief={brief} />}

      {e && (e.in_kev_sources?.length || e.metasploit_available || e.vulncheck_reported_exploited || e.ransomware_associated || e.zero_day_confirmed) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Flame className="h-4 w-4 text-primary" /> Exploitation Evidence</CardTitle>
          </CardHeader>
          <CardContent className="text-xs space-y-1.5">
            {e.in_kev_sources?.map((src: string) => <p key={src}><Badge variant="destructive" className="mr-2 text-[10px]">{src}</Badge>confirmed exploited</p>)}
            {e.ransomware_associated && <p><Badge variant="destructive" className="mr-2 text-[10px]">ransomware</Badge>used by ransomware operators</p>}
            {e.zero_day_confirmed && <p><Badge variant="destructive" className="mr-2 text-[10px]">0day</Badge>exploited before patch existed</p>}
            {e.vulncheck_reported_exploited && <p><Badge variant="outline" className="mr-2 text-[10px]">VulnCheck</Badge>reported in the wild</p>}
            {e.vulncheck_weaponized && <p><Badge variant="outline" className="mr-2 text-[10px]">VulnCheck</Badge>validated weaponised exploit</p>}
            {e.vulncheck_threat_actor_count > 0 && <p><Badge variant="outline" className="mr-2 text-[10px]">threat actors</Badge>linked to {e.vulncheck_threat_actor_count} group(s)</p>}
            {e.metasploit_available && <p><Badge variant="outline" className="mr-2 text-[10px]">Metasploit</Badge>{e.metasploit_module_count > 1 ? `${e.metasploit_module_count} modules available` : 'module available (push-button)'}</p>}
            {e.cisa_ssvc_decision && <p><Badge variant="outline" className="mr-2 text-[10px]">CISA SSVC</Badge>{e.cisa_ssvc_decision}</p>}
            {e.recent_poc_days > 0 && e.recent_poc_days <= 30 && <p><Badge variant="outline" className="mr-2 text-[10px]">PoC</Badge>public PoC within {e.recent_poc_days} days</p>}
          </CardContent>
        </Card>
      )}

      {a.preconditions?.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-primary" /> Preconditions</CardTitle>
            <CardDescription className="text-xs">Facts that must hold for exploitation. Verify each on the target.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            {a.preconditions.map((p: any) => (
              <div key={p.id} className="rounded-lg border p-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-medium">{p.id}</span>
                  <Badge variant="outline" className="text-[9px]">{p.severity}</Badge>
                </div>
                <p className="text-xs text-muted-foreground">{p.description}</p>
                {p.verification_method && <p className="text-[11px] mt-1 border-l-2 border-yellow-500 pl-2 text-yellow-400">Verify: {p.verification_method}</p>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════

export default function AgentPage() {
  const searchParams = useSearchParams();

  // ── Agent state ─────────────────────────────────────────────────
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [agentAvailable, setAgentAvailable] = useState<boolean | null>(null);
  const [agentStatusHint, setAgentStatusHint] = useState<string | null>(null);
  const [pendingAnswer, setPendingAnswer] = useState(false);
  const [playbooks, setPlaybooks] = useState<{ id: string; name: string; description: string }[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('custom');
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<'assist' | 'agent'>('assist');
  const [urlPrefilled, setUrlPrefilled] = useState(false);
  const [connectionMode, setConnectionMode] = useState<ConnectionMode>('connecting');
  const [liveStatus, setLiveStatus] = useState<StatusUpdate | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const wsAuthenticatedRef = useRef(false);
  const wsFailCountRef = useRef(0);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [chainData, setChainData] = useState<ChainData | null>(null);
  const [scenarioCollapsed, setScenarioCollapsed] = useState(false);
  const [showScenario, setShowScenario] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // ── Oracle state ─────────────────────────────────────────────────
  const [findings, setFindings] = useState<OracleFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [filterCat, setFilterCat] = useState<string>('all');
  const [showCveLookup, setShowCveLookup] = useState(false);
  const [showFindings, setShowFindings] = useState(false);
  const [cveLookupId, setCveLookupId] = useState('');
  const [cveLookup, setCveLookup] = useState<{ cve: unknown; analysis: unknown; exploitation: unknown; analysis_status?: string; analysis_error?: string } | null>(null);
  const [cveLookupLoading, setCveLookupLoading] = useState(false);
  const [cveLookupError, setCveLookupError] = useState<string | null>(null);
  const [cveLookupStatus, setCveLookupStatus] = useState<string | null>(null);

  const { toast } = useToast();

  // ── URL prefill ────────────────────────────────────────────────
  useEffect(() => {
    const t = searchParams.get('target');
    const p = searchParams.get('playbook');
    const q = searchParams.get('question');
    if (t != null && t !== '') setTarget(decodeURIComponent(t));
    if (p != null && p !== '') setSelectedPlaybookId(decodeURIComponent(p));
    if (q != null && q !== '') { setQuestion(decodeURIComponent(q)); setUrlPrefilled(true); }
    // Open findings panel if ?view=oracle
    if (searchParams.get('view') === 'oracle') setShowFindings(true);
  }, [searchParams]);

  const scrollToBottom = () => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  useEffect(() => { scrollToBottom(); }, [messages, liveStatus]);

  // ── Agent status + playbooks + conversations ───────────────────
  useEffect(() => {
    api.getAgentStatus()
      .then((data: { available?: boolean; hint?: string }) => {
        setAgentAvailable(data?.available ?? false);
        setAgentStatusHint(data?.hint ?? null);
      })
      .catch((err: unknown) => {
        setAgentAvailable(false);
        setAgentStatusHint(getApiErrorMessage(err as Error, 'Could not reach agent status.'));
      });
  }, []);

  useEffect(() => {
    if (agentAvailable) {
      api.getAgentPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
      loadConversations();
      if (!sessionId) setSessionId(crypto.randomUUID());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentAvailable]);

  const loadConversations = useCallback(() => {
    api.getAgentConversations(50)
      .then((data: ConversationSummary[]) => setConversations(data || []))
      .catch(() => setConversations([]));
  }, []);

  // ── WebSocket ─────────────────────────────────────────────────
  const connectWebSocket = useCallback((sid: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;
    const token = api.getToken();
    if (!token) { setConnectionMode('rest'); return; }
    if (wsFailCountRef.current >= 1) { setConnectionMode('rest'); return; }

    setConnectionMode('connecting');
    const url = api.getAgentWebSocketUrl(sid);
    const ws = new WebSocket(url);
    wsRef.current = ws;
    wsAuthenticatedRef.current = false;

    ws.onopen = () => { ws.send(JSON.stringify({ type: 'init', token })); };
    ws.onmessage = (event) => {
      try { const data = JSON.parse(event.data); handleWsMessage(data, sid); } catch { /* ignore */ }
    };
    ws.onerror = () => { wsFailCountRef.current += 1; wsRef.current = null; wsAuthenticatedRef.current = false; setConnectionMode('rest'); };
    ws.onclose = () => { wsRef.current = null; wsAuthenticatedRef.current = false; setConnectionMode('rest'); };
  }, []);

  const handleWsMessage = useCallback((data: Record<string, unknown>, sid: string) => {
    const msgType = data.type as string;
    if (msgType === 'authenticated') {
      wsAuthenticatedRef.current = true; setConnectionMode('websocket');
    } else if (['thinking', 'tool_start', 'tool_complete'].includes(msgType)) {
      setLiveStatus(data as unknown as StatusUpdate);
    } else if (msgType === 'attack_scenario_update') {
      if (data.chain) setChainData(data.chain as ChainData);
    } else if (msgType === 'response') {
      setLiveStatus(null); setLoading(false);
      appendAgentMessage({
        answer: data.answer as string,
        current_phase: data.current_phase as string,
        task_complete: data.task_complete as boolean,
        execution_trace_summary: data.execution_trace_summary as string,
        awaiting_approval: data.awaiting_approval as boolean,
        approval_request: data.approval_request as Record<string, unknown>,
        awaiting_question: data.awaiting_question as boolean,
        question_request: data.question_request as Record<string, unknown>,
      });
      if (data.awaiting_question) setPendingAnswer(true);
      loadConversations();
      if (sid) api.getAgentSessionChain(sid, true).then(setChainData).catch(() => {});
    } else if (msgType === 'error') {
      setLiveStatus(null); setLoading(false);
      const errMsg = (data.message as string) || 'Unknown error';
      toast({ variant: 'destructive', title: 'Agent error', description: errMsg });
      appendAgentMessage({ answer: `Error: ${errMsg}` });
    }
  }, []);

  useEffect(() => () => { if (wsRef.current) { wsRef.current.close(); wsRef.current = null; } }, []);

  useEffect(() => {
    if (sessionId && agentAvailable) connectWebSocket(sessionId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, agentAvailable]);

  useEffect(() => {
    const interval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify({ type: 'ping' }));
    }, 25000);
    return () => clearInterval(interval);
  }, []);

  const loadingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (loading) {
      loadingTimeoutRef.current = setTimeout(() => {
        setLoading(false); setLiveStatus(null);
        toast({ variant: 'destructive', title: 'Timeout', description: 'No response from the agent after 3 minutes.' });
        appendAgentMessage({ answer: 'Error: No response received within 3 minutes. Please try again.' });
      }, 180_000);
    } else if (loadingTimeoutRef.current) {
      clearTimeout(loadingTimeoutRef.current); loadingTimeoutRef.current = null;
    }
    return () => { if (loadingTimeoutRef.current) clearTimeout(loadingTimeoutRef.current); };
  }, [loading]);

  // ── Message helpers ───────────────────────────────────────────
  const appendAgentMessage = (payload: {
    answer: string; current_phase?: string; task_complete?: boolean;
    execution_trace_summary?: string; awaiting_approval?: boolean;
    approval_request?: Record<string, unknown>; awaiting_question?: boolean;
    question_request?: Record<string, unknown>;
  }) => {
    setMessages((prev) => [...prev, {
      id: `agent-${Date.now()}`, role: 'agent', content: payload.answer || '(No response)',
      phase: payload.current_phase, taskComplete: payload.task_complete,
      traceSummary: payload.execution_trace_summary, awaitingApproval: payload.awaiting_approval,
      approvalRequest: payload.approval_request, awaitingQuestion: payload.awaiting_question,
      questionRequest: payload.question_request,
    }]);
  };

  const sendViaWs = (msgObj: Record<string, unknown>): boolean => {
    if (wsRef.current?.readyState === WebSocket.OPEN && wsAuthenticatedRef.current) {
      wsRef.current.send(JSON.stringify(msgObj)); return true;
    }
    return false;
  };

  const handleSend = async () => {
    const q = question.trim();
    const usePreset = selectedPlaybookId !== 'custom';
    if (!usePreset && !q) return;
    if (loading) return;

    const displayContent = usePreset
      ? `${playbooks.find((p) => p.id === selectedPlaybookId)?.name ?? selectedPlaybookId}${target.trim() ? ` — ${target.trim()}` : ''}`
      : q;

    setMessages((prev) => [...prev, { id: `user-${Date.now()}`, role: 'user', content: displayContent }]);
    if (!usePreset) setQuestion('');
    setUrlPrefilled(false); setLoading(true); setLiveStatus(null);

    const sid = sessionId || crypto.randomUUID();
    if (!sessionId) setSessionId(sid);

    try {
      if (pendingAnswer && sid) {
        setPendingAnswer(false);
        const sent = sendViaWs({ type: 'answer', answer: q || displayContent });
        if (!sent) {
          const data = await api.answerAgentQuestion(sid, q || displayContent);
          setLoading(false); appendAgentMessage(data);
          if (data.awaiting_question) setPendingAnswer(true);
          loadConversations();
        }
      } else {
        const wsMsg: Record<string, unknown> = { type: 'query', question: usePreset ? displayContent : q, mode };
        if (usePreset) { wsMsg.playbook_id = selectedPlaybookId; wsMsg.target = target.trim() || undefined; }
        const sent = sendViaWs(wsMsg);
        if (!sent) {
          const data = await api.queryAgent(usePreset ? displayContent : q, sid, {
            ...(usePreset ? { playbookId: selectedPlaybookId, target: target.trim() || undefined } : {}), mode,
          });
          setLoading(false);
          if (data.session_id) setSessionId(data.session_id);
          appendAgentMessage(data);
          if (data.awaiting_question) setPendingAnswer(true);
          if (data.error) toast({ variant: 'destructive', title: 'Agent error', description: data.error });
          loadConversations();
        }
      }
    } catch (err: unknown) {
      setLoading(false);
      const msg = getApiErrorMessage(err as Error, 'Failed to send');
      toast({ variant: 'destructive', title: 'Error', description: msg });
      appendAgentMessage({ answer: `Error: ${msg}` });
    }
  };

  const handleApprove = async (decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!sessionId || loading) return;
    setLoading(true); setLiveStatus(null);
    const sent = sendViaWs({ type: 'approval', decision, modification });
    if (!sent) {
      try {
        const data = await api.approveAgent(sessionId, decision, modification);
        setLoading(false); appendAgentMessage(data);
        if (data.awaiting_question) setPendingAnswer(true);
        loadConversations();
      } catch (err: unknown) {
        setLoading(false);
        toast({ variant: 'destructive', title: 'Error', description: getApiErrorMessage(err as Error) });
      }
    }
  };

  const loadConversation = async (sid: string) => {
    try {
      const data = await api.getAgentConversation(sid);
      setSessionId(sid);
      const restored: Message[] = (data.messages || []).map((m: { role: string; content: string }, i: number) => ({
        id: `${m.role}-${i}`, role: m.role as MessageRole, content: m.content,
        phase: m.role === 'agent' ? data.current_phase : undefined,
      }));
      setMessages(restored); setShowHistory(false); setPendingAnswer(false);
      api.getAgentSessionChain(sid, true).then(setChainData).catch(() => setChainData(null));
    } catch {
      toast({ variant: 'destructive', title: 'Error', description: 'Could not load conversation' });
    }
  };

  const deleteConversation = async (sid: string) => {
    try {
      await api.deleteAgentConversation(sid);
      setConversations((prev) => prev.filter((c) => c.session_id !== sid));
      if (sessionId === sid) startNewConversation();
    } catch {
      toast({ variant: 'destructive', title: 'Error', description: 'Could not delete conversation' });
    }
  };

  const startNewConversation = () => {
    setMessages([]); setPendingAnswer(false); setLiveStatus(null); setShowHistory(false); setChainData(null);
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
    wsAuthenticatedRef.current = false; wsFailCountRef.current = 0;
    setSessionId(crypto.randomUUID()); setConnectionMode('connecting');
  };

  // ── Oracle functions ─────────────────────────────────────────
  const loadFindings = useCallback(async () => {
    setFindingsLoading(true);
    try { const data = await api.oracleGetFindings(); setFindings(data?.findings ?? []); }
    catch { /* silently fail */ }
    finally { setFindingsLoading(false); }
  }, []);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  const handleCveLookup = async () => {
    const raw = cveLookupId.trim().toUpperCase();
    if (!raw) return;
    if (!/^CVE-\d{4}-\d{4,7}$/.test(raw)) { setCveLookupError('Please enter a CVE id in the form CVE-YYYY-NNNN.'); return; }
    setCveLookupError(null); setCveLookupLoading(true); setCveLookupStatus('Fetching CVE intelligence…');
    const slowTimer = setTimeout(() => setCveLookupStatus('Ingesting this CVE on demand (first lookup may take 30–60s)…'), 5000);
    try {
      const data = await api.oracleCveLookup(raw);
      setCveLookup(data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } }; message?: string })?.response?.data?.detail
        ?? (err as { message?: string })?.message ?? 'Oracle is unavailable.';
      setCveLookupError(msg); setCveLookup(null);
      toast({ variant: 'destructive', title: 'CVE lookup failed', description: msg });
    } finally {
      clearTimeout(slowTimer); setCveLookupStatus(null); setCveLookupLoading(false);
    }
  };

  const filteredFindings = findings.filter((f) => filterCat === 'all' || f.opes.category === filterCat);
  const countByCategory = (cat: string) => findings.filter((f) => f.opes.category === cat).length;

  // ── Render helpers ────────────────────────────────────────────
  const connectionBadge = () => {
    switch (connectionMode) {
      case 'websocket':  return <Badge variant="outline" className="text-green-500 border-green-500 gap-1 text-xs"><Wifi className="h-3 w-3" /> Live</Badge>;
      case 'rest':       return <Badge variant="outline" className="text-yellow-500 border-yellow-500 gap-1 text-xs"><WifiOff className="h-3 w-3" /> REST</Badge>;
      case 'connecting': return <Badge variant="outline" className="text-muted-foreground gap-1 text-xs"><Loader2 className="h-3 w-3 animate-spin" /> Connecting</Badge>;
      default:           return <Badge variant="outline" className="text-red-500 border-red-500 gap-1 text-xs"><WifiOff className="h-3 w-3" /> Offline</Badge>;
    }
  };

  const renderLiveStatus = () => {
    if (!liveStatus) return null;
    const { type, iteration, phase, thought, tool_name, success, output_summary } = liveStatus;
    if (type === 'thinking') return (
      <div className="flex items-start gap-2 text-muted-foreground text-sm animate-pulse">
        <Loader2 className="h-4 w-4 animate-spin mt-0.5 shrink-0" />
        <div>
          <span className="font-medium">Step {iteration}</span>
          {phase && <Badge variant="outline" className="ml-2 text-xs">{phase}</Badge>}
          {thought && <p className="text-xs mt-0.5 opacity-80">{thought}</p>}
        </div>
      </div>
    );
    if (type === 'tool_start') return (
      <div className="flex items-start gap-2 text-muted-foreground text-sm">
        <Loader2 className="h-4 w-4 animate-spin mt-0.5 shrink-0" />
        <div><span className="font-medium">Running tool:</span>{' '}<code className="bg-muted px-1 rounded text-xs">{tool_name}</code></div>
      </div>
    );
    if (type === 'tool_complete') return (
      <div className="flex items-start gap-2 text-muted-foreground text-sm">
        {success ? <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" /> : <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />}
        <div>
          <code className="bg-muted px-1 rounded text-xs">{tool_name}</code>{' '}
          <span className="text-xs">{success ? 'completed' : 'failed'}</span>
          {output_summary && <p className="text-xs mt-0.5 opacity-70">{output_summary}</p>}
        </div>
      </div>
    );
    return null;
  };

  // ── Render ────────────────────────────────────────────────────
  return (
    <MainLayout>
      <div className="flex flex-col h-full">
        <Header
          title="Agent"
          subtitle="AI security agent — run scans, query assets, and analyze vulnerabilities"
        />

        <div className="flex-1 overflow-auto p-6 space-y-4">

          {/* Oracle OPES strip — only visible once there are findings */}
          {findings.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap rounded-lg border bg-card/50 px-4 py-2.5">
              <span className="text-xs text-muted-foreground font-medium shrink-0">Oracle findings:</span>
              {(['P0', 'P1', 'P2', 'P3', 'P4'] as const).map((cat) => {
                const count = countByCategory(cat);
                if (count === 0) return null;
                return (
                  <button
                    key={cat}
                    onClick={() => { setFilterCat(cat); setShowFindings(true); }}
                    className="flex items-center gap-1 hover:opacity-80 transition-opacity"
                  >
                    <CategoryBadge cat={cat} />
                    <span className="text-xs font-semibold">{count}</span>
                  </button>
                );
              })}
              <button
                onClick={() => { setShowFindings(!showFindings); setFilterCat('all'); }}
                className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
              >
                {showFindings ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                {showFindings ? 'Hide findings' : 'View all'}
              </button>
            </div>
          )}

          {/* Agent unavailable warning */}
          {agentAvailable === false && (
            <Card className="border-amber-500/50 bg-amber-500/5">
              <CardContent className="pt-4 flex flex-col gap-2">
                <p className="text-sm flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-amber-500 shrink-0" />
                  Agent is not available.
                </p>
                {agentStatusHint && <p className="text-sm text-muted-foreground pl-7">{agentStatusHint}</p>}
                {!agentStatusHint && (
                  <p className="text-sm text-muted-foreground pl-7">
                    Configure <code className="bg-muted px-1 rounded">OPENAI_API_KEY</code> or <code className="bg-muted px-1 rounded">ANTHROPIC_API_KEY</code> in the backend .env, then restart.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Main agent area */}
          <div className="flex gap-4">
            {/* Conversation history sidebar */}
            {showHistory && (
              <Card className="w-72 shrink-0">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm flex items-center gap-1.5"><History className="h-4 w-4" /> History</CardTitle>
                    <Button variant="ghost" size="sm" onClick={startNewConversation} className="h-7 px-2">
                      <Plus className="h-3.5 w-3.5 mr-1" /> New
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="p-2 max-h-[60vh] overflow-y-auto space-y-1">
                  {conversations.length === 0 && <p className="text-xs text-muted-foreground p-2">No conversations yet.</p>}
                  {conversations.map((c) => (
                    <div
                      key={c.session_id}
                      className={`flex items-center gap-1.5 rounded-md px-2 py-1.5 cursor-pointer text-sm hover:bg-muted/60 transition-colors ${c.session_id === sessionId ? 'bg-muted' : ''}`}
                      onClick={() => loadConversation(c.session_id)}
                    >
                      <div className="flex-1 min-w-0">
                        <p className="truncate font-medium text-xs">{c.title || c.session_id.slice(0, 8)}</p>
                        <p className="text-[10px] text-muted-foreground">{new Date(c.updated_at).toLocaleDateString()} · {c.message_count} msgs</p>
                      </div>
                      <Badge variant="outline" className="text-[10px] shrink-0">{c.current_phase}</Badge>
                      <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 opacity-50 hover:opacity-100"
                        onClick={(e) => { e.stopPropagation(); deleteConversation(c.session_id); }}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Chat card */}
            <Card className="flex-1">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <MessageSquare className="h-5 w-5" />
                    AI Security Agent
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    {connectionBadge()}
                    <Button variant="ghost" size="sm" onClick={() => setShowScenario(!showScenario)}
                      className={`h-8 px-2 ${showScenario ? 'bg-muted' : ''}`} title="Toggle attack scenario panel">
                      <Crosshair className="h-4 w-4 mr-1" />
                      <span className="text-xs">{showScenario ? 'Hide' : 'Scenario'}</span>
                    </Button>
                    <Button variant="ghost" size="sm"
                      onClick={() => { setShowHistory(!showHistory); if (!showHistory) loadConversations(); }}
                      className="h-8 px-2">
                      <Clock className="h-4 w-4 mr-1" />
                      <span className="text-xs">{showHistory ? 'Hide' : 'History'}</span>
                    </Button>
                  </div>
                </div>
                <CardDescription>
                  Query assets, scan targets, and analyze your attack surface. Use the CVE Lookup and Findings sections below for exploitability intelligence.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-lg border bg-muted/30 max-h-[50vh] overflow-y-auto p-4 space-y-3">
                  {messages.length === 0 && (
                    <p className="text-muted-foreground text-sm">Send a message to start. The agent can run scans and discovery for your organization.</p>
                  )}
                  {messages.map((m) => (
                    <div key={m.id} className={`flex flex-col gap-1 ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
                      <div className={`rounded-lg px-3 py-2 max-w-[85%] ${m.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted border'}`}>
                        {m.role === 'agent'
                          ? <AgentMessageContent content={m.content} />
                          : <p className="text-sm whitespace-pre-wrap">{m.content}</p>
                        }
                        {m.role === 'agent' && m.phase && <Badge variant="outline" className="mt-2 text-xs">{m.phase}</Badge>}
                        {m.role === 'agent' && m.taskComplete && (
                          <span className="ml-2 text-xs text-muted-foreground flex items-center gap-1">
                            <CheckCircle className="h-3 w-3" /> Task complete
                          </span>
                        )}
                        {m.role === 'agent' && m.traceSummary && (
                          <details className="mt-2">
                            <summary className="text-xs cursor-pointer text-muted-foreground">Execution trace</summary>
                            <pre className="text-xs mt-1 p-2 rounded bg-background overflow-x-auto whitespace-pre-wrap">{m.traceSummary}</pre>
                          </details>
                        )}
                      </div>
                      {m.role === 'agent' && m.awaitingApproval && m.approvalRequest && (
                        <div className="flex flex-wrap gap-2 mt-1">
                          <Button size="sm" onClick={() => handleApprove('approve')} disabled={loading}>Approve</Button>
                          <Button size="sm" variant="outline" onClick={() => handleApprove('abort')} disabled={loading}>Abort</Button>
                        </div>
                      )}
                      {m.role === 'agent' && m.awaitingQuestion && m.questionRequest && (
                        <p className="text-xs text-muted-foreground mt-1">Type your answer below and press Send.</p>
                      )}
                    </div>
                  ))}
                  {loading && renderLiveStatus()}
                  {loading && !liveStatus && (
                    <div className="flex items-center gap-2 text-muted-foreground text-sm">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Agent is thinking and may run tools…
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="mode-select">Mode</Label>
                    <Select value={mode} onValueChange={(v) => setMode(v as 'assist' | 'agent')}>
                      <SelectTrigger id="mode-select"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="assist">Assist (approval required between phases)</SelectItem>
                        <SelectItem value="agent">Agent (autonomous; no approval)</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">Agent mode runs without asking for approval between phases.</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="playbook-select">Preset</Label>
                    <Select value={selectedPlaybookId} onValueChange={setSelectedPlaybookId}>
                      <SelectTrigger id="playbook-select"><SelectValue placeholder="Custom" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="custom">Custom (free-form question)</SelectItem>
                        {playbooks.map((p) => <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  {selectedPlaybookId !== 'custom' && (
                    <div className="space-y-1.5">
                      <Label htmlFor="target-input">Target (optional)</Label>
                      <Input id="target-input" placeholder="e.g. example.com" value={target}
                        onChange={(e) => setTarget(e.target.value)} disabled={loading || agentAvailable === false} />
                    </div>
                  )}
                </div>

                {urlPrefilled && <p className="text-sm text-muted-foreground">Pre-filled from link. Click Send to start.</p>}

                <div className="flex gap-2">
                  <Textarea
                    placeholder={
                      pendingAnswer ? 'Type your answer to the agent…'
                        : selectedPlaybookId === 'custom' ? 'Ask a question (e.g. run a port scan on example.com)'
                        : 'Add a note or leave blank to run the preset'
                    }
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                    rows={2} className="resize-none"
                    disabled={loading || agentAvailable === false}
                  />
                  <Button
                    onClick={handleSend}
                    disabled={loading || agentAvailable === false || (selectedPlaybookId === 'custom' ? !question.trim() : false)}
                    size="icon" className="shrink-0 h-auto py-3"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  </Button>
                </div>
                {sessionId && <p className="text-xs text-muted-foreground">Session: {sessionId.slice(0, 8)}…</p>}
              </CardContent>
            </Card>

            {/* Attack scenario panel */}
            {showScenario && (
              <AttackScenarioPanel
                chainData={chainData} loading={loading}
                collapsed={scenarioCollapsed}
                onToggleCollapse={() => setScenarioCollapsed(!scenarioCollapsed)}
              />
            )}
          </div>

          {/* ── CVE Quick Lookup (collapsible) ── */}
          <div className="rounded-lg border bg-card">
            <button
              onClick={() => setShowCveLookup(!showCveLookup)}
              className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/40 transition-colors rounded-lg"
            >
              <span className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                CVE Quick Lookup
                <span className="text-xs text-muted-foreground font-normal">— exploitability intel without an asset</span>
              </span>
              {showCveLookup ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
            </button>

            {showCveLookup && (
              <div className="px-4 pb-4 space-y-4 border-t pt-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="CVE-2026-0300"
                    value={cveLookupId}
                    onChange={(e) => setCveLookupId(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCveLookup(); } }}
                    disabled={cveLookupLoading}
                    className="font-mono"
                  />
                  <Button onClick={handleCveLookup} disabled={cveLookupLoading || !cveLookupId.trim()} className="shrink-0">
                    {cveLookupLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    <span className="ml-1.5">Analyze</span>
                  </Button>
                </div>

                {cveLookupError && (
                  <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-400 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                    <div><p className="font-medium">Lookup failed</p><p className="text-xs opacity-90">{cveLookupError}</p></div>
                  </div>
                )}

                {cveLookupLoading && cveLookupStatus && (
                  <div className="rounded-lg border bg-muted/30 p-3 text-sm flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin shrink-0" />
                    <p className="text-muted-foreground">{cveLookupStatus}</p>
                  </div>
                )}

                {cveLookup && <CveLookupResult data={cveLookup as Parameters<typeof CveLookupResult>[0]['data']} />}

                {!cveLookup && !cveLookupError && !cveLookupLoading && (
                  <p className="text-xs text-muted-foreground">
                    Enter a CVE id to get an analyst brief, attack path, exploitation evidence, and preconditions.
                  </p>
                )}
              </div>
            )}
          </div>

          {/* ── Open Findings (collapsible) ── */}
          <div className="rounded-lg border bg-card">
            <button
              onClick={() => { setShowFindings(!showFindings); if (!showFindings) loadFindings(); }}
              className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/40 transition-colors rounded-lg"
            >
              <span className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                Open Findings
                {findings.length > 0 && (
                  <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">{findings.length}</Badge>
                )}
              </span>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost" size="sm" className="h-6 w-6 p-0"
                  onClick={(e) => { e.stopPropagation(); loadFindings(); }}
                  disabled={findingsLoading}
                  title="Refresh findings"
                >
                  <RefreshCw className={cn('h-3.5 w-3.5 text-muted-foreground', findingsLoading && 'animate-spin')} />
                </Button>
                {showFindings ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
              </div>
            </button>

            {showFindings && (
              <div className="px-4 pb-4 border-t pt-4 space-y-3">
                <div className="flex gap-2 flex-wrap">
                  {['all', 'P0', 'P1', 'P2', 'P3', 'P4'].map((c) => (
                    <Button key={c} size="sm" variant={filterCat === c ? 'default' : 'outline'}
                      onClick={() => setFilterCat(c)} className="h-7 px-2.5 text-xs">
                      {c === 'all' ? 'All' : <><CategoryBadge cat={c} /><span className="ml-1">{countByCategory(c)}</span></>}
                    </Button>
                  ))}
                </div>
                <OpenFindingsTable
                  findings={filteredFindings.sort((a, b) => b.opes.score - a.opes.score)}
                  onSelect={() => {}}
                />
              </div>
            )}
          </div>

        </div>
      </div>
    </MainLayout>
  );
}
