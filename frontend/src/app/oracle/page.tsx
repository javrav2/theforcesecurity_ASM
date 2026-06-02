'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog';
import {
  Send, Loader2, Eye, ShieldAlert, CheckCircle2, HelpCircle,
  XCircle, AlertTriangle, Flame, TrendingUp, RefreshCw, BookOpen,
  Crosshair, Globe, BarChart2, Code2, ShieldCheck, Mail, Network,
  ArrowRightLeft, Key, Package, MoveRight, Search,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

// ─────────────────────────── Types ──────────────────────────────────────

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

interface ChatMessage {
  id: string;
  role: 'user' | 'oracle';
  content: string;
  finding?: OracleFinding;
  loading?: boolean;
  iterations?: number;
  trace?: TraceStep[];
}

// ─────────────────────────── Helpers ──────────────────────────────────

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

// ─────────────────────────── Analyst Brief panel ───────────────────────

const BRIEF_SECTIONS: { key: keyof Omit<AnalystBrief, 'title'>; label: string; icon: React.ReactNode; accent: string }[] = [
  {
    key: 'what_is_it',
    label: 'What is this vulnerability?',
    icon: <BookOpen className="h-4 w-4" />,
    accent: 'border-blue-500/30 bg-blue-500/5',
  },
  {
    key: 'attack_vector_summary',
    label: 'Attack vector',
    icon: <Globe className="h-4 w-4" />,
    accent: 'border-orange-500/30 bg-orange-500/5',
  },
  {
    key: 'attack_scenario',
    label: 'How would an attacker exploit this?',
    icon: <Crosshair className="h-4 w-4" />,
    accent: 'border-red-500/30 bg-red-500/5',
  },
  {
    key: 'real_world_likelihood',
    label: 'Real-world exploitation likelihood',
    icon: <BarChart2 className="h-4 w-4" />,
    accent: 'border-purple-500/30 bg-purple-500/5',
  },
  {
    key: 'affected_if',
    label: 'You are affected if…',
    icon: <Code2 className="h-4 w-4" />,
    accent: 'border-yellow-500/30 bg-yellow-500/5',
  },
  {
    key: 'not_affected_if',
    label: 'You are NOT affected if…',
    icon: <ShieldCheck className="h-4 w-4" />,
    accent: 'border-green-500/30 bg-green-500/5',
  },
];

const EXPLOITABILITY_TIER_META: Record<string, { label: string; color: string; bg: string; border: string; bar: number }> = {
  push_button:   { label: 'Push-Button',   color: 'text-red-700 dark:text-red-400',    bg: 'bg-red-50 dark:bg-red-950/40',    border: 'border-red-200 dark:border-red-800',    bar: 5 },
  opportunistic: { label: 'Opportunistic',  color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', bar: 4 },
  moderate:      { label: 'Moderate',       color: 'text-yellow-700 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-950/30', border: 'border-yellow-200 dark:border-yellow-800', bar: 3 },
  targeted:      { label: 'Targeted',       color: 'text-blue-700 dark:text-blue-400',   bg: 'bg-blue-50 dark:bg-blue-950/40',   border: 'border-blue-200 dark:border-blue-800',   bar: 2 },
  theoretical:   { label: 'Theoretical',    color: 'text-slate-600 dark:text-slate-400', bg: 'bg-slate-50 dark:bg-slate-900/40', border: 'border-slate-200 dark:border-slate-700', bar: 1 },
};

function ExploitabilityBadge({ score, tier }: { score: number; tier: string }) {
  const meta = EXPLOITABILITY_TIER_META[tier] ?? EXPLOITABILITY_TIER_META.moderate;
  const pips = [1, 2, 3, 4, 5];
  return (
    <div className={cn('rounded-xl border px-4 py-3 flex items-center gap-4', meta.bg, meta.border)}>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-0.5">
          Exploitability Index
        </p>
        <p className={cn('text-lg font-bold leading-tight', meta.color)}>
          {meta.label}
        </p>
        <p className="text-xs text-muted-foreground mt-0.5">
          Practical exploitation difficulty · not CVSS severity
        </p>
      </div>
      <div className="flex flex-col items-center gap-1.5 shrink-0">
        <span className={cn('text-3xl font-black tabular-nums', meta.color)}>{score.toFixed(1)}</span>
        <div className="flex gap-0.5">
          {pips.map(p => (
            <div
              key={p}
              className={cn(
                'h-1.5 w-5 rounded-full transition-colors',
                p <= meta.bar ? meta.color.replace('text-', 'bg-').replace(' dark:text-', ' dark:bg-') : 'bg-muted',
              )}
            />
          ))}
        </div>
        <span className="text-[9px] text-muted-foreground">out of 5</span>
      </div>
    </div>
  );
}

const ATTACK_PATH_META: Record<AttackPathClass, { label: string; icon: React.ReactNode; color: string; bg: string; border: string; tooltip: string }> = {
  exploit_public_facing:        { label: 'Direct Exploit',        icon: <Globe className="h-3 w-3" />,         color: 'text-red-700 dark:text-red-400',    bg: 'bg-red-50 dark:bg-red-950/40',    border: 'border-red-200 dark:border-red-800',    tooltip: 'T1190 — Attacker directly exploits an internet-facing service. No user interaction required; automatable.' },
  phishing_delivery:            { label: 'Phishing Delivery',     icon: <Mail className="h-3 w-3" />,          color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', tooltip: 'T1566 — Exploit is delivered via email or malicious link. Requires a victim to trigger.' },
  lateral_movement_required:    { label: 'Lateral Movement',      icon: <ArrowRightLeft className="h-3 w-3" />, color: 'text-purple-700 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-950/40', border: 'border-purple-200 dark:border-purple-800', tooltip: 'T1021/T1550 — Requires an existing foothold on another host. Attacker moves laterally to reach this asset.' },
  valid_credentials_required:   { label: 'Credential-Dependent',  icon: <Key className="h-3 w-3" />,           color: 'text-yellow-700 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-950/30', border: 'border-yellow-200 dark:border-yellow-800', tooltip: 'T1078 — Attack requires valid credentials. Risk depends heavily on credential hygiene and MFA posture.' },
  supply_chain:                 { label: 'Supply Chain',           icon: <Package className="h-3 w-3" />,       color: 'text-blue-700 dark:text-blue-400',   bg: 'bg-blue-50 dark:bg-blue-950/40',   border: 'border-blue-200 dark:border-blue-800',   tooltip: 'T1195 — Compromise via a malicious dependency, build system, or update mechanism.' },
  unknown:                      { label: 'Unknown Path',           icon: <HelpCircle className="h-3 w-3" />,    color: 'text-slate-600 dark:text-slate-400', bg: 'bg-slate-50 dark:bg-slate-900/40', border: 'border-slate-200 dark:border-slate-700', tooltip: 'Insufficient information to classify the initial access technique.' },
};

const LATERAL_MOVEMENT_META: Record<LateralMovementPotential, { label: string; color: string; bg: string; border: string; tooltip: string }> = {
  high:   { label: 'High Pivot Risk',    color: 'text-red-700 dark:text-red-400',    bg: 'bg-red-50 dark:bg-red-950/40',    border: 'border-red-200 dark:border-red-800',    tooltip: 'Exploitation enables wide lateral movement: credential theft, domain controller or secrets manager access, pivot gateway takeover.' },
  medium: { label: 'Medium Pivot Risk',  color: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40', border: 'border-orange-200 dark:border-orange-800', tooltip: 'Limited pivot capability: access to one adjacent segment or partial credential exposure.' },
  low:    { label: 'Low Pivot Risk',     color: 'text-slate-600 dark:text-slate-400', bg: 'bg-slate-50 dark:bg-slate-900/40', border: 'border-slate-200 dark:border-slate-700', tooltip: 'Isolated blast radius — no meaningful path to other hosts or credentials post-exploitation.' },
};

function AttackContextBadges({ attackPath, lateralMovement }: { attackPath?: AttackPathClass; lateralMovement?: LateralMovementPotential }) {
  if (!attackPath && !lateralMovement) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {attackPath && attackPath !== 'unknown' && (() => {
        const m = ATTACK_PATH_META[attackPath];
        return (
          <span title={m.tooltip} className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', m.bg, m.border, m.color)}>
            {m.icon}
            {m.label}
          </span>
        );
      })()}
      {lateralMovement && (() => {
        const m = LATERAL_MOVEMENT_META[lateralMovement];
        return (
          <span title={m.tooltip} className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium', m.bg, m.border, m.color)}>
            <MoveRight className="h-3 w-3" />
            {m.label}
          </span>
        );
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
        {brief.title && (
          <p className="text-base font-semibold text-foreground leading-snug pl-6">
            {brief.title}
          </p>
        )}
      </div>
      {/* Exploitability Index badge — top of panel, most scannable signal */}
      {brief.exploitability_score != null && brief.exploitability_tier && (
        <div className="mb-3">
          <ExploitabilityBadge score={brief.exploitability_score} tier={brief.exploitability_tier} />
        </div>
      )}
      <div className="space-y-2">
        {BRIEF_SECTIONS.map(({ key, label, icon, accent }) => {
          const value = brief[key as keyof AnalystBrief];
          if (!value) return null;
          return (
            <div key={key} className={cn('rounded-lg border p-3 space-y-1', accent)}>
              <p className="text-xs font-semibold flex items-center gap-1.5 text-foreground/80">
                {icon}
                {label}
              </p>
              <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">{value as string}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ─────────────────────────── Finding detail ────────────────────────────

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
                <span className="text-xs text-muted-foreground ml-auto">
                  OPES {f.opes.score.toFixed(1)} · {f.opes.evaluator_version}
                </span>
              </div>
              {/* Attack path + lateral movement — immediately below OPES priority */}
              <AttackContextBadges
                attackPath={f.attack_path_class}
                lateralMovement={f.lateral_movement_potential}
              />
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 pt-2">
            {/* Analyst Brief — shown first so an analyst understands the vuln before diving into scores */}
            {f.analyst_brief && f.analyst_brief.what_is_it && (
              <AnalystBriefPanel brief={f.analyst_brief} />
            )}

            {/* OPES Components */}
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
              {f.opes.dampener && (
                <p className="mt-2 text-xs text-yellow-400 flex items-center gap-1">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  {f.opes.dampener}
                </p>
              )}
              {f.opes.override && (
                <p className="mt-1 text-xs text-blue-400 font-medium">Override: {f.opes.override}</p>
              )}
              <ul className="mt-2 space-y-0.5">
                {f.opes.top_contributors?.map((c, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex gap-1">
                    <span className="text-primary">•</span> {c}
                  </li>
                ))}
              </ul>
            </section>

            {/* CVSS Reconciliation */}
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
                    <span className="font-medium text-yellow-400">{d.source}</span>
                    {' '}<code className="bg-muted px-1 rounded">{d.their_vector}</code>
                    <p className="text-muted-foreground mt-0.5">{d.disagreement}</p>
                  </div>
                ))}
              </div>
            </section>

            {/* Preconditions */}
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
                      <p className="text-xs mt-1 border-l-2 border-yellow-500 pl-2 text-yellow-400">
                        Verify: {e.precondition.verification_method}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </section>

            {/* Verification Tasks */}
            {f.verification_tasks && f.verification_tasks.length > 0 && (
              <section>
                <h4 className="text-sm font-semibold mb-2">Open Verification Tasks</h4>
                <div className="space-y-2">
                  {f.verification_tasks.map((t) => (
                    <div key={t.id} className="rounded-lg border p-3 text-xs space-y-1">
                      <p className="font-medium">{t.summary}</p>
                      {t.command && (
                        <code className="block bg-muted rounded px-2 py-1 font-mono">{t.command}</code>
                      )}
                      <p className="text-muted-foreground">Signal: {t.expected_signal_path}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Recommendation */}
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

// ─────────────────────────── Chat bubble ──────────────────────────────

function OracleMessage({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === 'user';
  return (
    <div className={cn('flex flex-col gap-1', isUser ? 'items-end' : 'items-start')}>
      <div className={cn(
        'rounded-xl px-4 py-2.5 max-w-[88%] text-sm',
        isUser ? 'bg-primary text-primary-foreground' : 'bg-muted border',
      )}>
        {msg.loading ? (
          <span className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Oracle is reasoning…
          </span>
        ) : (
          <>
            <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
            {msg.iterations !== undefined && (
              <p className="text-[10px] text-muted-foreground mt-1">
                {msg.iterations} iteration{msg.iterations !== 1 ? 's' : ''}
              </p>
            )}
          </>
        )}

        {/* ReAct execution trace */}
        {msg.trace && msg.trace.length > 0 && (
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground select-none">
              Reasoning trace ({msg.trace.length} steps)
            </summary>
            <div className="mt-2 space-y-2 border-l-2 border-muted pl-3">
              {msg.trace.map((step, i) => (
                <div key={i} className="space-y-0.5">
                  <p className="font-medium text-foreground/80">
                    <span className="text-muted-foreground">Step {step.iteration + 1} · </span>
                    {step.thought}
                  </p>
                  {step.tool_name && (
                    <p className="text-blue-400">
                      → <code>{step.tool_name}</code>
                      {step.tool_args && Object.keys(step.tool_args).length > 0 && (
                        <span className="text-muted-foreground ml-1">
                          ({Object.entries(step.tool_args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})
                        </span>
                      )}
                    </p>
                  )}
                  {step.observation && (
                    <pre className="text-[10px] bg-muted/50 rounded px-2 py-1 overflow-x-auto whitespace-pre-wrap max-h-[120px] overflow-y-auto">
                      {step.observation.slice(0, 800)}{step.observation.length > 800 ? '…' : ''}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </details>
        )}

        {/* Inline OPES summary card */}
        {msg.finding && (
          <div className="mt-3 rounded-lg border bg-card p-3 text-xs space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <CategoryBadge cat={msg.finding.opes.category} />
              <span className="font-medium">{msg.finding.opes.label}</span>
              <span className="text-muted-foreground">OPES {msg.finding.opes.score.toFixed(1)}</span>
              <ConfidenceBadge c={msg.finding.opes.confidence} />
            </div>
            {msg.finding.opes.dampener && (
              <p className="text-yellow-400 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                {msg.finding.opes.dampener}
              </p>
            )}
            {/* Condensed brief — title + exploitability inline before opening full dialog */}
            {msg.finding.analyst_brief?.title && (
              <p className="font-medium text-foreground/90 text-xs">
                {msg.finding.analyst_brief.title}
              </p>
            )}
            {msg.finding.analyst_brief?.exploitability_score != null && msg.finding.analyst_brief?.exploitability_tier && (() => {
              const meta = EXPLOITABILITY_TIER_META[msg.finding.analyst_brief.exploitability_tier!] ?? EXPLOITABILITY_TIER_META.moderate;
              return (
                <div className={cn('inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold border w-fit', meta.bg, meta.border, meta.color)}>
                  <span>{meta.label}</span>
                  <span className="font-black">{msg.finding.analyst_brief.exploitability_score!.toFixed(1)}/5</span>
                </div>
              );
            })()}
            {/* Attack path + lateral movement at a glance */}
            <AttackContextBadges
              attackPath={msg.finding.attack_path_class}
              lateralMovement={msg.finding.lateral_movement_potential}
            />
            {msg.finding.analyst_brief?.attack_vector_summary && (
              <p className="text-muted-foreground border-l-2 border-orange-500/40 pl-2 leading-relaxed">
                {msg.finding.analyst_brief.attack_vector_summary}
              </p>
            )}
            <FindingDetail f={msg.finding} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────── Findings table ────────────────────────────

function OpenFindingsTable({ findings, onSelect }: {
  findings: OracleFinding[];
  onSelect: (f: OracleFinding) => void;
}) {
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
                <TableCell colSpan={6} className="text-center text-muted-foreground py-10">
                  No open findings yet. Ask Oracle to analyze a CVE.
                </TableCell>
              </TableRow>
            )}
            {findings.map((f) => (
              <TableRow
                key={`${f.cve_id}-${f.asset_id}`}
                className="cursor-pointer hover:bg-muted/50"
                onClick={() => { setSelected(f); onSelect(f); }}
              >
                <TableCell className="font-mono text-xs">{f.cve_id}</TableCell>
                <TableCell className="text-xs text-muted-foreground max-w-[120px] truncate">{f.asset_id}</TableCell>
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <CategoryBadge cat={f.opes.category} />
                    <span className="text-xs font-medium">{f.opes.score.toFixed(1)}</span>
                  </div>
                </TableCell>
                <TableCell className="hidden md:table-cell text-xs">{f.opes.label}</TableCell>
                <TableCell className="hidden lg:table-cell">
                  <ConfidenceBadge c={f.opes.confidence} />
                </TableCell>
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
            <DialogHeader>
              <DialogTitle>{selected.cve_id} — {selected.asset_id}</DialogTitle>
            </DialogHeader>
            <FindingDetail f={selected} />
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}

// ─────────────────────────── CVE Lookup result ─────────────────────────
//
// Renders the response of GET /api/v1/oracle/cve/{id}. Layout mirrors the
// existing finding detail dialog but is scoped to "no asset, no OPES score
// yet" — Phase-A facts only. Helps an analyst quickly answer "what is this
// CVE and how worried should I be?" before scoping it to a specific asset.
function CveLookupResult({ data }: { data: { cve: any; analysis: any; exploitation: any; analysis_status?: string; analysis_error?: string } }) {
  const cve = data.cve ?? {};
  const a = data.analysis ?? {};
  const e = data.exploitation ?? {};
  const brief: AnalystBrief | undefined = a.analyst_brief;
  const tierMeta = brief?.exploitability_tier
    ? (EXPLOITABILITY_TIER_META[brief.exploitability_tier] ?? EXPLOITABILITY_TIER_META.moderate)
    : null;

  return (
    <div className="space-y-4">
      {/* Header line: CVE id + published date + CVSS */}
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
          {a.attack_path_class && (
            <Badge variant="outline" className="text-[10px]">
              {String(a.attack_path_class).replace(/_/g, ' ')}
            </Badge>
          )}
          {a.lateral_movement_potential && (
            <Badge variant="outline" className="text-[10px]">
              lateral: {a.lateral_movement_potential}
            </Badge>
          )}
          {cve.in_kev && (
            <Badge variant="destructive" className="text-[10px]">CISA KEV</Badge>
          )}
          {a.cvss_reconciliation?.correct_vector && (
            <code className="bg-muted px-1 py-0.5 rounded text-[10px]">{a.cvss_reconciliation.correct_vector}</code>
          )}
          {a.cvss_reconciliation?.correct_score != null && (
            <span className="font-semibold text-foreground">{Number(a.cvss_reconciliation.correct_score).toFixed(1)}</span>
          )}
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

      {/* Analyst brief sections */}
      {brief && brief.what_is_it && <AnalystBriefPanel brief={brief} />}

      {/* Exploitation evidence — keeps an analyst from re-asking "is this
          actually being exploited?" by surfacing the structured signals. */}
      {e && (e.in_kev_sources?.length || e.metasploit_available || e.vulncheck_reported_exploited || e.ransomware_associated || e.zero_day_confirmed) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Flame className="h-4 w-4 text-primary" /> Exploitation Evidence
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs space-y-1.5">
            {e.in_kev_sources?.map((src: string) => (
              <p key={src}><Badge variant="destructive" className="mr-2 text-[10px]">{src}</Badge>confirmed exploited</p>
            ))}
            {e.ransomware_associated && (
              <p><Badge variant="destructive" className="mr-2 text-[10px]">ransomware</Badge>used by ransomware operators</p>
            )}
            {e.zero_day_confirmed && (
              <p><Badge variant="destructive" className="mr-2 text-[10px]">0day</Badge>exploited before patch existed (GP0)</p>
            )}
            {e.vulncheck_reported_exploited && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">VulnCheck</Badge>reported in the wild</p>
            )}
            {e.vulncheck_weaponized && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">VulnCheck</Badge>validated weaponised exploit</p>
            )}
            {e.vulncheck_threat_actor_count > 0 && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">threat actors</Badge>linked to {e.vulncheck_threat_actor_count} group(s)</p>
            )}
            {e.metasploit_available && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">Metasploit</Badge>{e.metasploit_module_count > 1 ? `${e.metasploit_module_count} modules available` : 'module available (push-button)'}</p>
            )}
            {e.cisa_ssvc_decision && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">CISA SSVC</Badge>{e.cisa_ssvc_decision}</p>
            )}
            {e.recent_poc_days > 0 && e.recent_poc_days <= 30 && (
              <p><Badge variant="outline" className="mr-2 text-[10px]">PoC</Badge>public PoC within {e.recent_poc_days} days</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Preconditions — useful even without an asset because they tell an
          analyst what to check on a target system. */}
      {a.preconditions?.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" /> Preconditions
            </CardTitle>
            <CardDescription className="text-xs">
              Facts that must hold for exploitation. Verify each on the target before treating as exploitable.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {a.preconditions.map((p: any) => (
              <div key={p.id} className="rounded-lg border p-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-medium">{p.id}</span>
                  <Badge variant="outline" className="text-[9px]">{p.severity}</Badge>
                </div>
                <p className="text-xs text-muted-foreground">{p.description}</p>
                {p.verification_method && (
                  <p className="text-[11px] mt-1 border-l-2 border-yellow-500 pl-2 text-yellow-400">
                    Verify: {p.verification_method}
                  </p>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* CVSS reconciliation — only when sources disagreed */}
      {a.cvss_reconciliation?.disagreements?.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">CVSS Reconciliation</CardTitle>
            <CardDescription className="text-xs">{a.cvss_reconciliation.rationale}</CardDescription>
          </CardHeader>
          <CardContent className="text-xs space-y-1.5">
            {a.cvss_reconciliation.disagreements.map((d: any, i: number) => (
              <div key={i} className="border-l-2 border-yellow-500 pl-2">
                <span className="font-medium text-yellow-400">{d.source}</span>{' '}
                <code className="bg-muted px-1 rounded text-[10px]">{d.their_vector}</code>
                <p className="text-muted-foreground mt-0.5">{d.disagreement}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────── Main page ────────────────────────────────

export default function OraclePage() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'oracle',
      content: `I'm Aegis Oracle — I analyze CVEs and tell you whether they're actually exploitable on your assets.\n\nAsk me things like:\n• "Analyze CVE-2025-55130 on asset ftds-tenant-prod-7421"\n• "Is CVE-2024-3094 exploitable on my internet-facing assets?"\n• "What open P0 and P1 findings do we have?"\n• "Explain the preconditions for CVE-2025-12345"`,
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [findings, setFindings] = useState<OracleFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'chat' | 'lookup' | 'findings'>('lookup');
  const [filterCat, setFilterCat] = useState<string>('all');

  // CVE-only lookup state — Phase-A intel without an asset. Used for ad-hoc
  // "what is this CVE?" questions when a new CVE drops.
  const [cveLookupId, setCveLookupId] = useState('');
  const [cveLookup, setCveLookup] = useState<{
    cve: any;
    analysis: any;
    exploitation: any;
    analysis_status?: string;
    analysis_error?: string;
  } | null>(null);
  const [cveLookupLoading, setCveLookupLoading] = useState(false);
  const [cveLookupError, setCveLookupError] = useState<string | null>(null);
  // Status string shown while a lookup is in flight. Switches from the
  // generic "Fetching…" to "Ingesting on demand…" after 5s so the user
  // understands the longer wait when Oracle is pulling a fresh CVE.
  const [cveLookupStatus, setCveLookupStatus] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const loadFindings = useCallback(async () => {
    setFindingsLoading(true);
    try {
      const data = await api.oracleGetFindings();
      setFindings(data?.findings ?? []);
    } catch {
      // silently fail — Oracle might not be running yet
    } finally {
      setFindingsLoading(false);
    }
  }, []);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  const appendMessage = (msg: Omit<ChatMessage, 'id'>) =>
    ({ ...msg, id: crypto.randomUUID() } as ChatMessage);

  async function handleSend() {
    const q = input.trim();
    if (!q || loading) return;
    setInput('');

    const userMsg = appendMessage({ role: 'user', content: q });
    const placeholderId = crypto.randomUUID();
    const placeholder: ChatMessage = { id: placeholderId, role: 'oracle', content: '', loading: true };

    setMessages((prev) => [...prev, userMsg, placeholder]);
    setLoading(true);

    try {
      const resp = await api.oracleChat(q);
      const oracleMsg: ChatMessage = {
        id: placeholderId,
        role: 'oracle',
        content: resp.answer,
        finding: resp.finding ?? undefined,
        iterations: resp.iterations ?? undefined,
        trace: resp.trace ?? undefined,
      };
      setMessages((prev) => prev.map((m) => m.id === placeholderId ? oracleMsg : m));
      if (resp.finding) {
        setFindings((prev) => {
          const key = `${resp.finding.cve_id}|${resp.finding.asset_id}`;
          const filtered = prev.filter((f) => `${f.cve_id}|${f.asset_id}` !== key);
          return [resp.finding, ...filtered];
        });
      }
    } catch (err: any) {
      const errMsg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable. Make sure the aegis-oracle service is running.';
      setMessages((prev) => prev.map((m) =>
        m.id === placeholderId ? { ...m, loading: false, content: `Error: ${errMsg}` } : m
      ));
      toast({ variant: 'destructive', title: 'Oracle error', description: errMsg });
    } finally {
      setLoading(false);
    }
  }

  // Phase-A CVE lookup — no asset required. Calls /api/v1/oracle/cve/{id}
  // which hits the Oracle daemon's GET /cve/{id} (intrinsic analysis only).
  //
  // First lookup for a CVE we've never seen can take 30-60s while Oracle
  // fetches it from vulnx/NVD on-demand, persists it, then runs the
  // Phase A LLM call. The status string flips after ~5s so the user knows
  // the call hasn't hung.
  async function handleCveLookup() {
    const raw = cveLookupId.trim().toUpperCase();
    if (!raw) return;
    if (!/^CVE-\d{4}-\d{4,7}$/.test(raw)) {
      setCveLookupError('Please enter a CVE id in the form CVE-YYYY-NNNN.');
      return;
    }
    setCveLookupError(null);
    setCveLookupLoading(true);
    setCveLookupStatus('Fetching CVE intelligence…');
    const slowTimer = setTimeout(() => {
      setCveLookupStatus('Ingesting this CVE on demand (first lookup may take 30–60s)…');
    }, 5000);
    try {
      const data = await api.oracleCveLookup(raw);
      setCveLookup(data);
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? err?.message ?? 'Oracle is unavailable.';
      setCveLookupError(msg);
      setCveLookup(null);
      toast({ variant: 'destructive', title: 'CVE lookup failed', description: msg });
    } finally {
      clearTimeout(slowTimer);
      setCveLookupStatus(null);
      setCveLookupLoading(false);
    }
  }

  const filteredFindings = findings.filter(
    (f) => filterCat === 'all' || f.opes.category === filterCat
  );

  const countByCategory = (cat: string) => findings.filter((f) => f.opes.category === cat).length;

  return (
    <MainLayout>
      <div className="flex flex-col h-full">
        <Header
          title="Aegis Oracle"
          subtitle="Practical exploitability scoring - ask about any CVE or asset"
        />

        <div className="flex-1 overflow-auto p-6 space-y-6">

          {/* Summary strip */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {(['P0','P1','P2','P3','P4'] as const).map((cat) => (
              <button
                key={cat}
                onClick={() => { setActiveTab('findings'); setFilterCat(cat); }}
                className={cn(
                  'rounded-lg border p-3 text-center hover:bg-muted/50 transition-colors',
                  filterCat === cat && 'ring-2 ring-primary'
                )}
              >
                <CategoryBadge cat={cat} />
                <div className="mt-1 text-2xl font-bold">{countByCategory(cat)}</div>
              </button>
            ))}
          </div>

          {/* Tab switcher */}
          <div className="flex gap-2">
            <Button
              variant={activeTab === 'lookup' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveTab('lookup')}
              className="gap-1.5"
            >
              <Search className="h-4 w-4" /> Quick CVE Lookup
            </Button>
            <Button
              variant={activeTab === 'chat' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveTab('chat')}
              className="gap-1.5"
            >
              <BookOpen className="h-4 w-4" /> Chat
            </Button>
            <Button
              variant={activeTab === 'findings' ? 'default' : 'outline'}
              size="sm"
              onClick={() => { setActiveTab('findings'); setFilterCat('all'); loadFindings(); }}
              className="gap-1.5"
            >
              <ShieldAlert className="h-4 w-4" /> Open Findings
              {findings.length > 0 && (
                <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">{findings.length}</Badge>
              )}
            </Button>
            <Button variant="ghost" size="sm" onClick={loadFindings} disabled={findingsLoading} className="ml-auto">
              <RefreshCw className={cn('h-4 w-4', findingsLoading && 'animate-spin')} />
            </Button>
          </div>

          {/* Quick CVE Lookup panel — Phase-A intel without an asset, for
              "what is this CVE?" questions when a new advisory drops. */}
          {activeTab === 'lookup' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Search className="h-4 w-4 text-primary" />
                  Quick CVE Lookup
                </CardTitle>
                <CardDescription>
                  Paste any CVE id to get Oracle&apos;s analyst brief, attack path, and
                  exploitation evidence — no asset required. Use this for ad-hoc
                  prioritisation when a new advisory drops.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="CVE-2026-0300"
                    value={cveLookupId}
                    onChange={(e) => setCveLookupId(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') { e.preventDefault(); handleCveLookup(); }
                    }}
                    disabled={cveLookupLoading}
                    className="font-mono"
                  />
                  <Button
                    onClick={handleCveLookup}
                    disabled={cveLookupLoading || !cveLookupId.trim()}
                    className="shrink-0"
                  >
                    {cveLookupLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    <span className="ml-1.5">Analyze</span>
                  </Button>
                </div>

                {cveLookupError && (
                  <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-400 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                    <div>
                      <p className="font-medium">Lookup failed</p>
                      <p className="text-xs opacity-90">{cveLookupError}</p>
                    </div>
                  </div>
                )}

                {cveLookupLoading && cveLookupStatus && (
                  <div className="rounded-lg border bg-muted/30 p-3 text-sm flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin shrink-0" />
                    <p className="text-muted-foreground">{cveLookupStatus}</p>
                  </div>
                )}

                {cveLookup && <CveLookupResult data={cveLookup} />}

                {!cveLookup && !cveLookupError && !cveLookupLoading && (
                  <div className="rounded-lg border bg-muted/30 p-4 text-xs text-muted-foreground space-y-1.5">
                    <p className="font-medium text-foreground">What you&apos;ll get back:</p>
                    <ul className="list-disc list-inside space-y-0.5">
                      <li><span className="text-foreground">Analyst brief</span> — what the bug is, how it&apos;s exploited, who&apos;s affected, who isn&apos;t</li>
                      <li><span className="text-foreground">Attack path classification</span> — direct internet exposure, phishing, lateral movement, etc.</li>
                      <li><span className="text-foreground">Real-world likelihood</span> — KEV listing, weaponised exploits, threat-actor links</li>
                      <li><span className="text-foreground">Preconditions</span> — facts the LLM extracted that must hold for exploitation to succeed</li>
                      <li><span className="text-foreground">CVSS reconciliation</span> — Oracle&apos;s adjudicated CVSS when sources disagree (NVD vs vendor vs ADP)</li>
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Chat panel */}
          {activeTab === 'chat' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Flame className="h-4 w-4 text-primary" />
                  Oracle Chat
                </CardTitle>
                <CardDescription>
                  Ask Oracle to analyze a CVE + asset pair, explain a finding, or list your open risks.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-lg border bg-muted/30 min-h-[360px] max-h-[55vh] overflow-y-auto p-4 space-y-3">
                  {messages.map((m) => <OracleMessage key={m.id} msg={m} />)}
                  <div ref={messagesEndRef} />
                </div>

                <div className="flex gap-2">
                  <Textarea
                    placeholder='e.g. "Analyze CVE-2025-55130 on asset ftds-tenant-prod-7421" or "List P0 findings"'
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
                    }}
                    rows={2}
                    className="resize-none"
                    disabled={loading}
                  />
                  <Button
                    onClick={handleSend}
                    disabled={loading || !input.trim()}
                    size="icon"
                    className="shrink-0 h-auto py-3"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  </Button>
                </div>

                {/* Quick prompts */}
                <div className="flex flex-wrap gap-2">
                  {[
                    'List all P0 and P1 findings',
                    'What CVEs are in KEV?',
                    'Show me unverified blocker preconditions',
                  ].map((p) => (
                    <button
                      key={p}
                      onClick={() => setInput(p)}
                      className="text-xs border rounded-full px-3 py-1 text-muted-foreground hover:text-foreground hover:border-foreground transition-colors"
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Findings table panel */}
          {activeTab === 'findings' && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <CardTitle className="text-base flex items-center gap-2">
                    <TrendingUp className="h-4 w-4 text-primary" />
                    Open Findings
                  </CardTitle>
                  <div className="flex gap-2 flex-wrap">
                    {['all','P0','P1','P2','P3','P4'].map((c) => (
                      <Button
                        key={c}
                        size="sm"
                        variant={filterCat === c ? 'default' : 'outline'}
                        onClick={() => setFilterCat(c)}
                        className="h-7 px-2.5 text-xs"
                      >
                        {c === 'all' ? 'All' : <><CategoryBadge cat={c} /><span className="ml-1">{countByCategory(c)}</span></>}
                      </Button>
                    ))}
                  </div>
                </div>
                <CardDescription>
                  Click a row to view full analysis. Sorted by OPES score descending.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <OpenFindingsTable
                  findings={filteredFindings.sort((a, b) => b.opes.score - a.opes.score)}
                  onSelect={() => {}}
                />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </MainLayout>
  );
}
