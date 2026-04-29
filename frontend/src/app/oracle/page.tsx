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
  XCircle, AlertTriangle, Flame, TrendingUp, RefreshCw, ChevronDown,
  ChevronUp, BookOpen,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

// ─────────────────────────── Types ──────────────────────────────────────

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

interface OracleFinding {
  cve_id: string;
  asset_id: string;
  evaluated_at: string;
  opes: OPESScore;
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

interface ChatMessage {
  id: string;
  role: 'user' | 'oracle';
  content: string;
  finding?: OracleFinding;
  loading?: boolean;
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
            <DialogDescription className="flex items-center gap-2 flex-wrap">
              <CategoryBadge cat={f.opes.category} />
              <span className="text-sm">{f.opes.label}</span>
              <ConfidenceBadge c={f.opes.confidence} />
              <span className="text-xs text-muted-foreground ml-auto">
                OPES {f.opes.score.toFixed(1)} · {f.opes.evaluator_version}
              </span>
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 pt-2">
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
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Oracle is analyzing…
          </span>
        ) : (
          <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
        )}

        {/* Inline OPES summary card */}
        {msg.finding && (
          <div className="mt-3 rounded-lg border bg-card p-3 text-xs space-y-1">
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
  const [activeTab, setActiveTab] = useState<'chat' | 'findings'>('chat');
  const [filterCat, setFilterCat] = useState<string>('all');
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

  const filteredFindings = findings.filter(
    (f) => filterCat === 'all' || f.opes.category === filterCat
  );

  const countByCategory = (cat: string) => findings.filter((f) => f.opes.category === cat).length;

  return (
    <MainLayout>
      <div className="flex flex-col h-full">
        <Header
          title="Aegis Oracle"
          description="Practical exploitability scoring — ask about any CVE or asset"
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
