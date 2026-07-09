'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Plug,
  Trash2,
  RefreshCw,
  ExternalLink,
  AlertCircle,
  Settings2,
  Plus,
  X,
  ArrowRight,
  Zap,
  ArrowLeftRight,
} from 'lucide-react';
import { api, getApiErrorMessage, type JiraIntegration } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

interface JiraFormState {
  hostname: string;
  email: string;
  api_token: string;
  default_project_key: string;
  default_issue_type: string;
  auto_create_enabled: boolean;
  auto_create_min_severity: string;
  open_to_close_transitions: string[];
  close_to_open_transitions: string[];
}

const defaultForm: JiraFormState = {
  hostname: '',
  email: '',
  api_token: '',
  default_project_key: '',
  default_issue_type: 'Bug',
  auto_create_enabled: false,
  auto_create_min_severity: 'high',
  open_to_close_transitions: [],
  close_to_open_transitions: [],
};

function TransitionListEditor({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const [input, setInput] = useState('');
  const add = () => {
    const trimmed = input.trim();
    if (trimmed && !value.includes(trimmed)) {
      onChange([...value, trimmed]);
    }
    setInput('');
  };
  const remove = (i: number) => onChange(value.filter((_, idx) => idx !== i));

  return (
    <div className="space-y-2">
      <label className="text-sm font-medium">{label}</label>
      <p className="text-xs text-muted-foreground">{hint}</p>
      <div className="space-y-1">
        {value.map((t, i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            {i > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
            {i === 0 && <span className="w-3 h-3 shrink-0" />}
            <span className="flex-1 bg-muted/50 rounded px-2 py-0.5 font-mono text-xs">{t}</span>
            <button onClick={() => remove(i)} className="text-muted-foreground hover:text-foreground">
              <X className="h-3 w-3" />
            </button>
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <Input
          placeholder="Transition name, e.g. In Progress"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          className="text-sm h-8"
        />
        <Button size="sm" variant="outline" onClick={add} className="h-8 shrink-0">
          <Plus className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

export default function IntegrationsPage() {
  const { toast } = useToast();
  const [integration, setIntegration] = useState<JiraIntegration | null>(null);
  const [loadingIntegration, setLoadingIntegration] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [form, setForm] = useState<JiraFormState>(defaultForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string; display_name?: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [activeTab, setActiveTab] = useState<'auth' | 'auto' | 'transitions'>('auth');

  useEffect(() => { loadIntegration(); }, []);

  async function loadIntegration() {
    setLoadingIntegration(true);
    try {
      const data = await api.getJiraIntegration();
      setIntegration(data);
    } catch {
      setIntegration(null);
    } finally {
      setLoadingIntegration(false);
    }
  }

  function openSetup() {
    if (integration) {
      setForm({
        hostname: integration.hostname,
        email: integration.email,
        api_token: '',
        default_project_key: integration.default_project_key || '',
        default_issue_type: integration.default_issue_type || 'Bug',
        auto_create_enabled: integration.auto_create_enabled,
        auto_create_min_severity: integration.auto_create_min_severity || 'high',
        open_to_close_transitions: integration.open_to_close_transitions || [],
        close_to_open_transitions: integration.close_to_open_transitions || [],
      });
    } else {
      setForm(defaultForm);
    }
    setTestResult(null);
    setActiveTab('auth');
    setSetupOpen(true);
  }

  async function handleTest() {
    if (!integration) { toast({ title: 'Save the integration first to test it.', variant: 'destructive' }); return; }
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.testJiraConnection();
      setTestResult(result);
      await loadIntegration();
    } catch (err) {
      setTestResult({ ok: false, message: getApiErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!form.hostname || !form.email) { toast({ title: 'Hostname and email are required.', variant: 'destructive' }); return; }
    if (!integration && !form.api_token) { toast({ title: 'API token is required when creating the integration.', variant: 'destructive' }); return; }
    setSaving(true);
    try {
      const payload = {
        hostname: form.hostname,
        email: form.email,
        ...(form.api_token ? { api_token: form.api_token } : {}),
        default_project_key: form.default_project_key || undefined,
        default_issue_type: form.default_issue_type || 'Bug',
        auto_create_enabled: form.auto_create_enabled,
        auto_create_min_severity: form.auto_create_min_severity,
        open_to_close_transitions: form.open_to_close_transitions,
        close_to_open_transitions: form.close_to_open_transitions,
      };
      if (integration) {
        await api.updateJiraIntegration(payload);
        toast({ title: 'Jira integration updated.' });
      } else {
        await api.createJiraIntegration({ ...payload, api_token: form.api_token });
        toast({ title: 'Jira integration configured.' });
      }
      setSetupOpen(false);
      await loadIntegration();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await api.deleteJiraIntegration();
      setIntegration(null);
      setDeleteOpen(false);
      toast({ title: 'Jira integration removed.' });
    } catch (err) {
      toast({ title: 'Failed to remove', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setDeleting(false);
    }
  }

  const tabBtn = (id: typeof activeTab, label: string) => (
    <button
      onClick={() => setActiveTab(id)}
      className={cn(
        'px-3 py-1.5 text-sm rounded-md transition-colors',
        activeTab === id
          ? 'bg-primary/15 text-primary border border-primary/25'
          : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
      )}
    >
      {label}
    </button>
  );

  return (
    <MainLayout>
      <Header title="Integrations" subtitle="Connect ASM to third-party platforms to push findings and automate workflows." />
      <div className="p-6 space-y-6">

        {/* Jira Integration Card */}
        <Card className="border border-border">
          <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
            <div className="w-10 h-10 rounded-lg bg-[#0052CC] flex items-center justify-center shrink-0">
              <svg viewBox="0 0 24 24" fill="white" className="w-6 h-6">
                <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <CardTitle className="text-base">Atlassian Jira</CardTitle>
              <CardDescription className="text-sm">
                Push vulnerability findings to Jira, sync status bidirectionally, and auto-create tickets on discovery.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {loadingIntegration ? (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              ) : integration ? (
                <Badge variant="outline" className={cn(
                  integration.is_active && integration.last_test_ok !== false
                    ? 'bg-green-500/10 text-green-400 border-green-500/30'
                    : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
                )}>
                  {integration.is_active && integration.last_test_ok !== false
                    ? <><CheckCircle2 className="h-3 w-3 mr-1" />Connected</>
                    : <><AlertCircle className="h-3 w-3 mr-1" />Check config</>}
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
              )}
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            {integration ? (
              <>
                {/* Summary grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Hostname</p>
                    <p className="font-mono text-xs">{integration.hostname}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auth email</p>
                    <p className="text-xs">{integration.email}</p>
                  </div>
                  {integration.default_project_key && (
                    <div>
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Default project</p>
                      <p className="font-mono text-xs">{integration.default_project_key}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auto-create</p>
                    <p className="text-xs">
                      {integration.auto_create_enabled
                        ? <span className="text-green-400">Enabled — {integration.auto_create_min_severity?.toUpperCase()}+</span>
                        : <span className="text-muted-foreground">Disabled</span>}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Status sync</p>
                    <p className="text-xs">
                      {(integration.open_to_close_transitions?.length || 0) > 0
                        ? <span className="text-green-400">
                            {integration.open_to_close_transitions.length} close + {integration.close_to_open_transitions.length} reopen transitions
                          </span>
                        : <span className="text-muted-foreground">Not configured</span>}
                    </p>
                  </div>
                </div>

                {integration.last_tested_at && (
                  <p className="text-xs text-muted-foreground">
                    Last tested: {new Date(integration.last_tested_at).toLocaleString()}{' '}
                    {integration.last_test_ok === true && <span className="text-green-400">— OK</span>}
                    {integration.last_test_ok === false && <span className="text-red-400">— Failed</span>}
                  </p>
                )}

                {testResult && (
                  <div className={cn(
                    'flex items-start gap-2 rounded-lg border p-3 text-sm',
                    testResult.ok ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300',
                  )}>
                    {testResult.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 shrink-0" />}
                    <span>{testResult.message}{testResult.display_name && ` (${testResult.display_name})`}</span>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
                    {testing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                    Test connection
                  </Button>
                  <Button size="sm" variant="outline" onClick={openSetup}>
                    <Settings2 className="h-4 w-4 mr-2" />Edit
                  </Button>
                  <a href={`https://${integration.hostname.replace(/^https?:\/\//, '')}`} target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="outline">
                      <ExternalLink className="h-4 w-4 mr-2" />Open Jira
                    </Button>
                  </a>
                  <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteOpen(true)}>
                    <Trash2 className="h-4 w-4 mr-2" />Remove
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                <p className="text-sm text-muted-foreground flex-1">
                  Connect your Jira workspace to create tickets, sync statuses, and auto-create issues from findings.
                </p>
                <Button onClick={openSetup}>
                  <Plug className="h-4 w-4 mr-2" />Set up Jira
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Placeholder integrations */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { name: 'Slack', desc: 'Send alerts to Slack channels on new critical findings.' },
            { name: 'PagerDuty', desc: 'Page on-call when P0/P1 findings are detected.' },
            { name: 'ServiceNow', desc: 'Sync ASM findings into your CMDB and incident workflows.' },
          ].map((item) => (
            <Card key={item.name} className="border border-border opacity-50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">{item.name}</CardTitle>
                <CardDescription className="text-xs">{item.desc}</CardDescription>
              </CardHeader>
              <CardContent>
                <Badge variant="outline" className="text-xs text-muted-foreground">Coming soon</Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Setup / Edit Dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#0052CC] flex items-center justify-center">
                <svg viewBox="0 0 24 24" fill="white" className="w-4 h-4">
                  <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
                </svg>
              </div>
              {integration ? 'Edit Jira Integration' : 'Connect Jira'}
            </DialogTitle>
            <DialogDescription>
              Configure authentication, auto-create behavior, and bidirectional status sync.
            </DialogDescription>
          </DialogHeader>

          {/* Tab navigation */}
          <div className="flex gap-1 border-b border-border pb-2">
            {tabBtn('auth', '1. Authentication')}
            {tabBtn('auto', '2. Auto-create')}
            {tabBtn('transitions', '3. Status Sync')}
          </div>

          <div className="space-y-4 py-2 min-h-[280px]">

            {/* ── Auth tab ── */}
            {activeTab === 'auth' && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Hostname</label>
                  <Input placeholder="myorg.atlassian.net" value={form.hostname} onChange={(e) => setForm(f => ({ ...f, hostname: e.target.value }))} />
                  <p className="text-xs text-muted-foreground">Your Jira Cloud instance URL (without https://)</p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">Email</label>
                  <Input type="email" placeholder="admin@yourcompany.com" value={form.email} onChange={(e) => setForm(f => ({ ...f, email: e.target.value }))} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">
                    API Token{integration && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
                  </label>
                  <Input type="password" placeholder={integration ? '••••••••••••' : 'Paste your API token'} value={form.api_token} onChange={(e) => setForm(f => ({ ...f, api_token: e.target.value }))} />
                  <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                    Create API token <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Default project key</label>
                    <Input placeholder="e.g. SEC" value={form.default_project_key} onChange={(e) => setForm(f => ({ ...f, default_project_key: e.target.value.toUpperCase() }))} />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Default issue type</label>
                    <Select value={form.default_issue_type} onValueChange={(v) => setForm(f => ({ ...f, default_issue_type: v }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {['Bug', 'Task', 'Story', 'Epic', 'Vulnerability', 'Security'].map(t => (
                          <SelectItem key={t} value={t}>{t}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
            )}

            {/* ── Auto-create tab ── */}
            {activeTab === 'auto' && (
              <div className="space-y-5">
                <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                  <Checkbox
                    id="auto-create"
                    checked={form.auto_create_enabled}
                    onCheckedChange={(v) => setForm(f => ({ ...f, auto_create_enabled: !!v }))}
                    className="mt-0.5 shrink-0"
                  />
                  <div>
                    <label htmlFor="auto-create" className="text-sm font-medium cursor-pointer flex items-center gap-2">
                      <Zap className="h-4 w-4 text-yellow-400" />
                      Auto-create Jira tickets on discovery
                    </label>
                    <p className="text-xs text-muted-foreground mt-1">
                      When a new vulnerability is detected at or above the minimum severity, a Jira ticket is automatically created using the default project and issue type above.
                    </p>
                  </div>
                </div>

                {form.auto_create_enabled && (
                  <div className="space-y-1.5">
                    <label className="text-sm font-medium">Minimum severity threshold</label>
                    <Select value={form.auto_create_min_severity} onValueChange={(v) => setForm(f => ({ ...f, auto_create_min_severity: v }))}>
                      <SelectTrigger className="w-48">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITIES.map(s => (
                          <SelectItem key={s} value={s}>
                            <span className={cn(
                              'capitalize font-medium',
                              s === 'critical' ? 'text-red-400' :
                              s === 'high' ? 'text-orange-400' :
                              s === 'medium' ? 'text-yellow-400' :
                              s === 'low' ? 'text-blue-400' : 'text-muted-foreground'
                            )}>{s.toUpperCase()} and above</span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      Requires a default project key to be set on the Authentication tab.
                    </p>
                  </div>
                )}

                {!form.auto_create_enabled && (
                  <p className="text-sm text-muted-foreground">
                    When disabled, tickets must be created manually from the Findings page.
                  </p>
                )}
              </div>
            )}

            {/* ── Transitions tab ── */}
            {activeTab === 'transitions' && (
              <div className="space-y-6">
                <div className="rounded-lg border border-border bg-muted/20 p-3 text-xs text-muted-foreground space-y-1">
                  <p className="flex items-center gap-2 text-foreground font-medium text-sm">
                    <ArrowLeftRight className="h-4 w-4" />
                    Bidirectional Status Sync
                  </p>
                  <p>When a vulnerability status changes in ASM, linked Jira tickets are automatically transitioned through your configured workflow sequences. Enter the <strong>exact transition names</strong> as they appear in your Jira project settings.</p>
                </div>

                <TransitionListEditor
                  label="Open → Close transitions"
                  hint="Executed when a finding is marked Resolved, Accepted, Mitigated, or False Positive. Example: In Progress → Done"
                  value={form.open_to_close_transitions}
                  onChange={(v) => setForm(f => ({ ...f, open_to_close_transitions: v }))}
                />

                <TransitionListEditor
                  label="Close → Open transitions"
                  hint="Executed when a resolved finding is reopened or redetected. Example: Reopen Issue"
                  value={form.close_to_open_transitions}
                  onChange={(v) => setForm(f => ({ ...f, close_to_open_transitions: v }))}
                />

                <div className="rounded-lg border border-border p-3 text-xs text-muted-foreground space-y-1">
                  <p className="font-medium text-foreground">Tip: finding your transition names</p>
                  <p>In Jira, go to <strong>Project settings → Workflows</strong> and click on your workflow to see all available transitions and their names.</p>
                  <p>After you connect an integration and have an active ticket, you can also click "Jira" on a finding and look at the available transitions displayed there.</p>
                </div>
              </div>
            )}
          </div>

          <DialogFooter className="gap-2 pt-2 border-t border-border">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {integration ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={deleteOpen} onOpenChange={(v) => { if (!deleting) setDeleteOpen(v); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove Jira integration
            </DialogTitle>
            <DialogDescription>
              This removes the stored credentials and disables all Jira features. Existing tickets in Jira will not be affected.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={deleting}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
