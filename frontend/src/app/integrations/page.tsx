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
  Radar,
  Download,
  RotateCw,
} from 'lucide-react';
import { api, getApiErrorMessage, type JiraIntegration, type CensysIntegration } from '@/lib/api';
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

interface CensysFormState {
  workspace_name: string;
  api_key: string;
  import_vulnerabilities: boolean;
  import_assets: boolean;
  continuous_sync_enabled: boolean;
  sync_interval_minutes: number;
}

const defaultCensysForm: CensysFormState = {
  workspace_name: '',
  api_key: '',
  import_vulnerabilities: true,
  import_assets: true,
  continuous_sync_enabled: false,
  sync_interval_minutes: 360,
};

const CENSYS_SYNC_INTERVALS: { value: number; label: string }[] = [
  { value: 60, label: 'Every hour' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours' },
];

function formatCensysInterval(minutes: number): string {
  const match = CENSYS_SYNC_INTERVALS.find(i => i.value === minutes);
  if (match) return match.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} min`;
}

function CensysSection() {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<CensysIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [setupOpen, setSetupOpen] = useState(false);
  const [editing, setEditing] = useState<CensysIntegration | null>(null);
  const [form, setForm] = useState<CensysFormState>(defaultCensysForm);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CensysIntegration | null>(null);

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      setIntegrations(await api.getCensysIntegrations());
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditing(null);
    setForm(defaultCensysForm);
    setSetupOpen(true);
  }

  function openEdit(integration: CensysIntegration) {
    setEditing(integration);
    setForm({
      workspace_name: integration.workspace_name,
      api_key: '',
      import_vulnerabilities: integration.import_vulnerabilities,
      import_assets: integration.import_assets,
      continuous_sync_enabled: integration.continuous_sync_enabled,
      sync_interval_minutes: integration.sync_interval_minutes,
    });
    setSetupOpen(true);
  }

  async function handleSave() {
    if (!form.workspace_name.trim()) {
      toast({ title: 'Workspace name is required.', variant: 'destructive' });
      return;
    }
    if (!editing && !form.api_key.trim()) {
      toast({ title: 'API key is required when adding a connection.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateCensysIntegration(editing.id, {
          workspace_name: form.workspace_name,
          ...(form.api_key ? { api_key: form.api_key } : {}),
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Censys ASM connection updated.' });
      } else {
        await api.createCensysIntegration({
          workspace_name: form.workspace_name,
          api_key: form.api_key,
          import_vulnerabilities: form.import_vulnerabilities,
          import_assets: form.import_assets,
          continuous_sync_enabled: form.continuous_sync_enabled,
          sync_interval_minutes: form.sync_interval_minutes,
        });
        toast({ title: 'Censys ASM connection added.' });
      }
      setSetupOpen(false);
      await load();
    } catch (err) {
      toast({ title: 'Failed to save', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(integration: CensysIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.testCensysConnection(integration.id);
      toast({
        title: result.ok ? 'Connection OK' : 'Connection failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleSync(integration: CensysIntegration) {
    setBusyId(integration.id);
    try {
      const result = await api.syncCensysIntegration(integration.id);
      toast({
        title: result.ok ? 'Sync complete' : 'Sync failed',
        description: result.message,
        variant: result.ok ? undefined : 'destructive',
      });
      await load();
    } catch (err) {
      toast({ title: 'Sync failed', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await api.deleteCensysIntegration(deleteTarget.id);
      setDeleteTarget(null);
      toast({ title: 'Censys ASM connection removed.' });
      await load();
    } catch (err) {
      toast({ title: 'Failed to remove', description: getApiErrorMessage(err), variant: 'destructive' });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card className="border border-border">
      <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
        <div className="w-10 h-10 rounded-lg bg-[#0A1F44] flex items-center justify-center shrink-0">
          <Radar className="w-5 h-5 text-[#4A90E2]" />
        </div>
        <div className="flex-1 min-w-0">
          <CardTitle className="text-base">Censys ASM</CardTitle>
          <CardDescription className="text-sm">
            Import risks and assets that Censys Attack Surface Management has attributed to your organization. Read-only.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : integrations.length > 0 ? (
            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
              <CheckCircle2 className="h-3 w-3 mr-1" />
              {integrations.length} workspace{integrations.length > 1 ? 's' : ''}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {integrations.length > 0 ? (
          <div className="space-y-3">
            {integrations.map((c) => (
              <div key={c.id} className="rounded-lg border border-border p-3 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm truncate">{c.workspace_name}</p>
                      {!c.is_active && <Badge variant="outline" className="text-muted-foreground text-xs">Disabled</Badge>}
                      {c.last_test_ok === false && (
                        <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />Auth issue
                        </Badge>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-xs text-muted-foreground">
                      <span>Import: {[c.import_assets && 'Assets', c.import_vulnerabilities && 'Vulnerabilities'].filter(Boolean).join(' + ') || 'Nothing'}</span>
                      {c.continuous_sync_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400">
                          <RotateCw className="h-3 w-3" />
                          Auto-sync {formatCensysInterval(c.sync_interval_minutes).toLowerCase()}
                        </span>
                      ) : (
                        <span>Auto-sync off</span>
                      )}
                      {c.last_sync_at && (
                        <span>
                          Last sync: {new Date(c.last_sync_at).toLocaleString()}
                          {c.last_sync_ok === true && <span className="text-green-400"> — OK</span>}
                          {c.last_sync_ok === false && <span className="text-red-400"> — Failed</span>}
                        </span>
                      )}
                      {c.continuous_sync_enabled && c.next_sync_at && (
                        <span>Next: {new Date(c.next_sync_at).toLocaleString()}</span>
                      )}
                    </div>
                    {c.last_sync_ok && c.last_sync_stats && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {c.last_sync_stats.assets_created ?? 0} new assets, {c.last_sync_stats.vulns_created ?? 0} new risks imported.
                      </p>
                    )}
                    {c.last_sync_ok === false && c.last_error && (
                      <p className="text-xs text-red-400 mt-1 truncate">{c.last_error}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={() => handleSync(c)} disabled={busyId === c.id || !c.is_active}>
                    {busyId === c.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Download className="h-4 w-4 mr-2" />}
                    Sync now
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => handleTest(c)} disabled={busyId === c.id}>
                    <RefreshCw className="h-4 w-4 mr-2" />Test
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openEdit(c)}>
                    <Settings2 className="h-4 w-4 mr-2" />Edit
                  </Button>
                  <Button size="sm" variant="outline" className="border-red-600/30 hover:bg-red-600/20 text-red-400" onClick={() => setDeleteTarget(c)}>
                    <Trash2 className="h-4 w-4 mr-2" />Remove
                  </Button>
                </div>
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-2" />Add another workspace
            </Button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <p className="text-sm text-muted-foreground flex-1">
              Connect a Censys ASM workspace to ingest its discovered risks and assets into your attack surface.
            </p>
            <Button onClick={openCreate}>
              <Plug className="h-4 w-4 mr-2" />Connect Censys ASM
            </Button>
          </div>
        )}
      </CardContent>

      {/* Setup / Edit Dialog */}
      <Dialog open={setupOpen} onOpenChange={(v) => { if (!saving) setSetupOpen(v); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5 text-[#4A90E2]" />
              {editing ? 'Edit Censys ASM connection' : 'Connect Censys ASM'}
            </DialogTitle>
            <DialogDescription>
              Each connection maps to one Censys ASM workspace. Generate a workspace-scoped API key from the Censys ASM Integrations page.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Workspace name</label>
              <Input
                placeholder="e.g. Production"
                value={form.workspace_name}
                onChange={(e) => setForm(f => ({ ...f, workspace_name: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">A label to identify this connection.</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                ASM API Key{editing && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
              </label>
              <Input
                type="password"
                placeholder={editing ? '••••••••••••' : 'Paste your workspace API key'}
                value={form.api_key}
                onChange={(e) => setForm(f => ({ ...f, api_key: e.target.value }))}
              />
              <a href="https://app.censys.io/integrations" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
                Get your ASM API key <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">What to import</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-assets"
                  checked={form.import_assets}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_assets: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-assets" className="text-sm cursor-pointer">
                  <span className="font-medium">Import assets</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Hosts, domains, subdomains, and certificates Censys attributes to you.</p>
                </label>
              </div>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-vulns"
                  checked={form.import_vulnerabilities}
                  onCheckedChange={(v) => setForm(f => ({ ...f, import_vulnerabilities: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-vulns" className="text-sm cursor-pointer">
                  <span className="font-medium">Import vulnerabilities</span>
                  <p className="text-xs text-muted-foreground mt-0.5">Risks identified by Censys ASM, imported as findings.</p>
                </label>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Continuous sync</label>
              <div className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Checkbox
                  id="censys-continuous"
                  checked={form.continuous_sync_enabled}
                  onCheckedChange={(v) => setForm(f => ({ ...f, continuous_sync_enabled: !!v }))}
                  className="mt-0.5 shrink-0"
                />
                <label htmlFor="censys-continuous" className="text-sm cursor-pointer">
                  <span className="font-medium flex items-center gap-2">
                    <RotateCw className="h-4 w-4 text-green-400" />
                    Automatically re-sync on a schedule
                  </span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Keeps your inventory current by pulling new Censys risks and assets in the background.
                  </p>
                </label>
              </div>
              {form.continuous_sync_enabled && (
                <div className="space-y-1.5 pl-1">
                  <label className="text-sm font-medium">Sync frequency</label>
                  <Select
                    value={String(form.sync_interval_minutes)}
                    onValueChange={(v) => setForm(f => ({ ...f, sync_interval_minutes: Number(v) }))}
                  >
                    <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {CENSYS_SYNC_INTERVALS.map(i => (
                        <SelectItem key={i.value} value={String(i.value)}>{i.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
          </div>

          <DialogFooter className="gap-2 pt-2 border-t border-border">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {editing ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(v) => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />Remove connection
            </DialogTitle>
            <DialogDescription>
              This removes the stored API key for <strong>{deleteTarget?.workspace_name}</strong>. Assets and findings already imported are kept.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={busyId === deleteTarget?.id}>
              {busyId === deleteTarget?.id ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
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

  // Admin org-selector state
  const [currentUser, setCurrentUser] = useState<{ is_superuser?: boolean; organization_id?: number } | null>(null);
  const [organizations, setOrganizations] = useState<{ id: number; name: string }[]>([]);
  const [selectedOrgId, setSelectedOrgId] = useState<number | undefined>(undefined);

  useEffect(() => {
    async function bootstrap() {
      try {
        const user = await api.getCurrentUser();
        setCurrentUser(user);
        if (user.is_superuser) {
          const orgs = await api.getOrganizations();
          const list = Array.isArray(orgs) ? orgs : orgs.items || [];
          setOrganizations(list);
        }
      } catch { /* ignore */ }
      loadIntegration();
    }
    bootstrap();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reload integration whenever the selected org changes
  useEffect(() => {
    loadIntegration();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId]);

  async function loadIntegration() {
    setLoadingIntegration(true);
    try {
      const data = await api.getJiraIntegration(selectedOrgId);
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
      const result = await api.testJiraConnection(selectedOrgId);
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
        await api.updateJiraIntegration(payload, selectedOrgId);
        toast({ title: 'Jira integration updated.' });
      } else {
        await api.createJiraIntegration({ ...payload, api_token: form.api_token }, selectedOrgId);
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
      await api.deleteJiraIntegration(selectedOrgId);
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

        {/* Admin org selector — only visible to superusers */}
        {currentUser?.is_superuser && organizations.length > 0 && (
          <Card className="border border-primary/20 bg-primary/5">
            <CardContent className="py-3 px-4 flex items-center gap-3">
              <Settings2 className="h-4 w-4 text-primary shrink-0" />
              <span className="text-sm font-medium text-primary">Admin view — configure for:</span>
              <Select
                value={selectedOrgId ? String(selectedOrgId) : '__own__'}
                onValueChange={(v) => {
                  setSelectedOrgId(v === '__own__' ? undefined : Number(v));
                  setIntegration(null);
                }}
              >
                <SelectTrigger className="h-8 w-56 text-sm border-primary/30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__own__">My organization</SelectItem>
                  {organizations.map((org) => (
                    <SelectItem key={org.id} value={String(org.id)}>
                      {org.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedOrgId && (
                <Badge variant="outline" className="text-primary border-primary/40 text-xs">
                  Org #{selectedOrgId}
                </Badge>
              )}
            </CardContent>
          </Card>
        )}
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

        {/* Censys ASM Integration Card */}
        <CensysSection />

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
