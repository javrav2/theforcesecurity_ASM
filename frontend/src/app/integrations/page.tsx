'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
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
} from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface JiraIntegration {
  id: number;
  hostname: string;
  email: string;
  default_project_key?: string;
  default_issue_type?: string;
  is_active: boolean;
  last_tested_at?: string;
  last_test_ok?: boolean;
  created_at: string;
  updated_at: string;
}

interface JiraFormState {
  hostname: string;
  email: string;
  api_token: string;
  default_project_key: string;
  default_issue_type: string;
}

const defaultForm: JiraFormState = {
  hostname: '',
  email: '',
  api_token: '',
  default_project_key: '',
  default_issue_type: 'Bug',
};

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
  const [projects, setProjects] = useState<{ key: string; name: string }[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(false);

  useEffect(() => {
    loadIntegration();
  }, []);

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

  async function openSetup() {
    if (integration) {
      setForm({
        hostname: integration.hostname,
        email: integration.email,
        api_token: '',
        default_project_key: integration.default_project_key || '',
        default_issue_type: integration.default_issue_type || 'Bug',
      });
      // Pre-load projects for default project picker
      loadProjects(integration.hostname, integration.email, '');
    } else {
      setForm(defaultForm);
      setProjects([]);
    }
    setTestResult(null);
    setSetupOpen(true);
  }

  async function loadProjects(hostname?: string, email?: string, apiToken?: string) {
    const h = hostname ?? form.hostname;
    const e = email ?? form.email;
    const t = apiToken ?? form.api_token;
    if (!h || !e) return;
    setLoadingProjects(true);
    try {
      const data = await api.getJiraProjects();
      setProjects(data.projects);
    } catch {
      // Projects load silently; user can still type a project key manually
    } finally {
      setLoadingProjects(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      if (!integration) {
        toast({ title: 'Save the integration first to test it.', variant: 'destructive' });
        return;
      }
      const result = await api.testJiraConnection();
      setTestResult(result);
    } catch (err) {
      setTestResult({ ok: false, message: getApiErrorMessage(err, 'Test failed') });
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!form.hostname || !form.email) {
      toast({ title: 'Hostname and email are required.', variant: 'destructive' });
      return;
    }
    if (!integration && !form.api_token) {
      toast({ title: 'API token is required when creating the integration.', variant: 'destructive' });
      return;
    }
    setSaving(true);
    try {
      const payload = {
        hostname: form.hostname,
        email: form.email,
        ...(form.api_token ? { api_token: form.api_token } : {}),
        default_project_key: form.default_project_key || undefined,
        default_issue_type: form.default_issue_type || 'Bug',
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

  return (
    <MainLayout>
      <Header title="Integrations" subtitle="Connect ASM to third-party platforms to push findings and automate workflows." />
      <div className="p-6 space-y-6">

        {/* Jira Integration Card */}
        <Card className="border border-border">
          <CardHeader className="flex flex-row items-center gap-4 space-y-0 pb-3">
            {/* Jira logo */}
            <div className="w-10 h-10 rounded-lg bg-[#0052CC] flex items-center justify-center shrink-0">
              <svg viewBox="0 0 24 24" fill="white" className="w-6 h-6">
                <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <CardTitle className="text-base">Atlassian Jira</CardTitle>
              <CardDescription className="text-sm">
                Push vulnerability findings directly to Jira as tracked issues for your security and engineering teams.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {loadingIntegration ? (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              ) : integration ? (
                <Badge
                  variant="outline"
                  className={cn(
                    integration.is_active && integration.last_test_ok !== false
                      ? 'bg-green-500/10 text-green-400 border-green-500/30'
                      : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
                  )}
                >
                  {integration.is_active && integration.last_test_ok !== false ? (
                    <><CheckCircle2 className="h-3 w-3 mr-1" />Connected</>
                  ) : (
                    <><AlertCircle className="h-3 w-3 mr-1" />Check config</>
                  )}
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">
                  Not configured
                </Badge>
              )}
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            {integration ? (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Hostname</p>
                    <p className="font-mono">{integration.hostname}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Auth email</p>
                    <p>{integration.email}</p>
                  </div>
                  {integration.default_project_key && (
                    <div>
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Default project</p>
                      <p className="font-mono">{integration.default_project_key}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Default issue type</p>
                    <p>{integration.default_issue_type || 'Bug'}</p>
                  </div>
                </div>

                {integration.last_tested_at && (
                  <p className="text-xs text-muted-foreground">
                    Last tested:{' '}
                    {new Date(integration.last_tested_at).toLocaleString()}{' '}
                    {integration.last_test_ok === true && (
                      <span className="text-green-400">— OK</span>
                    )}
                    {integration.last_test_ok === false && (
                      <span className="text-red-400">— Failed</span>
                    )}
                  </p>
                )}

                {testResult && (
                  <div
                    className={cn(
                      'flex items-start gap-2 rounded-lg border p-3 text-sm',
                      testResult.ok
                        ? 'border-green-500/30 bg-green-500/10 text-green-300'
                        : 'border-red-500/30 bg-red-500/10 text-red-300',
                    )}
                  >
                    {testResult.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 shrink-0" />}
                    <span>
                      {testResult.message}
                      {testResult.display_name && ` (${testResult.display_name})`}
                    </span>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
                    {testing ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                    Test connection
                  </Button>
                  <Button size="sm" variant="outline" onClick={openSetup}>
                    <Settings2 className="h-4 w-4 mr-2" />
                    Edit
                  </Button>
                  <a
                    href={`https://${integration.hostname.replace(/^https?:\/\//, '')}/jira`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <Button size="sm" variant="outline">
                      <ExternalLink className="h-4 w-4 mr-2" />
                      Open Jira
                    </Button>
                  </a>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-red-600/30 hover:bg-red-600/20 text-red-400"
                    onClick={() => setDeleteOpen(true)}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Remove
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                <p className="text-sm text-muted-foreground flex-1">
                  Connect your Jira workspace to create tickets directly from findings in the ASM platform.
                </p>
                <Button onClick={openSetup}>
                  <Plug className="h-4 w-4 mr-2" />
                  Set up Jira
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Placeholder for future integrations */}
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
        <DialogContent className="max-w-lg">
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
              Enter your Jira Cloud hostname, admin email, and an API token.{' '}
              <a
                href="https://id.atlassian.com/manage-profile/security/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center gap-1"
              >
                Create an API token <ExternalLink className="h-3 w-3" />
              </a>
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-sm font-medium">Hostname</label>
              <Input
                placeholder="myorg.atlassian.net"
                value={form.hostname}
                onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">Your Jira Cloud instance URL (without https://)</p>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">Email</label>
              <Input
                type="email"
                placeholder="admin@yourcompany.com"
                value={form.email}
                onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                API Token{integration && <span className="text-muted-foreground font-normal"> (leave blank to keep existing)</span>}
              </label>
              <Input
                type="password"
                placeholder={integration ? '••••••••••••' : 'Paste your API token'}
                value={form.api_token}
                onChange={(e) => setForm((f) => ({ ...f, api_token: e.target.value }))}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Default project key</label>
                <Input
                  placeholder="e.g. SEC"
                  value={form.default_project_key}
                  onChange={(e) => setForm((f) => ({ ...f, default_project_key: e.target.value.toUpperCase() }))}
                />
                <p className="text-xs text-muted-foreground">Pre-selected in ticket dialog</p>
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Default issue type</label>
                <Select
                  value={form.default_issue_type}
                  onValueChange={(v) => setForm((f) => ({ ...f, default_issue_type: v }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {['Bug', 'Task', 'Story', 'Epic', 'Vulnerability', 'Security'].map((t) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setSetupOpen(false)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              {integration ? 'Save changes' : 'Connect'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteOpen} onOpenChange={(v) => { if (!deleting) setDeleteOpen(v); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <Trash2 className="h-5 w-5" />
              Remove Jira integration
            </DialogTitle>
            <DialogDescription>
              This will remove the stored credentials and disable Jira ticket creation. Existing tickets in Jira will not be affected.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={deleting}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleting}
            >
              {deleting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
