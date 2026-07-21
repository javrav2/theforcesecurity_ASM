'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
  Building2,
  Globe,
  Loader2,
  Play,
  ArrowLeft,
  Edit,
  Save,
  X,
  Server,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { api, type JiraIntegration } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import Link from 'next/link';

interface Organization {
  id: number;
  name: string;
  description?: string;
  domain?: string;
  industry?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  asset_count?: number;
  vulnerability_count?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  asset_type: string;
  status: string;
  created_at: string;
}


export default function OrganizationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const orgId = Number(params.id);
  
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState({ name: '', description: '', domain: '' });
  const [saving, setSaving] = useState(false);

  // Jira integration state
  const [jiraIntegration, setJiraIntegration] = useState<JiraIntegration | null>(null);
  const [jiraLoading, setJiraLoading] = useState(true);
  const [jiraForm, setJiraForm] = useState({ hostname: '', email: '', api_token: '', default_project_key: '', default_issue_type: 'Bug' });
  const [jiraFormOpen, setJiraFormOpen] = useState(false);
  const [jiraSaving, setJiraSaving] = useState(false);
  const [jiraTesting, setJiraTesting] = useState(false);
  const [jiraTestResult, setJiraTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  
  const { toast } = useToast();

  const fetchOrganization = async () => {
    try {
      const data = await api.getOrganization(orgId);
      setOrganization(data);
      setEditData({
        name: data.name || '',
        description: data.description || '',
        domain: data.domain || '',
      });
    } catch (error: any) {
      if (error.response?.status === 404) {
        toast({
          title: 'Not Found',
          description: 'Organization not found',
          variant: 'destructive',
        });
        router.push('/organizations');
      } else {
        toast({
          title: 'Error',
          description: 'Failed to fetch organization',
          variant: 'destructive',
        });
      }
    }
  };

  const fetchAssets = async () => {
    try {
      const data = await api.getAssets({ organization_id: orgId, limit: 50 });
      setAssets(Array.isArray(data) ? data : data.items || []);
    } catch (error) {
      console.error('Failed to fetch assets:', error);
    }
  };

  const fetchJiraIntegration = async () => {
    setJiraLoading(true);
    try {
      const data = await api.getJiraIntegration(orgId);
      setJiraIntegration(data);
    } catch {
      setJiraIntegration(null);
    } finally {
      setJiraLoading(false);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await fetchOrganization();
      await fetchAssets();
      await fetchJiraIntegration();
      setLoading(false);
    };
    loadData();
  }, [orgId]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateOrganization(orgId, editData);
      await fetchOrganization();
      setEditing(false);
      toast({
        title: 'Success',
        description: 'Organization updated successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to update organization',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleOpenJiraForm = () => {
    if (jiraIntegration) {
      setJiraForm({
        hostname: jiraIntegration.hostname,
        email: jiraIntegration.email,
        api_token: '',
        default_project_key: jiraIntegration.default_project_key || '',
        default_issue_type: jiraIntegration.default_issue_type || 'Bug',
      });
    } else {
      setJiraForm({ hostname: '', email: '', api_token: '', default_project_key: '', default_issue_type: 'Bug' });
    }
    setJiraTestResult(null);
    setJiraFormOpen(true);
  };

  const handleJiraSave = async () => {
    if (!jiraForm.hostname || !jiraForm.email) {
      toast({ title: 'Hostname and email are required.', variant: 'destructive' });
      return;
    }
    if (!jiraIntegration && !jiraForm.api_token) {
      toast({ title: 'API token is required when creating the integration.', variant: 'destructive' });
      return;
    }
    setJiraSaving(true);
    try {
      const payload = {
        hostname: jiraForm.hostname,
        email: jiraForm.email,
        ...(jiraForm.api_token ? { api_token: jiraForm.api_token } : {}),
        default_project_key: jiraForm.default_project_key || undefined,
        default_issue_type: jiraForm.default_issue_type || 'Bug',
      };
      if (jiraIntegration) {
        await api.updateJiraIntegration(payload, orgId);
        toast({ title: 'Jira integration updated.' });
      } else {
        await api.createJiraIntegration({ ...payload, api_token: jiraForm.api_token }, orgId);
        toast({ title: 'Jira integration configured.' });
      }
      setJiraFormOpen(false);
      await fetchJiraIntegration();
    } catch (err: any) {
      toast({ title: 'Failed to save', description: err.response?.data?.detail || 'Unknown error', variant: 'destructive' });
    } finally {
      setJiraSaving(false);
    }
  };

  const handleJiraTest = async () => {
    setJiraTesting(true);
    setJiraTestResult(null);
    try {
      const result = await api.testJiraConnection(orgId);
      setJiraTestResult(result);
      await fetchJiraIntegration();
    } catch (err: any) {
      setJiraTestResult({ ok: false, message: err.response?.data?.detail || 'Test failed' });
    } finally {
      setJiraTesting(false);
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </MainLayout>
    );
  }

  if (!organization) {
    return (
      <MainLayout>
        <div className="p-6">
          <p>Organization not found</p>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header 
        title={organization.name} 
        subtitle={organization.description || 'Organization details and asset discovery'} 
      />

      <div className="p-6 space-y-6">
        {/* Back button */}
        <div>
          <Link href="/organizations">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Organizations
            </Button>
          </Link>
        </div>

        {/* Organization Info */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                Organization Details
              </CardTitle>
              {!editing ? (
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  <Edit className="h-4 w-4 mr-2" />
                  Edit
                </Button>
              ) : (
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setEditing(false)}>
                    <X className="h-4 w-4 mr-2" />
                    Cancel
                  </Button>
                  <Button size="sm" onClick={handleSave} disabled={saving}>
                    {saving ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Save className="h-4 w-4 mr-2" />
                    )}
                    Save
                  </Button>
                </div>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {editing ? (
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={editData.name}
                    onChange={(e) => setEditData({ ...editData, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Description</Label>
                  <Input
                    value={editData.description}
                    onChange={(e) => setEditData({ ...editData, description: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Primary Domain</Label>
                  <Input
                    value={editData.domain}
                    onChange={(e) => setEditData({ ...editData, domain: e.target.value })}
                    placeholder="example.com"
                  />
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Name</p>
                  <p className="font-medium">{organization.name}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Primary Domain</p>
                  <p className="font-medium">
                    {organization.domain ? (
                      <Badge variant="outline" className="font-mono">
                        <Globe className="h-3 w-3 mr-1" />
                        {organization.domain}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground italic">Not set</span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  <Badge variant={organization.is_active ? 'default' : 'secondary'}>
                    {organization.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Created</p>
                  <p className="font-medium">{formatDate(organization.created_at)}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Asset Discovery */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Asset Discovery
            </CardTitle>
            <CardDescription>
              Discover subdomains, IPs, and related assets using external sources
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
              <div className="flex-1">
                <p className="text-sm text-muted-foreground">
                  Run a comprehensive discovery scan to find subdomains, IP addresses, technologies, 
                  and capture screenshots across all your assets.
                </p>
              </div>
              <Link 
                href={`/discovery?org=${orgId}${organization.domain ? `&domain=${organization.domain}` : ''}`}
              >
                <Button className="whitespace-nowrap">
                  <Play className="h-4 w-4 mr-2" />
                  Run Full Discovery
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>

        {/* Jira Integration */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-[#0052CC] flex items-center justify-center">
                  <svg viewBox="0 0 24 24" fill="white" className="w-3.5 h-3.5">
                    <path d="M11.571 11.429 6.286 6.143A.857.857 0 0 0 5.07 7.357l4.071 4.072-4.07 4.071a.857.857 0 0 0 1.213 1.214l5.285-5.286a.857.857 0 0 0 0-1.214zm4.286 0-5.286-5.286a.857.857 0 0 0-1.214 1.214l4.072 4.072-4.072 4.071a.857.857 0 0 0 1.214 1.214l5.286-5.286a.857.857 0 0 0 0-1.214z" />
                  </svg>
                </div>
                Jira Integration
              </CardTitle>
              <div className="flex items-center gap-2">
                {jiraLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                ) : jiraIntegration ? (
                  <Badge variant="outline" className={
                    jiraIntegration.last_test_ok !== false
                      ? 'bg-green-500/10 text-green-400 border-green-500/30'
                      : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                  }>
                    {jiraIntegration.last_test_ok !== false
                      ? <><CheckCircle2 className="h-3 w-3 mr-1" />Connected</>
                      : <><AlertCircle className="h-3 w-3 mr-1" />Check config</>
                    }
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground">Not configured</Badge>
                )}
                <Button variant="outline" size="sm" onClick={handleOpenJiraForm}>
                  <Edit className="h-4 w-4 mr-2" />
                  {jiraIntegration ? 'Edit' : 'Configure'}
                </Button>
                {jiraIntegration && (
                  <Button variant="outline" size="sm" onClick={handleJiraTest} disabled={jiraTesting}>
                    {jiraTesting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Test'}
                  </Button>
                )}
              </div>
            </div>
            <CardDescription>
              Configure Jira credentials so findings for this org can be pushed as tickets.
              For advanced settings (auto-create, bidirectional sync) use the{' '}
              <Link href="/integrations" className="underline text-primary">Integrations page</Link>.
            </CardDescription>
          </CardHeader>
          {jiraIntegration && !jiraFormOpen && (
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Hostname</p>
                  <p className="font-mono text-xs">{jiraIntegration.hostname}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Auth email</p>
                  <p className="text-xs truncate">{jiraIntegration.email}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Default project</p>
                  <p className="text-xs font-mono">{jiraIntegration.default_project_key || <span className="text-muted-foreground italic">none</span>}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Auto-create</p>
                  <Badge variant="outline" className="text-xs">
                    {jiraIntegration.auto_create_enabled
                      ? `On ≥ ${jiraIntegration.auto_create_min_severity}`
                      : 'Off'}
                  </Badge>
                </div>
              </div>
              {jiraTestResult && (
                <div className={`mt-3 flex items-center gap-2 text-xs p-2 rounded-md ${jiraTestResult.ok ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
                  {jiraTestResult.ok ? <CheckCircle2 className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
                  {jiraTestResult.message}
                </div>
              )}
              <div className="mt-3 flex justify-end">
                <Link href="/integrations">
                  <Button variant="ghost" size="sm" className="text-xs text-muted-foreground h-7">
                    <ExternalLink className="h-3 w-3 mr-1" />
                    Advanced settings
                  </Button>
                </Link>
              </div>
            </CardContent>
          )}
          {jiraFormOpen && (
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label className="text-sm">Hostname <span className="text-red-400">*</span></Label>
                  <Input
                    placeholder="yourorg.atlassian.net"
                    value={jiraForm.hostname}
                    onChange={(e) => setJiraForm(f => ({ ...f, hostname: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-sm">Auth email <span className="text-red-400">*</span></Label>
                  <Input
                    placeholder="you@company.com"
                    value={jiraForm.email}
                    onChange={(e) => setJiraForm(f => ({ ...f, email: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-sm">API token {jiraIntegration && <span className="text-muted-foreground">(leave blank to keep existing)</span>}</Label>
                  <Input
                    type="password"
                    placeholder={jiraIntegration ? '••••••••' : 'Atlassian API token'}
                    value={jiraForm.api_token}
                    onChange={(e) => setJiraForm(f => ({ ...f, api_token: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-sm">Default project key</Label>
                  <Input
                    placeholder="e.g. SEC"
                    value={jiraForm.default_project_key}
                    onChange={(e) => setJiraForm(f => ({ ...f, default_project_key: e.target.value }))}
                  />
                </div>
              </div>
              {jiraTestResult && (
                <div className={`flex items-center gap-2 text-xs p-2 rounded-md ${jiraTestResult.ok ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
                  {jiraTestResult.ok ? <CheckCircle2 className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
                  {jiraTestResult.message}
                </div>
              )}
              <div className="flex justify-end gap-2">
                <Button variant="outline" size="sm" onClick={() => setJiraFormOpen(false)}>
                  <X className="h-4 w-4 mr-1" /> Cancel
                </Button>
                <Button variant="outline" size="sm" onClick={handleJiraTest} disabled={jiraTesting || !jiraIntegration}>
                  {jiraTesting ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Test connection
                </Button>
                <Button size="sm" onClick={handleJiraSave} disabled={jiraSaving}>
                  {jiraSaving ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Save className="h-4 w-4 mr-1" />}
                  Save
                </Button>
              </div>
            </CardContent>
          )}
        </Card>

        {/* Assets List */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Discovered Assets ({assets.length})
              </CardTitle>
              <Link href="/assets">
                <Button variant="outline" size="sm">
                  View All Assets
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            {assets.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No assets discovered yet.</p>
                <p className="text-sm">Run a discovery scan to find subdomains and IPs.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Discovered</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.slice(0, 20).map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell className="font-mono text-sm">
                        {asset.name || asset.value}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{asset.asset_type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={asset.status === 'discovered' || asset.status === 'verified' ? 'default' : 'secondary'}>
                          {asset.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDate(asset.created_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {assets.length > 20 && (
              <p className="text-sm text-muted-foreground mt-4 text-center">
                Showing 20 of {assets.length} assets. <Link href="/assets" className="text-primary underline">View all</Link>
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}





