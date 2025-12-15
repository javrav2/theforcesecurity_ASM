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
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
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

interface DiscoveryResult {
  domain: string;
  total_subdomains: number;
  total_ips: number;
  total_cidrs: number;
  assets_created: number;
  source_results: Array<{
    source: string;
    success: boolean;
    subdomains_found: number;
    ips_found: number;
    elapsed_time: number;
    error?: string;
  }>;
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
  
  // Discovery state
  const [discoveryDomain, setDiscoveryDomain] = useState('');
  const [running, setRunning] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryResult | null>(null);
  
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
      setDiscoveryDomain(data.domain || '');
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

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await fetchOrganization();
      await fetchAssets();
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

  const handleRunDiscovery = async () => {
    if (!discoveryDomain) {
      toast({
        title: 'Error',
        description: 'Please enter a domain to discover',
        variant: 'destructive',
      });
      return;
    }

    setRunning(true);
    setDiscoveryResult(null);
    try {
      const result = await api.runExternalDiscovery({
        organization_id: orgId,
        domain: discoveryDomain,
        include_free_sources: true,
        include_paid_sources: true,
        create_assets: true,
        skip_existing: true,
      });

      setDiscoveryResult(result);
      toast({
        title: 'Discovery Complete',
        description: `Found ${result.total_subdomains} subdomains, ${result.total_ips} IPs. Created ${result.assets_created} new assets.`,
      });
      
      // Refresh assets list
      await fetchAssets();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to run discovery',
        variant: 'destructive',
      });
    } finally {
      setRunning(false);
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
          <CardContent className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Enter domain (e.g., rockwellautomation.com)"
                  value={discoveryDomain}
                  onChange={(e) => setDiscoveryDomain(e.target.value)}
                />
              </div>
              <Button onClick={handleRunDiscovery} disabled={running || !discoveryDomain}>
                {running ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Discovering...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Discovery
                  </>
                )}
              </Button>
            </div>

            {running && (
              <div className="p-4 bg-muted rounded-lg">
                <div className="flex items-center gap-3">
                  <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  <div>
                    <p className="font-medium">Discovery in progress...</p>
                    <p className="text-sm text-muted-foreground">
                      Querying crt.sh, Wayback Machine, RapidDNS, and other sources...
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Discovery Results */}
            {discoveryResult && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-8 w-8 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResult.total_subdomains}</p>
                          <p className="text-sm text-muted-foreground">Subdomains</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Server className="h-8 w-8 text-green-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResult.total_ips}</p>
                          <p className="text-sm text-muted-foreground">IP Addresses</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Shield className="h-8 w-8 text-orange-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResult.assets_created}</p>
                          <p className="text-sm text-muted-foreground">Assets Created</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-8 w-8 text-purple-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResult.total_cidrs}</p>
                          <p className="text-sm text-muted-foreground">IP Ranges</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Source Results */}
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Source</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Subdomains</TableHead>
                      <TableHead className="text-right">IPs</TableHead>
                      <TableHead className="text-right">Time</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {discoveryResult.source_results.map((source) => (
                      <TableRow key={source.source}>
                        <TableCell className="font-medium">{source.source}</TableCell>
                        <TableCell>
                          {source.success ? (
                            <Badge variant="default" className="bg-green-600">
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Success
                            </Badge>
                          ) : (
                            <Badge variant="destructive">
                              <XCircle className="h-3 w-3 mr-1" />
                              Failed
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-right">{source.subdomains_found}</TableCell>
                        <TableCell className="text-right">{source.ips_found}</TableCell>
                        <TableCell className="text-right">{source.elapsed_time.toFixed(2)}s</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
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

