'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Play,
  ScanLine,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Scan {
  id: number;
  name: string;
  organization_id: number;
  organization_name?: string;
  scan_type: string;
  status: string;
  targets?: string[];
  progress?: number;
  assets_discovered?: number;
  vulnerabilities_found?: number;
  started_at?: string;
  completed_at?: string;
  targets_count?: number;
  findings_count?: number;
  created_at: string;
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    organization_id: '',
    scan_type: 'vulnerability',
    targets: '',
  });
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [scansData, orgsData] = await Promise.all([
        api.getScans({ limit: 50 }),
        api.getOrganizations(),
      ]);

      setScans(scansData.items || scansData || []);
      setOrganizations(orgsData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch scans',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Poll for updates every 10 seconds
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleCreateScan = async () => {
    if (!formData.organization_id) {
      toast({
        title: 'Error',
        description: 'Please select an organization',
        variant: 'destructive',
      });
      return;
    }

    if (!formData.name.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter a scan name',
        variant: 'destructive',
      });
      return;
    }

    setSubmitting(true);
    try {
      const targets = formData.targets
        .split('\n')
        .map((t) => t.trim())
        .filter((t) => t);

      await api.createScan({
        name: formData.name.trim(),
        organization_id: parseInt(formData.organization_id),
        scan_type: formData.scan_type,
        targets: targets.length > 0 ? targets : undefined,
      });

      toast({
        title: 'Scan Started',
        description: 'The scan has been queued and will start shortly.',
      });

      setCreateDialogOpen(false);
      setFormData({ name: '', organization_id: '', scan_type: 'vulnerability', targets: '' });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to start scan',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running':
      case 'in_progress':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'pending':
      case 'queued':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'bg-green-500/20 text-green-400';
      case 'running':
      case 'in_progress':
        return 'bg-blue-500/20 text-blue-400';
      case 'failed':
        return 'bg-red-500/20 text-red-400';
      case 'pending':
      case 'queued':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <MainLayout>
      <Header title="Scans" subtitle="Vulnerability and discovery scan management" />

      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Button variant="outline" size="sm" onClick={fetchData}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Play className="h-4 w-4 mr-2" />
                New Scan
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Start New Scan</DialogTitle>
                <DialogDescription>
                  Configure and start a new vulnerability or discovery scan.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Scan Name</Label>
                  <Input
                    placeholder="e.g., Weekly vulnerability scan"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Organization</Label>
                  <Select
                    value={formData.organization_id}
                    onValueChange={(value) =>
                      setFormData({ ...formData, organization_id: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
                      {organizations.map((org) => (
                        <SelectItem key={org.id} value={org.id.toString()}>
                          {org.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Scan Type</Label>
                  <Select
                    value={formData.scan_type}
                    onValueChange={(value) => setFormData({ ...formData, scan_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="vulnerability">Vulnerability Scan (Nuclei)</SelectItem>
                      <SelectItem value="discovery">Asset Discovery</SelectItem>
                      <SelectItem value="subdomain_enum">Subdomain Enumeration</SelectItem>
                      <SelectItem value="port_scan">Port Scan</SelectItem>
                      <SelectItem value="web_scan">Web Scan</SelectItem>
                      <SelectItem value="technology">Technology Detection</SelectItem>
                      <SelectItem value="full">Full Scan (All)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Targets (optional, one per line)</Label>
                  <textarea
                    className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    placeholder="example.com&#10;sub.example.com&#10;192.168.1.1"
                    value={formData.targets}
                    onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave empty to scan all assets in the organization
                  </p>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateScan} disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Starting...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Start Scan
                    </>
                  )}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No scans yet. Start a new scan to begin discovering vulnerabilities.
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <Badge className={getStatusColor(scan.status)}>{scan.status}</Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{scan.scan_type}</Badge>
                    </TableCell>
                    <TableCell>{scan.organization_name || '-'}</TableCell>
                    <TableCell>{scan.targets_count || '-'}</TableCell>
                    <TableCell>
                      {scan.findings_count !== undefined ? (
                        <Badge variant={scan.findings_count > 0 ? 'destructive' : 'secondary'}>
                          {scan.findings_count}
                        </Badge>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {scan.started_at ? formatDate(scan.started_at) : formatDate(scan.created_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {scan.started_at && scan.completed_at
                        ? `${Math.round(
                            (new Date(scan.completed_at).getTime() -
                              new Date(scan.started_at).getTime()) /
                              1000
                          )}s`
                        : scan.status === 'running'
                        ? 'In progress...'
                        : '-'}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>
      </div>
    </MainLayout>
  );
}












