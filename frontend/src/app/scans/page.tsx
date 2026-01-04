'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
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
  StopCircle,
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
  results?: {
    ports_found?: number;
    ports_imported?: number;
    live_hosts?: number;
    host_results?: Array<{
      host: string;
      ip: string;
      is_live: boolean;
      open_ports: number[];
      port_count: number;
      asset_id?: number;
      asset_created?: boolean;
    }>;
    targets_expanded?: number;
    [key: string]: any;
  };
}

export default function ScansPage() {
  const router = useRouter();
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
    scanner: 'naabu',  // Port scanner: naabu, masscan, nmap
    ports: '',         // Port specification for port scans
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

      // Build config based on scan type
      const config: Record<string, any> = {};
      if (formData.scan_type === 'port_scan') {
        config.scanner = formData.scanner;
        if (formData.ports) {
          config.ports = formData.ports;
        }
      }

      await api.createScan({
        name: formData.name.trim(),
        organization_id: parseInt(formData.organization_id),
        scan_type: formData.scan_type,
        targets: targets.length > 0 ? targets : undefined,
        config: Object.keys(config).length > 0 ? config : undefined,
      });

      toast({
        title: 'Scan Started',
        description: 'The scan has been queued and will start shortly.',
      });

      setCreateDialogOpen(false);
      setFormData({ name: '', organization_id: '', scan_type: 'vulnerability', targets: '', scanner: 'naabu', ports: '' });
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

  const handleCancelScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent row click navigation
    try {
      await api.cancelScan(scanId);
      toast({
        title: 'Scan Cancelled',
        description: 'The scan has been stopped.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to cancel scan',
        variant: 'destructive',
      });
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

                {/* Port Scan Options */}
                {formData.scan_type === 'port_scan' && (
                  <>
                    <div className="space-y-2">
                      <Label>Scanner Tool</Label>
                      <Select
                        value={formData.scanner}
                        onValueChange={(value) => setFormData({ ...formData, scanner: value })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="naabu">
                            <div className="flex flex-col">
                              <span>Naabu (Recommended)</span>
                              <span className="text-xs text-muted-foreground">Fast, reliable port scanner</span>
                            </div>
                          </SelectItem>
                          <SelectItem value="masscan">
                            <div className="flex flex-col">
                              <span>Masscan</span>
                              <span className="text-xs text-muted-foreground">Fastest scanner, good for large ranges</span>
                            </div>
                          </SelectItem>
                          <SelectItem value="nmap">
                            <div className="flex flex-col">
                              <span>Nmap</span>
                              <span className="text-xs text-muted-foreground">Most accurate, includes service detection</span>
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Ports (optional)</Label>
                      <Input
                        placeholder="80,443,8080 or 1-1000 or - for all"
                        value={formData.ports}
                        onChange={(e) => setFormData({ ...formData, ports: e.target.value })}
                      />
                      <p className="text-xs text-muted-foreground">
                        Leave empty to scan top 100 common ports
                      </p>
                    </div>
                  </>
                )}

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
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Live Assets</TableHead>
                <TableHead>Ports</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead className="w-[80px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center py-8 text-muted-foreground">
                    No scans yet. Start a new scan to begin discovering vulnerabilities.
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow 
                    key={scan.id} 
                    className="cursor-pointer hover:bg-secondary/50 transition-colors"
                    onClick={() => router.push(`/scans/${scan.id}`)}
                  >
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium text-primary hover:underline">{scan.name}</span>
                        {scan.progress !== undefined && scan.progress > 0 && scan.progress < 100 && (
                          <div className="flex items-center gap-2 mt-1">
                            <div className="w-20 h-1.5 bg-secondary rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-primary transition-all" 
                                style={{ width: `${scan.progress}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground">{scan.progress}%</span>
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <Badge className={getStatusColor(scan.status)}>{scan.status}</Badge>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{scan.scan_type?.replace(/_/g, ' ')}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {scan.organization_name || '-'}
                    </TableCell>
                    <TableCell>
                      {scan.targets?.length || scan.targets_count || scan.results?.targets_expanded ? (
                        <div className="flex flex-col">
                          <span className="font-mono text-sm">
                            {scan.results?.targets_expanded || scan.targets?.length || scan.targets_count}
                          </span>
                          {scan.targets?.length && scan.targets.length <= 3 && (
                            <span className="text-xs text-muted-foreground truncate max-w-[120px]">
                              {scan.targets.slice(0, 2).join(', ')}
                              {scan.targets.length > 2 && '...'}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const liveHosts = scan.results?.live_hosts || 
                          scan.results?.host_results?.filter((h: any) => h.is_live).length || 
                          0;
                        const totalHosts = scan.results?.host_results?.length || scan.assets_discovered || 0;
                        
                        if (liveHosts > 0) {
                          return (
                            <div className="flex items-center gap-1">
                              <Badge className="bg-green-500/20 text-green-400">{liveHosts}</Badge>
                              {totalHosts > liveHosts && (
                                <span className="text-xs text-muted-foreground">/ {totalHosts}</span>
                              )}
                            </div>
                          );
                        } else if (scan.assets_discovered !== undefined && scan.assets_discovered > 0) {
                          return <Badge variant="secondary">{scan.assets_discovered}</Badge>;
                        }
                        return <span className="text-muted-foreground">—</span>;
                      })()}
                    </TableCell>
                    <TableCell>
                      {scan.results?.ports_found !== undefined && scan.results.ports_found > 0 ? (
                        <Badge variant="outline" className="font-mono">{scan.results.ports_found}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.findings_count !== undefined && scan.findings_count > 0 ? (
                        <Badge variant="destructive">{scan.findings_count}</Badge>
                      ) : scan.vulnerabilities_found !== undefined && scan.vulnerabilities_found > 0 ? (
                        <Badge variant="destructive">{scan.vulnerabilities_found}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                      {scan.started_at ? formatDate(scan.started_at) : formatDate(scan.created_at)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                      {scan.started_at && scan.completed_at
                        ? `${Math.round(
                            (new Date(scan.completed_at).getTime() -
                              new Date(scan.started_at).getTime()) /
                              1000
                          )}s`
                        : scan.status?.toLowerCase() === 'running'
                        ? 'In progress...'
                        : scan.status?.toLowerCase() === 'pending'
                        ? 'Waiting...'
                        : '—'}
                    </TableCell>
                    <TableCell>
                      {(scan.status?.toLowerCase() === 'running' || scan.status?.toLowerCase() === 'pending') && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 text-red-500 hover:text-red-600 hover:bg-red-500/10"
                          onClick={(e) => handleCancelScan(scan.id, e)}
                        >
                          <StopCircle className="h-4 w-4" />
                        </Button>
                      )}
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














