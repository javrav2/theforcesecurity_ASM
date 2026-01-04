'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
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
  ArrowLeft,
  Play,
  Pause,
  RefreshCw,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Target,
  Shield,
  Bug,
  Server,
  Calendar,
  User,
  FileText,
  AlertCircle,
  StopCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface ScanResults {
  summary?: Record<string, any>;
  import_summary?: Record<string, any>;
  targets_original?: number;
  targets_expanded?: number;
  targets_scanned?: number;
  [key: string]: any;
}

interface Scan {
  id: number;
  name: string;
  organization_id: number;
  organization_name?: string;
  scan_type: string;
  status: string;
  targets: string[];
  config: Record<string, any>;
  progress: number;
  assets_discovered: number;
  technologies_found: number;
  vulnerabilities_found: number;
  targets_count: number;
  findings_count: number;
  started_by?: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  results: ScanResults;
  created_at: string;
  updated_at: string;
}

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const { toast } = useToast();

  const fetchScan = async () => {
    try {
      const data = await api.getScan(parseInt(scanId));
      setScan(data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch scan details',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchScan();
    // Poll for updates if scan is running
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        fetchScan();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchScan();
  };

  const handleCancel = async () => {
    if (!scan) return;
    
    setCancelling(true);
    try {
      await api.cancelScan(scan.id);
      toast({
        title: 'Scan Cancelled',
        description: 'The scan has been stopped.',
      });
      fetchScan();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to cancel scan',
        variant: 'destructive',
      });
    } finally {
      setCancelling(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'running':
      case 'in_progress':
        return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'pending':
      case 'queued':
        return <Clock className="h-5 w-5 text-yellow-500" />;
      case 'cancelled':
        return <AlertCircle className="h-5 w-5 text-gray-500" />;
      default:
        return <AlertTriangle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'running':
      case 'in_progress':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'pending':
      case 'queued':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'cancelled':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const formatDuration = (startedAt: string, completedAt?: string) => {
    const start = new Date(startedAt);
    const end = completedAt ? new Date(completedAt) : new Date();
    const seconds = Math.round((end.getTime() - start.getTime()) / 1000);
    
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-96">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </MainLayout>
    );
  }

  if (!scan) {
    return (
      <MainLayout>
        <div className="flex flex-col items-center justify-center h-96 gap-4">
          <AlertTriangle className="h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">Scan not found</p>
          <Button variant="outline" onClick={() => router.push('/scans')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Scans
          </Button>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header 
        title={scan.name} 
        subtitle={`${scan.scan_type?.replace(/_/g, ' ')} scan`} 
      />

      <div className="p-6 space-y-6">
        {/* Navigation and Actions */}
        <div className="flex items-center justify-between">
          <Button variant="outline" onClick={() => router.push('/scans')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Scans
          </Button>
          <div className="flex gap-2">
            {(scan.status === 'running' || scan.status === 'pending') && (
              <Button 
                variant="destructive" 
                onClick={handleCancel} 
                disabled={cancelling}
              >
                {cancelling ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <StopCircle className="h-4 w-4 mr-2" />
                )}
                Stop Scan
              </Button>
            )}
            <Button variant="outline" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Status Banner */}
        <Card className={`border-l-4 ${
          scan.status === 'completed' ? 'border-l-green-500' :
          scan.status === 'running' ? 'border-l-blue-500' :
          scan.status === 'failed' ? 'border-l-red-500' :
          scan.status === 'pending' ? 'border-l-yellow-500' :
          'border-l-gray-500'
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                {getStatusIcon(scan.status)}
                <div>
                  <div className="flex items-center gap-2">
                    <Badge className={getStatusColor(scan.status)}>
                      {scan.status?.toUpperCase()}
                    </Badge>
                    {scan.progress > 0 && scan.progress < 100 && (
                      <span className="text-sm text-muted-foreground">
                        {scan.progress}% complete
                      </span>
                    )}
                  </div>
                  {scan.error_message && (
                    <p className="text-sm text-red-400 mt-1">{scan.error_message}</p>
                  )}
                </div>
              </div>
              {scan.progress > 0 && scan.progress < 100 && (
                <div className="w-48 h-2 bg-secondary rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-primary transition-all" 
                    style={{ width: `${scan.progress}%` }}
                  />
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Target className="h-8 w-8 text-blue-400" />
                <div>
                  <p className="text-2xl font-bold">
                    {scan.results?.targets_expanded || scan.results?.targets_scanned || scan.targets?.length || 0}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {scan.results?.targets_expanded && scan.results?.targets_original && 
                     scan.results.targets_expanded !== scan.results.targets_original
                      ? `IPs (from ${scan.results.targets_original} ${scan.results.targets_original === 1 ? 'range' : 'ranges'})`
                      : 'Targets'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Server className="h-8 w-8 text-green-400" />
                <div>
                  <p className="text-2xl font-bold">
                    {scan.results?.live_hosts || scan.results?.host_results?.filter((h: any) => h.is_live).length || scan.assets_discovered || 0}
                  </p>
                  <p className="text-sm text-muted-foreground">Live Assets</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                {scan.scan_type === 'port_scan' ? (
                  <>
                    <Shield className="h-8 w-8 text-purple-400" />
                    <div>
                      <p className="text-2xl font-bold">{scan.results?.ports_found || 0}</p>
                      <p className="text-sm text-muted-foreground">Ports Found</p>
                    </div>
                  </>
                ) : (
                  <>
                    <Bug className="h-8 w-8 text-red-400" />
                    <div>
                      <p className="text-2xl font-bold">{scan.vulnerabilities_found || 0}</p>
                      <p className="text-sm text-muted-foreground">Vulnerabilities</p>
                    </div>
                  </>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Clock className="h-8 w-8 text-yellow-400" />
                <div>
                  <p className="text-2xl font-bold">
                    {scan.started_at ? formatDuration(scan.started_at, scan.completed_at) : '—'}
                  </p>
                  <p className="text-sm text-muted-foreground">Duration</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Scan Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Scan Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Organization</span>
                <span className="font-medium">{scan.organization_name || `Org #${scan.organization_id}`}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Scan Type</span>
                <Badge variant="outline">{scan.scan_type?.replace(/_/g, ' ')}</Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Started By</span>
                <span className="font-medium">{scan.started_by || '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Created</span>
                <span className="text-sm">{formatDate(scan.created_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Started</span>
                <span className="text-sm">{scan.started_at ? formatDate(scan.started_at) : '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Completed</span>
                <span className="text-sm">{scan.completed_at ? formatDate(scan.completed_at) : '—'}</span>
              </div>
            </CardContent>
          </Card>

          {/* Configuration */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              {scan.config && Object.keys(scan.config).length > 0 ? (
                <div className="space-y-2">
                  {Object.entries(scan.config).map(([key, value]) => (
                    <div key={key} className="flex justify-between">
                      <span className="text-muted-foreground">{key.replace(/_/g, ' ')}</span>
                      <span className="font-mono text-sm">
                        {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-sm">Default configuration</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Targets */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Target className="h-5 w-5" />
              Targets ({scan.targets?.length || 0})
              {scan.results?.targets_expanded && scan.results.targets_expanded > (scan.targets?.length || 0) && (
                <Badge variant="outline" className="ml-2 text-xs">
                  {scan.results.targets_expanded} IPs after CIDR expansion
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              {scan.results?.targets_expanded && scan.results.targets_expanded > (scan.targets?.length || 0)
                ? `${scan.targets?.length || 0} input targets expanded to ${scan.results.targets_expanded} individual IPs`
                : 'Assets scanned in this job'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {scan.targets && scan.targets.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {scan.targets.map((target, index) => (
                  <Badge key={index} variant="secondary" className="font-mono">
                    {target}
                    {target.includes('/') && (
                      <span className="text-xs text-muted-foreground ml-1">(CIDR)</span>
                    )}
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">
                No specific targets — scanning all organization assets
              </p>
            )}
          </CardContent>
        </Card>

        {/* Live Assets Found */}
        {scan.results?.host_results && scan.results.host_results.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Server className="h-5 w-5" />
                Discovered Hosts ({scan.results.host_results.length})
                <Badge variant="default" className="ml-2">
                  {scan.results.host_results.filter((h: any) => h.is_live).length} Live
                </Badge>
              </CardTitle>
              <CardDescription>
                Hosts discovered during the scan with their port information
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host / IP</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Open Ports</TableHead>
                    <TableHead>Port Count</TableHead>
                    <TableHead>Asset</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scan.results.host_results.map((host: any, index: number) => (
                    <TableRow key={index}>
                      <TableCell className="font-mono">{host.host || host.ip}</TableCell>
                      <TableCell>
                        {host.is_live ? (
                          <Badge className="bg-green-500/20 text-green-400">Live</Badge>
                        ) : (
                          <Badge variant="secondary">No Response</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {host.open_ports && host.open_ports.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {host.open_ports.slice(0, 10).map((port: number) => (
                              <Badge key={port} variant="outline" className="font-mono text-xs">
                                {port}
                              </Badge>
                            ))}
                            {host.open_ports.length > 10 && (
                              <Badge variant="secondary" className="text-xs">
                                +{host.open_ports.length - 10} more
                              </Badge>
                            )}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono">{host.port_count || 0}</span>
                      </TableCell>
                      <TableCell>
                        {host.asset_id ? (
                          <div className="flex items-center gap-2">
                            <Button
                              variant="link"
                              className="h-auto p-0 text-primary"
                              onClick={() => router.push(`/assets/${host.asset_id}`)}
                            >
                              View Asset
                            </Button>
                            {host.asset_created && (
                              <Badge className="bg-blue-500/20 text-blue-400 text-xs">New</Badge>
                            )}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        {/* Port Scan Summary */}
        {scan.results?.ports_found !== undefined && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Port Scan Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-secondary/50 rounded-lg">
                  <p className="text-2xl font-bold text-blue-400">{scan.results.ports_found || 0}</p>
                  <p className="text-sm text-muted-foreground">Ports Found</p>
                </div>
                <div className="text-center p-4 bg-secondary/50 rounded-lg">
                  <p className="text-2xl font-bold text-green-400">{scan.results.ports_imported || 0}</p>
                  <p className="text-sm text-muted-foreground">Ports Imported</p>
                </div>
                <div className="text-center p-4 bg-secondary/50 rounded-lg">
                  <p className="text-2xl font-bold text-yellow-400">{scan.results.ports_updated || 0}</p>
                  <p className="text-sm text-muted-foreground">Ports Updated</p>
                </div>
                <div className="text-center p-4 bg-secondary/50 rounded-lg">
                  <p className="text-2xl font-bold text-purple-400">{scan.results.live_hosts || scan.results.host_results?.filter((h: any) => h.is_live).length || 0}</p>
                  <p className="text-sm text-muted-foreground">Live Hosts</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Raw Results (Collapsible) */}
        {scan.results && Object.keys(scan.results).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Raw Results
              </CardTitle>
              <CardDescription>Full scan output data (JSON format)</CardDescription>
            </CardHeader>
            <CardContent>
              <details className="group">
                <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground mb-2">
                  Click to expand raw JSON data
                </summary>
                <pre className="bg-secondary/50 p-4 rounded-lg overflow-x-auto text-sm max-h-96 overflow-y-auto">
                  {JSON.stringify(scan.results, null, 2)}
                </pre>
              </details>
            </CardContent>
          </Card>
        )}

        {/* Error Message */}
        {scan.error_message && (
          <Card className="border-red-500/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2 text-red-400">
                <AlertCircle className="h-5 w-5" />
                Error Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-red-500/10 p-4 rounded-lg overflow-x-auto text-sm text-red-300 whitespace-pre-wrap">
                {scan.error_message}
              </pre>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}



