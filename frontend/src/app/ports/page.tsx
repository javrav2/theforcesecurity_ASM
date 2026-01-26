'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Network, Search, Download, Loader2, Filter, AlertTriangle, MoreVertical, Bug, Flag } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';

interface PortResult {
  id: number;
  asset_id: number;
  hostname: string | null;
  ip_address: string | null;
  asset_value: string | null;
  port: number;
  protocol: string;
  service_name?: string;
  service_product?: string;
  service_version?: string;
  state: string;
  banner?: string;
  is_risky: boolean;
  risk_reason?: string;
  discovered_by?: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
}

export default function PortsPage() {
  const [ports, setPorts] = useState<PortResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const [riskyFilter, setRiskyFilter] = useState<string>('all');
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [portsData, orgsData] = await Promise.all([
        api.getPorts({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          is_risky: riskyFilter === 'risky' ? true : riskyFilter === 'safe' ? false : undefined,
          limit: 200,
        }),
        api.getOrganizations(),
      ]);

      setPorts(portsData.items || portsData || []);
      setOrganizations(orgsData);
    } catch (error) {
      console.error('Failed to fetch ports:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch port data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [orgFilter, riskyFilter]);

  const handleCreateFinding = async (portId: number, severity: string) => {
    try {
      const response = await api.request(`/ports/${portId}/create-finding?severity=${severity}`, {
        method: 'POST',
      });
      if (response.success) {
        toast({
          title: 'Finding Created',
          description: response.message,
        });
        fetchData(); // Refresh to show updated risky status
      } else {
        toast({
          title: 'Finding Exists',
          description: response.message,
          variant: 'default',
        });
      }
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create finding',
        variant: 'destructive',
      });
    }
  };

  const handleMarkRisky = async (portId: number) => {
    const reason = prompt('Enter reason why this port is risky:');
    if (!reason) return;
    
    try {
      await api.request(`/ports/${portId}/mark-risky?reason=${encodeURIComponent(reason)}`, {
        method: 'POST',
      });
      toast({
        title: 'Port Marked as Risky',
        description: 'The port has been flagged for attention.',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to mark port as risky',
        variant: 'destructive',
      });
    }
  };

  const handleExport = () => {
    downloadCSV(
      ports.map((p) => ({
        hostname: p.hostname || p.asset_value || '',
        ip_address: p.ip_address || p.asset_value || '',
        port: p.port,
        protocol: p.protocol,
        service: p.service_name || '',
        product: p.service_product || '',
        version: p.service_version || '',
        state: p.state,
        is_risky: p.is_risky ? 'Yes' : 'No',
        risk_reason: p.risk_reason || '',
        discovered_by: p.discovered_by || '',
        last_seen: p.last_seen,
      })),
      'ports'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  const filteredPorts = ports.filter(
    (p) =>
      (p.hostname?.toLowerCase() || '').includes(search.toLowerCase()) ||
      (p.ip_address || '').includes(search) ||
      (p.asset_value || '').toLowerCase().includes(search.toLowerCase()) ||
      p.port?.toString().includes(search) ||
      (p.service_name?.toLowerCase() || '').includes(search.toLowerCase())
  );

  const getStateColor = (state: string) => {
    switch (state?.toLowerCase()) {
      case 'open':
        return 'bg-green-500/20 text-green-400';
      case 'closed':
        return 'bg-red-500/20 text-red-400';
      case 'filtered':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getServiceColor = (port: number) => {
    const criticalPorts = [21, 22, 23, 25, 53, 110, 143, 445, 3389, 5900];
    const webPorts = [80, 443, 8080, 8443];
    const dbPorts = [3306, 5432, 27017, 6379, 1433];

    if (criticalPorts.includes(port)) return 'border-red-500/30 bg-red-500/10';
    if (webPorts.includes(port)) return 'border-blue-500/30 bg-blue-500/10';
    if (dbPorts.includes(port)) return 'border-yellow-500/30 bg-yellow-500/10';
    return '';
  };

  return (
    <MainLayout>
      <Header title="Ports" subtitle="Open ports and services discovered across assets" />

      <div className="p-6">
        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 mb-6 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by host, IP, port, or service..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="flex items-center gap-2">
            <Select value={orgFilter} onValueChange={setOrgFilter}>
              <SelectTrigger className="w-[200px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Organization" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Organizations</SelectItem>
                {organizations.map((org) => (
                  <SelectItem key={org.id} value={org.id.toString()}>
                    {org.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Port Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Network className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{ports.filter((p) => p.state?.toUpperCase() === 'OPEN').length}</p>
                <p className="text-sm text-muted-foreground">Open Ports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Network className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {new Set(ports.map((p) => p.asset_value || p.hostname || p.ip_address)).size}
                </p>
                <p className="text-sm text-muted-foreground">Unique Hosts</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Network className="h-5 w-5 text-yellow-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {new Set(ports.map((p) => p.service_name).filter(Boolean)).size}
                </p>
                <p className="text-sm text-muted-foreground">Services</p>
              </div>
            </div>
          </Card>
          <Card 
            className={`p-4 cursor-pointer hover:border-red-500/40 transition-colors ${riskyFilter === 'risky' ? 'ring-2 ring-red-500' : ''}`}
            onClick={() => setRiskyFilter(riskyFilter === 'risky' ? 'all' : 'risky')}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <AlertTriangle className="h-5 w-5 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => p.is_risky).length}
                </p>
                <p className="text-sm text-muted-foreground">Risky Ports</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Network className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => [21, 22, 23, 3389, 5900, 3306, 5432, 27017, 6379].includes(p.port)).length}
                </p>
                <p className="text-sm text-muted-foreground">Critical Ports</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Ports Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Product / Version</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead className="w-[60px]">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : filteredPorts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                    No port scan results found. Run a port scan to discover services.
                  </TableCell>
                </TableRow>
              ) : (
                filteredPorts.map((port) => (
                  <TableRow key={port.id} className={getServiceColor(port.port)}>
                    <TableCell className="font-medium">
                      <div className="flex flex-col">
                        <span>{port.hostname || port.asset_value || port.ip_address || '-'}</span>
                        {port.hostname && port.ip_address && port.hostname !== port.ip_address && (
                          <span className="text-xs text-muted-foreground font-mono">{port.ip_address}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {port.port}
                      </Badge>
                    </TableCell>
                    <TableCell className="uppercase text-xs">{port.protocol}</TableCell>
                    <TableCell>{port.service_name || '-'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                      {port.service_product || port.service_version 
                        ? `${port.service_product || ''} ${port.service_version || ''}`.trim()
                        : '-'}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStateColor(port.state)}>{port.state}</Badge>
                    </TableCell>
                    <TableCell>
                      {port.is_risky ? (
                        <Badge className="bg-red-500/20 text-red-400" title={port.risk_reason}>
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          Risky
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(port.last_seen)}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'critical')}>
                            <Bug className="h-4 w-4 mr-2 text-red-500" />
                            Create Critical Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'high')}>
                            <Bug className="h-4 w-4 mr-2 text-orange-500" />
                            Create High Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCreateFinding(port.id, 'medium')}>
                            <Bug className="h-4 w-4 mr-2 text-yellow-500" />
                            Create Medium Finding
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleMarkRisky(port.id)}>
                            <Flag className="h-4 w-4 mr-2 text-red-500" />
                            Mark as Risky
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
          <span>Showing {filteredPorts.length} ports</span>
        </div>
      </div>
    </MainLayout>
  );
}














