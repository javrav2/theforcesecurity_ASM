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
import { Network, Search, Download, Loader2, Filter } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';

interface PortResult {
  id: number;
  asset_id: number;
  hostname: string;
  ip_address: string;
  port: number;
  protocol: string;
  service?: string;
  version?: string;
  state: string;
  banner?: string;
  created_at: string;
}

export default function PortsPage() {
  const [ports, setPorts] = useState<PortResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [portsData, orgsData] = await Promise.all([
        api.getPorts({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          limit: 100,
        }),
        api.getOrganizations(),
      ]);

      setPorts(portsData.items || portsData || []);
      setOrganizations(orgsData);
    } catch (error) {
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
  }, [orgFilter]);

  const handleExport = () => {
    downloadCSV(
      ports.map((p) => ({
        hostname: p.hostname,
        ip_address: p.ip_address,
        port: p.port,
        protocol: p.protocol,
        service: p.service || '',
        version: p.version || '',
        state: p.state,
        created_at: p.created_at,
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
      p.hostname?.toLowerCase().includes(search.toLowerCase()) ||
      p.ip_address?.includes(search) ||
      p.port?.toString().includes(search) ||
      p.service?.toLowerCase().includes(search.toLowerCase())
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
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Network className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{ports.filter((p) => p.state === 'open').length}</p>
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
                  {new Set(ports.map((p) => p.hostname)).size}
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
                  {new Set(ports.map((p) => p.service).filter(Boolean)).size}
                </p>
                <p className="text-sm text-muted-foreground">Services</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <Network className="h-5 w-5 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {ports.filter((p) => [21, 22, 23, 3389, 5900].includes(p.port)).length}
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
                <TableHead>IP Address</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Discovered</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : filteredPorts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    No port scan results found. Run a port scan to discover services.
                  </TableCell>
                </TableRow>
              ) : (
                filteredPorts.map((port) => (
                  <TableRow key={port.id} className={getServiceColor(port.port)}>
                    <TableCell className="font-medium">{port.hostname}</TableCell>
                    <TableCell className="font-mono text-sm">{port.ip_address}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {port.port}
                      </Badge>
                    </TableCell>
                    <TableCell className="uppercase text-xs">{port.protocol}</TableCell>
                    <TableCell>{port.service || '-'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                      {port.version || '-'}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStateColor(port.state)}>{port.state}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(port.created_at)}
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














