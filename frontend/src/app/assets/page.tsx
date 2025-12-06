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
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Globe,
  Search,
  Download,
  Columns,
  Filter,
  Loader2,
  ExternalLink,
  MoreHorizontal,
  Camera,
  Shield,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';
import Link from 'next/link';

interface Asset {
  id: number;
  hostname: string;
  ip_address?: string;
  asset_type: string;
  status: string;
  organization_id: number;
  organization_name?: string;
  http_status?: number;
  technologies?: string[];
  created_at: string;
}

interface Column {
  key: string;
  label: string;
  visible: boolean;
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const [organizations, setOrganizations] = useState<any[]>([]);
  const { toast } = useToast();

  const [columns, setColumns] = useState<Column[]>([
    { key: 'hostname', label: 'Hostname', visible: true },
    { key: 'ip_address', label: 'IP Address', visible: true },
    { key: 'asset_type', label: 'Type', visible: true },
    { key: 'status', label: 'Status', visible: true },
    { key: 'http_status', label: 'HTTP Status', visible: true },
    { key: 'technologies', label: 'Technologies', visible: true },
    { key: 'organization', label: 'Organization', visible: true },
    { key: 'created_at', label: 'Discovered', visible: true },
  ]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [assetsData, orgsData] = await Promise.all([
        api.getAssets({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          search: search || undefined,
          limit: 100,
        }),
        api.getOrganizations(),
      ]);

      setAssets(assetsData.items || assetsData || []);
      setOrganizations(orgsData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch assets',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [orgFilter]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (search !== '') {
        fetchData();
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [search]);

  const handleExport = () => {
    downloadCSV(
      assets.map((a) => ({
        hostname: a.hostname,
        ip_address: a.ip_address || '',
        type: a.asset_type,
        status: a.status,
        http_status: a.http_status || '',
        created_at: a.created_at,
      })),
      'assets'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  const toggleColumn = (key: string) => {
    setColumns(columns.map((col) => (col.key === key ? { ...col, visible: !col.visible } : col)));
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'active':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'inactive':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      case 'error':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  return (
    <MainLayout>
      <Header title="Assets" subtitle="Discovered hosts, domains, and services" />

      <div className="p-6">
        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 mb-6 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search assets..."
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

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Columns className="h-4 w-4 mr-2" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel>Toggle Columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {columns.map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.key}
                    checked={column.visible}
                    onCheckedChange={() => toggleColumn(column.key)}
                  >
                    {column.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>

            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Assets Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                {columns.find((c) => c.key === 'hostname')?.visible && (
                  <TableHead>Hostname</TableHead>
                )}
                {columns.find((c) => c.key === 'ip_address')?.visible && (
                  <TableHead>IP Address</TableHead>
                )}
                {columns.find((c) => c.key === 'asset_type')?.visible && <TableHead>Type</TableHead>}
                {columns.find((c) => c.key === 'status')?.visible && <TableHead>Status</TableHead>}
                {columns.find((c) => c.key === 'http_status')?.visible && (
                  <TableHead>HTTP</TableHead>
                )}
                {columns.find((c) => c.key === 'technologies')?.visible && (
                  <TableHead>Technologies</TableHead>
                )}
                {columns.find((c) => c.key === 'organization')?.visible && (
                  <TableHead>Organization</TableHead>
                )}
                {columns.find((c) => c.key === 'created_at')?.visible && (
                  <TableHead>Discovered</TableHead>
                )}
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : assets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                    No assets found. Run a discovery scan to find assets.
                  </TableCell>
                </TableRow>
              ) : (
                assets.map((asset) => (
                  <TableRow key={asset.id}>
                    {columns.find((c) => c.key === 'hostname')?.visible && (
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Globe className="h-4 w-4 text-muted-foreground" />
                          <a
                            href={`https://${asset.hostname}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-medium hover:text-primary flex items-center gap-1"
                          >
                            {asset.hostname}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'ip_address')?.visible && (
                      <TableCell className="font-mono text-sm">
                        {asset.ip_address || '-'}
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'asset_type')?.visible && (
                      <TableCell>
                        <Badge variant="outline">{asset.asset_type || 'domain'}</Badge>
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'status')?.visible && (
                      <TableCell>
                        <Badge className={getStatusColor(asset.status)}>{asset.status}</Badge>
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'http_status')?.visible && (
                      <TableCell>
                        {asset.http_status ? (
                          <Badge
                            variant="outline"
                            className={
                              asset.http_status >= 200 && asset.http_status < 300
                                ? 'text-green-400'
                                : asset.http_status >= 400
                                ? 'text-red-400'
                                : 'text-yellow-400'
                            }
                          >
                            {asset.http_status}
                          </Badge>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'technologies')?.visible && (
                      <TableCell>
                        <div className="flex flex-wrap gap-1 max-w-[200px]">
                          {asset.technologies?.slice(0, 3).map((tech) => (
                            <Badge key={tech} variant="secondary" className="text-xs">
                              {tech}
                            </Badge>
                          ))}
                          {(asset.technologies?.length || 0) > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{asset.technologies!.length - 3}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'organization')?.visible && (
                      <TableCell className="text-muted-foreground">
                        {asset.organization_name || '-'}
                      </TableCell>
                    )}
                    {columns.find((c) => c.key === 'created_at')?.visible && (
                      <TableCell className="text-muted-foreground text-sm">
                        {formatDate(asset.created_at)}
                      </TableCell>
                    )}
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem asChild>
                            <Link href={`/assets/${asset.id}`}>View Details</Link>
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Camera className="h-4 w-4 mr-2" />
                            Capture Screenshot
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Shield className="h-4 w-4 mr-2" />
                            Run Vulnerability Scan
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

        {/* Pagination info */}
        <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
          <span>Showing {assets.length} assets</span>
        </div>
      </div>
    </MainLayout>
  );
}

