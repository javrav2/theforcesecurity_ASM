'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TableCustomization, Column, FilterOption } from '@/components/table/TableCustomization';
import {
  Globe,
  Server,
  Network,
  Lock,
  Layers,
  Award,
  ImageOff,
  Wifi,
  Hash,
  Tag,
  X,
  Plus,
  ArrowUpDown,
  Loader2,
  ExternalLink,
  MoreHorizontal,
  Camera,
  Shield,
  Eye,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  MapPin,
  Code,
  Zap,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';
import Link from 'next/link';

interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  ip_address?: string;
  asset_type: string;
  type?: string;
  status: string;
  organization_id: number;
  organization_name?: string;
  http_status?: number;
  technologies?: Array<{ name: string; slug: string; categories: string[] }>;
  tags?: string[];
  findingsCount?: number;
  screenshotUrl?: string;
  geoLocation?: GeoLocation;
  created_at: string;
  lastSeen?: Date;
  // Screenshots from API
  screenshots?: Array<{ id: number; image_path: string; thumbnail_path?: string }>;
  // Attack surface data
  is_live?: boolean;
  open_ports_count?: number;
  risky_ports_count?: number;
  port_services?: Array<{ port: number; protocol: string; service?: string; is_risky?: boolean }>;
  endpoints?: string[];
  parameters?: string[];
  js_files?: string[];
  discovery_source?: string;
  risk_score?: number;
  in_scope?: boolean;
  asn?: string;
  country?: string;
  city?: string;
}

// Asset type icons - matching AssetType enum values
const assetIcons: Record<string, typeof Globe> = {
  domain: Globe,
  subdomain: Globe,
  ip_address: Server,
  ip: Server,  // alias
  url: ExternalLink,
  port: Network,
  service: Layers,
  certificate: Lock,
  cloud_resource: Server,
  api_endpoint: Layers,
  email: Globe,
  other: Globe,
};

// Asset type colors - matching AssetType enum values
const assetColors: Record<string, string> = {
  domain: 'text-primary',
  subdomain: 'text-blue-400',
  ip_address: 'text-orange-400',
  ip: 'text-orange-400',  // alias
  url: 'text-cyan-400',
  port: 'text-purple-400',
  service: 'text-green-400',
  certificate: 'text-gray-400',
  cloud_resource: 'text-yellow-400',
  api_endpoint: 'text-pink-400',
  email: 'text-teal-400',
  other: 'text-gray-400',
};

export default function AssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [sortColumn, setSortColumn] = useState<string>('');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [selectedScreenshot, setSelectedScreenshot] = useState<{ url: string; asset: string } | null>(null);
  const [editingLabels, setEditingLabels] = useState<Asset | null>(null);
  const [newLabel, setNewLabel] = useState('');
  const { toast } = useToast();

  const [columns, setColumns] = useState<Column[]>([
    { key: 'screenshot', label: 'Screenshot', visible: true },
    { key: 'type', label: 'Type', visible: true },
    { key: 'hostname', label: 'Value', visible: true },
    { key: 'is_live', label: 'Live', visible: true },
    { key: 'http_status', label: 'HTTP', visible: true },
    { key: 'ports', label: 'Ports', visible: true },
    { key: 'technologies', label: 'Technologies', visible: true },
    { key: 'labels', label: 'Labels', visible: false },
    { key: 'ip_address', label: 'IP Address', visible: false },
    { key: 'status', label: 'Status', visible: false },
    { key: 'findings', label: 'Findings', visible: true },
    { key: 'endpoints', label: 'Endpoints', visible: false },
    { key: 'source', label: 'Source', visible: false },
    { key: 'location', label: 'Location', visible: false },
    { key: 'organization', label: 'Organization', visible: true },
    { key: 'created_at', label: 'Last Seen', visible: true },
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

      // Transform assets to include derived properties
      const assetsList = assetsData.items || assetsData || [];
      
      // Fetch screenshots for each asset in parallel (limit to first 20 to avoid too many requests)
      const assetsWithScreenshots = await Promise.all(
        assetsList.slice(0, 50).map(async (a: any) => {
          let screenshotUrl = null;
          let screenshotId = null;
          
          try {
            const screenshotData = await api.getAssetScreenshots(a.id);
            if (screenshotData.screenshots && screenshotData.screenshots.length > 0) {
              // Find the most recent successful screenshot
              const successfulScreenshot = screenshotData.screenshots.find((s: any) => s.status === 'success' && s.file_path);
              if (successfulScreenshot) {
                screenshotId = successfulScreenshot.id;
                screenshotUrl = api.getScreenshotImageUrl(successfulScreenshot.id);
              }
            }
          } catch (e) {
            // Ignore screenshot fetch errors
          }
          
          return {
            ...a,
            name: a.name || a.value,
            value: a.value || a.name,
            type: a.asset_type || 'subdomain',
            findingsCount: a.vulnerability_count || 0,
            tags: a.tags || [],
            lastSeen: new Date(a.updated_at || a.created_at),
            screenshotUrl,
            screenshotId,
          };
        })
      );
      
      // Add remaining assets without screenshots
      const remainingAssets = assetsList.slice(50).map((a: any) => ({
        ...a,
        name: a.name || a.value,
        value: a.value || a.name,
        type: a.asset_type || 'subdomain',
        findingsCount: a.vulnerability_count || 0,
        tags: a.tags || [],
        lastSeen: new Date(a.updated_at || a.created_at),
        screenshotUrl: null,
        screenshotId: null,
      }));

      setAssets([...assetsWithScreenshots, ...remainingAssets]);
      setOrganizations(orgsData);
    } catch (error: any) {
      console.error('Failed to fetch assets:', error);
      // Extract meaningful error message
      let errorMessage = 'Failed to fetch assets';
      const detail = error?.response?.data?.detail;
      if (typeof detail === 'string') {
        errorMessage = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        errorMessage = detail.map((e: any) => e.msg || e.message || String(e)).join(', ');
      } else if (error?.message) {
        errorMessage = error.message;
      }
      toast({
        title: 'Error',
        description: errorMessage,
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

  // Filter and sort assets
  const displayedAssets = useMemo(() => {
    let filtered = assets.filter(asset => {
      const matchesType = typeFilter === 'all' || asset.asset_type === typeFilter || asset.type === typeFilter;
      const matchesStatus = statusFilter === 'all' || asset.status === statusFilter;
      const matchesSearch = search === '' || 
        asset.name?.toLowerCase().includes(search.toLowerCase()) ||
        asset.value?.toLowerCase().includes(search.toLowerCase()) ||
        asset.ip_address?.toLowerCase().includes(search.toLowerCase()) ||
        asset.tags?.some(tag => tag.toLowerCase().includes(search.toLowerCase()));
      return matchesType && matchesStatus && matchesSearch;
    });

    // Sort assets
    if (sortColumn) {
      filtered = [...filtered].sort((a, b) => {
        const aVal: any = a[sortColumn as keyof Asset];
        const bVal: any = b[sortColumn as keyof Asset];
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return filtered;
  }, [assets, typeFilter, statusFilter, search, sortColumn, sortDirection]);

  const handleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const handleExport = () => {
    const csv = [
      ['Type', 'Value', 'IP Address', 'Labels', 'Status', 'Findings', 'Last Seen'],
      ...displayedAssets.map(a => [
        a.type || a.asset_type,
        a.name || a.value,
        a.ip_address || '',
        a.tags?.join('; ') || '',
        a.status,
        (a.findingsCount || 0).toString(),
        a.created_at,
      ]),
    ].map(row => row.join(',')).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `assets-${new Date().toISOString()}.csv`;
    link.click();
    
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  const handleAddLabel = async () => {
    if (!editingLabels || !newLabel.trim()) return;
    // In production, this would call an API to update the asset
    const updatedTags = [...(editingLabels.tags || []), newLabel.trim()];
    setAssets(assets.map(a => 
      a.id === editingLabels.id ? { ...a, tags: updatedTags } : a
    ));
    setNewLabel('');
    toast({
      title: 'Label Added',
      description: `Added label "${newLabel.trim()}" to ${editingLabels.name || editingLabels.value}`,
    });
  };

  const handleRemoveLabel = (label: string) => {
    if (!editingLabels) return;
    const updatedTags = (editingLabels.tags || []).filter(t => t !== label);
    setAssets(assets.map(a => 
      a.id === editingLabels.id ? { ...a, tags: updatedTags } : a
    ));
    setEditingLabels({ ...editingLabels, tags: updatedTags });
  };

  const handleFilterChange = (key: string, value: string) => {
    if (key === 'type') setTypeFilter(value);
    if (key === 'status') setStatusFilter(value);
    if (key === 'organization') setOrgFilter(value);
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      // AssetStatus enum values
      case 'discovered':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'verified':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'unverified':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'inactive':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      case 'archived':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
      // Legacy/scan status values (for backward compatibility)
      case 'active':
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'pending':
      case 'running':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'error':
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const filters: FilterOption[] = [
    {
      key: 'type',
      label: 'Type',
      options: [
        { label: 'Domain', value: 'domain' },
        { label: 'Subdomain', value: 'subdomain' },
        { label: 'IP Address', value: 'ip_address' },
        { label: 'URL', value: 'url' },
        { label: 'Port', value: 'port' },
        { label: 'Service', value: 'service' },
        { label: 'Certificate', value: 'certificate' },
        { label: 'API Endpoint', value: 'api_endpoint' },
      ],
    },
    {
      key: 'status',
      label: 'Status',
      options: [
        { label: 'Discovered', value: 'discovered' },
        { label: 'Verified', value: 'verified' },
        { label: 'Unverified', value: 'unverified' },
        { label: 'Inactive', value: 'inactive' },
        { label: 'Archived', value: 'archived' },
      ],
    },
  ];

  const visibleColumns = columns.filter(c => c.visible);

  // Calculate attack surface stats
  const attackSurfaceStats = useMemo(() => {
    const liveAssets = assets.filter(a => a.is_live).length;
    const totalPorts = assets.reduce((sum, a) => sum + (a.open_ports_count || 0), 0);
    const riskyPorts = assets.reduce((sum, a) => sum + (a.risky_ports_count || 0), 0);
    const withTech = assets.filter(a => a.technologies && a.technologies.length > 0).length;
    const withEndpoints = assets.filter(a => a.endpoints && a.endpoints.length > 0).length;
    const withFindings = assets.filter(a => (a.findingsCount || 0) > 0).length;
    
    // Count unique technologies
    const techSet = new Set<string>();
    assets.forEach(a => {
      a.technologies?.forEach(t => techSet.add(typeof t === 'string' ? t : t.name));
    });
    
    return {
      total: assets.length,
      live: liveAssets,
      totalPorts,
      riskyPorts,
      withTech,
      uniqueTech: techSet.size,
      withEndpoints,
      withFindings,
    };
  }, [assets]);

  return (
    <MainLayout>
      <Header title="Attack Surface" subtitle="Discovered hosts, domains, and services across your organization" />

      <div className="p-6 space-y-6">
        {/* Attack Surface Overview Stats */}
        {!loading && assets.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <Card className="p-4 bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/20">
                  <Globe className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.total}</p>
                  <p className="text-xs text-muted-foreground">Total Assets</p>
                </div>
              </div>
            </Card>
            
            <Card className="p-4 bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-500/20">
                  <Activity className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.live}</p>
                  <p className="text-xs text-muted-foreground">Live Assets</p>
                </div>
              </div>
            </Card>
            
            <Card className="p-4 bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 border-cyan-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/20">
                  <Network className="h-5 w-5 text-cyan-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.totalPorts}</p>
                  <p className="text-xs text-muted-foreground">Open Ports</p>
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.riskyPorts > 0 && (
              <Card className="p-4 bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-500/20">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.riskyPorts}</p>
                    <p className="text-xs text-muted-foreground">Risky Ports</p>
                  </div>
                </div>
              </Card>
            )}
            
            <Card className="p-4 bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/20">
                  <Zap className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.uniqueTech}</p>
                  <p className="text-xs text-muted-foreground">Technologies</p>
                </div>
              </div>
            </Card>
            
            {attackSurfaceStats.withFindings > 0 && (
              <Card className="p-4 bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-orange-500/20">
                    <Shield className="h-5 w-5 text-orange-400" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-foreground">{attackSurfaceStats.withFindings}</p>
                    <p className="text-xs text-muted-foreground">With Findings</p>
                  </div>
                </div>
              </Card>
            )}
          </div>
        )}

        {/* Table with Customization */}
        <TableCustomization
          columns={columns}
          onColumnVisibilityChange={setColumns}
          onExport={handleExport}
          onSort={handleSort}
          onSearch={setSearch}
          onRefresh={fetchData}
          isLoading={loading}
          filters={filters}
          onFilterChange={handleFilterChange}
        >
          <Card className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  {visibleColumns.map(col => (
                    <TableHead 
                      key={col.key} 
                      className="text-muted-foreground cursor-pointer"
                      onClick={() => col.key !== 'screenshot' && handleSort(col.key)}
                    >
                      <div className="flex items-center gap-1">
                        {col.label}
                        {col.key !== 'screenshot' && col.key !== 'labels' && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </div>
                    </TableHead>
                  ))}
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={visibleColumns.length + 1} className="text-center py-8">
                      <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                    </TableCell>
                  </TableRow>
                ) : displayedAssets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={visibleColumns.length + 1} className="text-center py-8 text-muted-foreground">
                      No assets found. Run a discovery scan to find assets.
                    </TableCell>
                  </TableRow>
                ) : (
                  displayedAssets.map((asset) => {
                    const assetType = asset.type || asset.asset_type || 'domain';
                    const Icon = assetIcons[assetType] || Globe;

                    return (
                      <TableRow 
                        key={asset.id} 
                        className="border-border cursor-pointer transition-colors hover:bg-secondary/50"
                        onClick={() => router.push(`/assets/${asset.id}`)}
                      >
                        {/* Screenshot */}
                        {columns.find(c => c.key === 'screenshot')?.visible && (
                          <TableCell>
                            {asset.screenshotUrl ? (
                                <div
                                  className="relative w-16 h-12 rounded overflow-hidden border border-border cursor-pointer hover:border-primary transition-colors group"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedScreenshot({ url: asset.screenshotUrl!, asset: asset.name || asset.value });
                                  }}
                                >
                                  <img
                                    src={asset.screenshotUrl}
                                    alt={`Screenshot of ${asset.name || asset.value}`}
                                    className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                                  />
                                <div className="absolute inset-0 bg-primary/0 group-hover:bg-primary/10 transition-colors flex items-center justify-center">
                                  <Eye className="h-4 w-4 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
                                </div>
                              </div>
                            ) : (
                              <div className="w-16 h-12 rounded border border-border/50 bg-secondary/30 flex items-center justify-center">
                                <ImageOff className="h-4 w-4 text-muted-foreground/50" />
                              </div>
                            )}
                          </TableCell>
                        )}

                        {/* Type */}
                        {columns.find(c => c.key === 'type')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Icon className={`h-4 w-4 ${assetColors[assetType] || 'text-muted-foreground'}`} />
                              <span className="text-xs font-medium uppercase text-muted-foreground">
                                {assetType}
                              </span>
                            </div>
                          </TableCell>
                        )}

                        {/* Value/Name */}
                        {columns.find(c => c.key === 'hostname')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {(() => {
                                const value = asset.value || asset.name;
                                // Build proper URL - don't double-add protocol
                                let href = value;
                                if (value && !value.startsWith('http://') && !value.startsWith('https://')) {
                                  href = `https://${value}`;
                                }
                                return (
                                  <a
                                    href={href}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-mono text-sm text-foreground hover:text-primary flex items-center gap-1"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {asset.name || asset.value}
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                );
                              })()}
                            </div>
                          </TableCell>
                        )}

                        {/* Live Status */}
                        {columns.find(c => c.key === 'is_live')?.visible && (
                          <TableCell>
                            {asset.is_live ? (
                              <div className="flex items-center gap-1">
                                <CheckCircle2 className="h-4 w-4 text-green-500" />
                                <span className="text-xs text-green-500 font-medium">Live</span>
                              </div>
                            ) : (
                              <div className="flex items-center gap-1">
                                <XCircle className="h-4 w-4 text-muted-foreground/50" />
                                <span className="text-xs text-muted-foreground">—</span>
                              </div>
                            )}
                          </TableCell>
                        )}

                        {/* Ports */}
                        {columns.find(c => c.key === 'ports')?.visible && (
                          <TableCell>
                            {(asset.open_ports_count || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Network className="h-4 w-4 text-blue-400" />
                                <span className="font-mono text-sm text-blue-400">
                                  {asset.open_ports_count}
                                </span>
                                {(asset.risky_ports_count || 0) > 0 && (
                                  <Badge variant="destructive" className="text-[10px] px-1 py-0 h-4">
                                    {asset.risky_ports_count} risky
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Technologies */}
                        {columns.find(c => c.key === 'technologies')?.visible && (
                          <TableCell>
                            {asset.technologies && asset.technologies.length > 0 ? (
                              <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                                {asset.technologies.slice(0, 3).map((tech, i) => (
                                  <Badge 
                                    key={i} 
                                    variant="outline" 
                                    className="text-[10px] px-1.5 py-0 h-5 bg-purple-500/10 text-purple-400 border-purple-500/30"
                                  >
                                    {typeof tech === 'string' ? tech : tech.name}
                                  </Badge>
                                ))}
                                {asset.technologies.length > 3 && (
                                  <Badge variant="outline" className="text-[10px] px-1 py-0 h-5">
                                    +{asset.technologies.length - 3}
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* IP Address */}
                        {columns.find(c => c.key === 'ip_address')?.visible && (
                          <TableCell className="font-mono text-sm">
                            {asset.ip_address || '—'}
                          </TableCell>
                        )}

                        {/* Labels */}
                        {columns.find(c => c.key === 'labels')?.visible && (
                          <TableCell>
                            <div className="flex items-center gap-1 flex-wrap">
                              {asset.tags && asset.tags.length > 0 ? (
                                <>
                                  {asset.tags.slice(0, 2).map((tag) => (
                                    <Badge key={tag} variant="secondary" className="text-xs">
                                      {tag}
                                    </Badge>
                                  ))}
                                  {asset.tags.length > 2 && (
                                    <Badge variant="secondary" className="text-xs">
                                      +{asset.tags.length - 2}
                                    </Badge>
                                  )}
                                </>
                              ) : (
                                <span className="text-muted-foreground text-xs">—</span>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-6 w-6 p-0"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setEditingLabels(asset);
                                }}
                              >
                                <Tag className="h-3 w-3" />
                              </Button>
                            </div>
                          </TableCell>
                        )}

                        {/* Status */}
                        {columns.find(c => c.key === 'status')?.visible && (
                          <TableCell>
                            <Badge className={getStatusColor(asset.status)}>
                              {asset.status}
                            </Badge>
                          </TableCell>
                        )}

                        {/* Findings */}
                        {columns.find(c => c.key === 'findings')?.visible && (
                          <TableCell>
                            {(asset.findingsCount || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Award className="h-4 w-4 text-orange-400" />
                                <span className="font-mono text-orange-400">
                                  {asset.findingsCount}
                                </span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* HTTP Status */}
                        {columns.find(c => c.key === 'http_status')?.visible && (
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
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Endpoints */}
                        {columns.find(c => c.key === 'endpoints')?.visible && (
                          <TableCell>
                            {(asset.endpoints?.length || 0) > 0 ? (
                              <div className="flex items-center gap-1">
                                <Code className="h-4 w-4 text-cyan-400" />
                                <span className="font-mono text-sm text-cyan-400">
                                  {asset.endpoints!.length}
                                </span>
                                {(asset.parameters?.length || 0) > 0 && (
                                  <span className="text-xs text-muted-foreground">
                                    ({asset.parameters!.length} params)
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Discovery Source */}
                        {columns.find(c => c.key === 'source')?.visible && (
                          <TableCell>
                            {asset.discovery_source ? (
                              <Badge variant="outline" className="text-xs">
                                {asset.discovery_source}
                              </Badge>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Location */}
                        {columns.find(c => c.key === 'location')?.visible && (
                          <TableCell>
                            {asset.country ? (
                              <div className="flex items-center gap-1">
                                <MapPin className="h-3 w-3 text-muted-foreground" />
                                <span className="text-xs">
                                  {asset.city ? `${asset.city}, ` : ''}{asset.country}
                                </span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        )}

                        {/* Organization */}
                        {columns.find(c => c.key === 'organization')?.visible && (
                          <TableCell className="text-muted-foreground">
                            {asset.organization_name || '—'}
                          </TableCell>
                        )}

                        {/* Last Seen */}
                        {columns.find(c => c.key === 'created_at')?.visible && (
                          <TableCell className="text-muted-foreground text-sm">
                            {formatDate(asset.created_at)}
                          </TableCell>
                        )}

                        {/* Actions */}
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" onClick={(e) => e.stopPropagation()}>
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
                              <DropdownMenuItem onClick={() => setEditingLabels(asset)}>
                                <Tag className="h-4 w-4 mr-2" />
                                Manage Labels
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </TableCustomization>

        {/* Pagination info */}
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>Showing {displayedAssets.length} of {assets.length} assets</span>
        </div>
      </div>

      {/* Screenshot Preview Dialog */}
      <Dialog open={!!selectedScreenshot} onOpenChange={() => setSelectedScreenshot(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm">{selectedScreenshot?.asset}</DialogTitle>
          </DialogHeader>
          {selectedScreenshot && (
            <div className="rounded-lg overflow-hidden border border-border">
              <img
                src={selectedScreenshot.url}
                alt={`Screenshot of ${selectedScreenshot.asset}`}
                className="w-full h-auto"
              />
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Label Management Dialog */}
      <Dialog open={!!editingLabels} onOpenChange={() => setEditingLabels(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Labels</DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {editingLabels?.name || editingLabels?.value}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Current Labels</Label>
              <div className="flex flex-wrap gap-2 min-h-[40px] p-2 border border-border rounded-md">
                {editingLabels?.tags && editingLabels.tags.length > 0 ? (
                  editingLabels.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="gap-1">
                      {tag}
                      <button
                        onClick={() => handleRemoveLabel(tag)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground text-sm">No labels</span>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Add New Label</Label>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., wordpress, drupal, citrix-netscaler"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      handleAddLabel();
                    }
                  }}
                />
                <Button onClick={handleAddLabel} size="sm" disabled={!newLabel.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Common labels: wordpress, drupal, citrix-netscaler, salesforce, joomla, magento
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
