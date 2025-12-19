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
  RefreshCw,
  Loader2,
  Globe,
  Server,
  Shield,
  AlertTriangle,
  MapPin,
  Network,
  Clock,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  ExternalLink,
  Copy,
  CheckCircle,
  XCircle,
  Cpu,
  Database,
  Wifi,
  AlertCircle,
  Tag,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Technology {
  name: string;
  slug: string;
  categories: string[];
  version?: string;
}

interface PortService {
  id: number;
  port: number;
  protocol: string;
  service?: string;
  product?: string;
  version?: string;
  state: string;
  is_ssl: boolean;
  is_risky: boolean;
  port_string: string;
}

interface Asset {
  id: number;
  name: string;
  asset_type: string;
  value: string;
  organization_id: number;
  parent_id?: number;
  status: string;
  description?: string;
  tags: string[];
  metadata_: Record<string, any>;
  discovery_source?: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  criticality: string;
  is_monitored: boolean;
  http_status?: number;
  http_title?: string;
  dns_records: Record<string, any>;
  ip_address?: string;
  latitude?: string;
  longitude?: string;
  city?: string;
  country?: string;
  country_code?: string;
  isp?: string;
  in_scope: boolean;
  is_owned: boolean;
  netblock_id?: number;
  asn?: string;
  technologies: Technology[];
  port_services: PortService[];
  open_ports_count: number;
  risky_ports_count: number;
  created_at: string;
  updated_at: string;
}

const assetTypeIcons: Record<string, any> = {
  domain: Globe,
  subdomain: Globe,
  ip_address: Server,
  url: ExternalLink,
  port: Network,
  service: Cpu,
  certificate: Lock,
  api_endpoint: Database,
};

const assetTypeColors: Record<string, string> = {
  domain: 'text-blue-400',
  subdomain: 'text-cyan-400',
  ip_address: 'text-green-400',
  url: 'text-purple-400',
  port: 'text-orange-400',
  service: 'text-yellow-400',
  certificate: 'text-pink-400',
  api_endpoint: 'text-indigo-400',
};

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;
  const [asset, setAsset] = useState<Asset | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const fetchAsset = async () => {
    try {
      const data = await api.getAsset(parseInt(assetId));
      setAsset(data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch asset details',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAsset();
  }, [assetId]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAsset();
  };

  const handleCopyValue = () => {
    if (asset?.value) {
      navigator.clipboard.writeText(asset.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({ title: 'Copied to clipboard' });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'verified':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'discovered':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'unverified':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'inactive':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      case 'archived':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    if (score >= 20) return 'text-blue-500';
    return 'text-green-500';
  };

  const getCriticalityColor = (criticality: string) => {
    switch (criticality?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getHttpStatusColor = (status?: number) => {
    if (!status) return 'text-gray-400';
    if (status >= 200 && status < 300) return 'text-green-400';
    if (status >= 300 && status < 400) return 'text-blue-400';
    if (status >= 400 && status < 500) return 'text-yellow-400';
    if (status >= 500) return 'text-red-400';
    return 'text-gray-400';
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

  if (!asset) {
    return (
      <MainLayout>
        <div className="flex flex-col items-center justify-center h-96 gap-4">
          <AlertTriangle className="h-12 w-12 text-muted-foreground" />
          <p className="text-muted-foreground">Asset not found</p>
          <Button variant="outline" onClick={() => router.push('/assets')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Assets
          </Button>
        </div>
      </MainLayout>
    );
  }

  const AssetIcon = assetTypeIcons[asset.asset_type] || Globe;
  const iconColor = assetTypeColors[asset.asset_type] || 'text-gray-400';

  return (
    <MainLayout>
      <Header 
        title={asset.name} 
        subtitle={`${asset.asset_type?.replace(/_/g, ' ')} asset`} 
      />

      <div className="p-6 space-y-6">
        {/* Navigation and Actions */}
        <div className="flex items-center justify-between">
          <Button variant="outline" onClick={() => router.push('/assets')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Assets
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleCopyValue}>
              {copied ? <CheckCircle className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
              {copied ? 'Copied!' : 'Copy Value'}
            </Button>
            <Button variant="outline" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Main Info Card */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-start gap-4">
              <div className={`p-3 rounded-lg bg-secondary ${iconColor}`}>
                <AssetIcon className="h-8 w-8" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h2 className="text-xl font-mono font-bold">{asset.value}</h2>
                  {asset.value.startsWith('http') && (
                    <a href={asset.value} target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="h-4 w-4 text-muted-foreground hover:text-primary" />
                    </a>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge className={getStatusColor(asset.status)}>
                    {asset.status?.toUpperCase()}
                  </Badge>
                  <Badge className={getCriticalityColor(asset.criticality)}>
                    {asset.criticality?.toUpperCase()} CRITICALITY
                  </Badge>
                  <Badge variant="outline">
                    {asset.asset_type?.replace(/_/g, ' ').toUpperCase()}
                  </Badge>
                  {asset.is_monitored ? (
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                      <Eye className="h-3 w-3 mr-1" /> Monitored
                    </Badge>
                  ) : (
                    <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">
                      <EyeOff className="h-3 w-3 mr-1" /> Not Monitored
                    </Badge>
                  )}
                  {asset.in_scope ? (
                    <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                      In Scope
                    </Badge>
                  ) : (
                    <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">
                      Out of Scope
                    </Badge>
                  )}
                </div>
                {asset.description && (
                  <p className="text-muted-foreground mt-3">{asset.description}</p>
                )}
              </div>
              <div className="text-right">
                <div className={`text-4xl font-bold ${getRiskColor(asset.risk_score)}`}>
                  {asset.risk_score}
                </div>
                <div className="text-sm text-muted-foreground">Risk Score</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Network className="h-8 w-8 text-blue-400" />
                <div>
                  <p className="text-2xl font-bold">{asset.open_ports_count || 0}</p>
                  <p className="text-sm text-muted-foreground">Open Ports</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <AlertCircle className="h-8 w-8 text-red-400" />
                <div>
                  <p className="text-2xl font-bold">{asset.risky_ports_count || 0}</p>
                  <p className="text-sm text-muted-foreground">Risky Ports</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Cpu className="h-8 w-8 text-purple-400" />
                <div>
                  <p className="text-2xl font-bold">{asset.technologies?.length || 0}</p>
                  <p className="text-sm text-muted-foreground">Technologies</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <Clock className="h-8 w-8 text-green-400" />
                <div>
                  <p className="text-sm font-medium">{formatDate(asset.last_seen)}</p>
                  <p className="text-sm text-muted-foreground">Last Seen</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Asset Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Asset Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Discovery Source</span>
                <span className="font-medium">{asset.discovery_source || '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">First Seen</span>
                <span className="text-sm">{formatDate(asset.first_seen)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Last Seen</span>
                <span className="text-sm">{formatDate(asset.last_seen)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Created</span>
                <span className="text-sm">{formatDate(asset.created_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Updated</span>
                <span className="text-sm">{formatDate(asset.updated_at)}</span>
              </div>
              {asset.http_status && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">HTTP Status</span>
                  <span className={`font-mono ${getHttpStatusColor(asset.http_status)}`}>
                    {asset.http_status}
                  </span>
                </div>
              )}
              {asset.http_title && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">HTTP Title</span>
                  <span className="text-sm truncate max-w-[200px]">{asset.http_title}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Network/Location Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <MapPin className="h-5 w-5" />
                Network & Location
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {asset.ip_address && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">IP Address</span>
                  <span className="font-mono">{asset.ip_address}</span>
                </div>
              )}
              {asset.asn && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ASN</span>
                  <span className="font-mono">{asset.asn}</span>
                </div>
              )}
              {asset.isp && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ISP</span>
                  <span className="text-sm">{asset.isp}</span>
                </div>
              )}
              {(asset.city || asset.country) && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Location</span>
                  <span className="text-sm">
                    {[asset.city, asset.country].filter(Boolean).join(', ')}
                    {asset.country_code && ` (${asset.country_code})`}
                  </span>
                </div>
              )}
              {(asset.latitude && asset.longitude) && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Coordinates</span>
                  <span className="font-mono text-xs">
                    {asset.latitude}, {asset.longitude}
                  </span>
                </div>
              )}
              {!asset.ip_address && !asset.asn && !asset.isp && !asset.city && !asset.country && (
                <p className="text-muted-foreground text-sm">No network information available</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Tags */}
        {asset.tags && asset.tags.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Tag className="h-5 w-5" />
                Tags ({asset.tags.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {asset.tags.map((tag, index) => (
                  <Badge key={index} variant="secondary">
                    {tag}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Technologies */}
        {asset.technologies && asset.technologies.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Cpu className="h-5 w-5" />
                Technologies ({asset.technologies.length})
              </CardTitle>
              <CardDescription>
                Detected technologies and frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {asset.technologies.map((tech, index) => (
                  <Badge key={index} variant="outline" className="py-1.5">
                    <span className="font-medium">{tech.name}</span>
                    {tech.version && (
                      <span className="text-muted-foreground ml-1">v{tech.version}</span>
                    )}
                    {tech.categories?.length > 0 && (
                      <span className="text-xs text-muted-foreground ml-2">
                        ({tech.categories.join(', ')})
                      </span>
                    )}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Port Services */}
        {asset.port_services && asset.port_services.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Network className="h-5 w-5" />
                Open Ports ({asset.port_services.length})
              </CardTitle>
              <CardDescription>
                Discovered network services
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead>Product</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {asset.port_services.map((port) => (
                    <TableRow key={port.id}>
                      <TableCell className="font-mono font-bold">{port.port}</TableCell>
                      <TableCell className="uppercase text-muted-foreground">{port.protocol}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {port.service || '—'}
                          {port.is_ssl && (
                            <span title="SSL/TLS">
                              <Lock className="h-3 w-3 text-green-400" />
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>{port.product || '—'}</TableCell>
                      <TableCell className="font-mono text-sm">{port.version || '—'}</TableCell>
                      <TableCell>
                        <Badge 
                          className={port.state === 'open' 
                            ? 'bg-green-500/20 text-green-400' 
                            : 'bg-yellow-500/20 text-yellow-400'}
                        >
                          {port.state}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {port.is_risky ? (
                          <Badge className="bg-red-500/20 text-red-400">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Risky
                          </Badge>
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

        {/* DNS Records */}
        {asset.dns_records && Object.keys(asset.dns_records).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Globe className="h-5 w-5" />
                DNS Records
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {Object.entries(asset.dns_records).map(([recordType, records]) => (
                  <div key={recordType}>
                    <span className="text-sm font-medium text-muted-foreground uppercase">
                      {recordType}
                    </span>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {Array.isArray(records) ? (
                        records.map((record: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="font-mono">
                            {record}
                          </Badge>
                        ))
                      ) : (
                        <Badge variant="secondary" className="font-mono">
                          {String(records)}
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Metadata */}
        {asset.metadata_ && Object.keys(asset.metadata_).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Additional Metadata</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-secondary/50 p-4 rounded-lg overflow-x-auto text-sm">
                {JSON.stringify(asset.metadata_, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
