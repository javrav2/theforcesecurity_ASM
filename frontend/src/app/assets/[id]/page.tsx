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
  ExternalLink,
  Copy,
  CheckCircle,
  Cpu,
  AlertCircle,
  Tag,
  Camera,
  ImageIcon,
  Activity,
  FileText,
  Settings,
  Monitor,
  Wifi,
  Database,
  Calendar,
  Hash,
  Mail,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import { ApplicationMap } from '@/components/assets/ApplicationMap';
import { DiscoveryPath } from '@/components/assets/DiscoveryPath';

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

interface DiscoveryStep {
  step: number;
  source: string;
  match_type?: string;
  match_value?: string;
  query_domain?: string;
  timestamp?: string;
  confidence?: number;
}

interface Screenshot {
  id: number;
  url: string;
  status: string;
  file_path?: string;
  thumbnail_path?: string;
  http_status?: number;
  page_title?: string;
  captured_at: string;
  has_changed?: boolean;
  change_percentage?: number;
}

interface Vulnerability {
  id: number;
  title: string;
  name?: string;
  description?: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  references?: string[];
  asset_id: number;
  scan_id?: number;
  detected_by?: string;
  template_id?: string;
  matcher_name?: string;
  status: string;
  assigned_to?: string;
  evidence?: string;
  proof_of_concept?: string;
  remediation?: string;
  remediation_deadline?: string;
  first_detected: string;
  last_detected: string;
  resolved_at?: string;
  tags?: string[];
  host?: string;
  matched_at?: string;
}

interface Asset {
  id: number;
  name: string;
  asset_type: string;
  value: string;
  root_domain?: string;
  live_url?: string;
  organization_id: number;
  parent_id?: number;
  status: string;
  description?: string;
  tags: string[];
  metadata_: Record<string, any>;
  discovery_source?: string;
  discovery_chain?: DiscoveryStep[];
  association_reason?: string;
  association_confidence?: number;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  criticality: string;
  is_monitored: boolean;
  is_live?: boolean;
  http_status?: number;
  http_title?: string;
  dns_records: Record<string, any>;
  ip_address?: string;
  ip_addresses?: string[];
  ip_history?: Array<{ip: string; first_seen: string; last_seen: string; removed_at?: string}>;
  latitude?: string;
  longitude?: string;
  city?: string;
  country?: string;
  country_code?: string;
  region?: string;
  isp?: string;
  in_scope: boolean;
  is_owned: boolean;
  netblock_id?: number;
  asn?: string;
  // Hosting classification (for IP assets)
  hosting_type?: string;  // owned, cloud, cdn, third_party, unknown
  hosting_provider?: string;  // azure, aws, gcp, cloudflare, etc.
  is_ephemeral_ip?: boolean;  // True if IP could change
  resolved_from?: string;  // Domain this IP was resolved from
  technologies: Technology[];
  port_services: PortService[];
  open_ports_count: number;
  risky_ports_count: number;
  created_at: string;
  updated_at: string;
  // Risk and Criticality scores
  acs_score?: number;
  acs_drivers?: Record<string, any>;
  ars_score?: number;
  system_type?: string;
  operating_system?: string;
  device_class?: string;
  device_subclass?: string;
  is_public?: boolean;
  is_licensed?: boolean;
  last_scan_id?: string;
  last_scan_name?: string;
  last_scan_date?: string;
  last_scan_target?: string;
  last_authenticated_scan_status?: string;
  vulnerability_count?: number;
  critical_vuln_count?: number;
  high_vuln_count?: number;
  medium_vuln_count?: number;
  low_vuln_count?: number;
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

const TABS = [
  { id: 'details', label: 'Details', icon: FileText },
  { id: 'findings', label: 'Findings', icon: Shield },
  { id: 'ports', label: 'Open Ports', icon: Network },
  { id: 'activity', label: 'Activity', icon: Activity },
  { id: 'mitigations', label: 'Mitigations', icon: Settings },
];

export default function AssetDetailPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;
  const [asset, setAsset] = useState<Asset | null>(null);
  const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [activeTab, setActiveTab] = useState('details');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [capturingScreenshot, setCapturingScreenshot] = useState(false);
  const { toast } = useToast();

  const fetchAsset = async () => {
    try {
      const [assetData, screenshotData, vulnData] = await Promise.all([
        api.getAsset(parseInt(assetId)),
        api.getAssetScreenshots(parseInt(assetId)).catch(() => ({ screenshots: [] })),
        api.getVulnerabilitiesForAsset(parseInt(assetId), { limit: 50 }).catch(() => [])
      ]);
      setAsset(assetData);
      setScreenshots(screenshotData.screenshots || []);
      
      // Sort vulnerabilities by severity: critical, high, medium, low, info
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const sortedVulns = (Array.isArray(vulnData) ? vulnData : []).sort((a: Vulnerability, b: Vulnerability) => {
        const orderA = severityOrder[a.severity?.toLowerCase()] ?? 5;
        const orderB = severityOrder[b.severity?.toLowerCase()] ?? 5;
        return orderA - orderB;
      });
      setVulnerabilities(sortedVulns);
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

  const handleCaptureScreenshot = async () => {
    if (!asset) return;
    
    setCapturingScreenshot(true);
    try {
      await api.captureScreenshot(asset.id);
      toast({ title: 'Screenshot captured successfully' });
      fetchAsset();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to capture screenshot',
        variant: 'destructive',
      });
    } finally {
      setCapturingScreenshot(false);
    }
  };

  useEffect(() => {
    fetchAsset();
  }, [assetId]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAsset();
  };

  const handleCopyValue = (value: string) => {
    navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({ title: 'Copied to clipboard' });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-green-500 text-white';
      case 'info': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getVulnStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'open': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'in_progress': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'resolved': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const formatVulnAge = (firstDetected: string) => {
    const start = new Date(firstDetected);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return '1 day';
    if (diffDays < 30) return `${diffDays} days`;
    return `${Math.floor(diffDays / 30)} months`;
  };

  const getACSColor = (score: number) => {
    if (score >= 8) return 'text-red-500';
    if (score >= 6) return 'text-orange-500';
    if (score >= 4) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getARSColor = (score: number) => {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    if (score >= 20) return 'text-blue-500';
    return 'text-green-500';
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

  const AssetIcon = assetTypeIcons[asset.asset_type] || Monitor;
  const acsScore = asset.acs_score || 5;
  const arsScore = asset.ars_score || asset.risk_score || 0;
  const vulnCount = asset.vulnerability_count || vulnerabilities.length;

  return (
    <MainLayout>
      {/* Header with Asset Name and ID */}
      <div className="border-b bg-card">
        <div className="p-6">
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="icon" onClick={() => router.push('/assets')}>
                <ArrowLeft className="h-5 w-5" />
          </Button>
              <div className="flex items-center gap-3">
                <AssetIcon className="h-8 w-8 text-primary" />
                <div>
                  <h1 className="text-2xl font-bold font-mono">{asset.value}</h1>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <span>Asset ID: {asset.id}</span>
                    <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => handleCopyValue(String(asset.id))}>
                      <Copy className="h-3 w-3" />
            </Button>
                  </div>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="gap-1">
                <Database className="h-3 w-3" />
                Data Sources
              </Badge>
            <Button variant="outline" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

          {/* Score Cards */}
          <div className="grid grid-cols-4 gap-4 mt-6">
            {/* ARS Score - Asset Risk Score */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="text-sm text-muted-foreground mb-1">ARS</div>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-bold ${getARSColor(arsScore)}`}>
                    {arsScore}
                  </span>
                  <span className="text-muted-foreground">/100</span>
              </div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div 
                    className={`h-full rounded-full ${arsScore >= 80 ? 'bg-red-500' : arsScore >= 60 ? 'bg-orange-500' : arsScore >= 40 ? 'bg-yellow-500' : arsScore >= 20 ? 'bg-blue-500' : 'bg-green-500'}`}
                    style={{ width: `${arsScore}%` }}
                  />
            </div>
          </CardContent>
        </Card>

            {/* ACS Score - Asset Criticality Score */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-muted-foreground">ACS</span>
                  <Button variant="ghost" size="icon" className="h-5 w-5">
                    <Settings className="h-3 w-3" />
                  </Button>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className={`text-3xl font-bold ${getACSColor(acsScore)}`}>{acsScore}</span>
                  <span className="text-muted-foreground">/10</span>
                </div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div 
                    className={`h-full rounded-full ${acsScore >= 8 ? 'bg-red-500' : acsScore >= 6 ? 'bg-orange-500' : acsScore >= 4 ? 'bg-yellow-500' : 'bg-green-500'}`}
                    style={{ width: `${(acsScore / 10) * 100}%` }}
                  />
              </div>
            </CardContent>
          </Card>

            {/* Key Drivers */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="text-sm text-muted-foreground mb-2">Key Drivers</div>
                <div className="flex flex-wrap gap-1">
                  {asset.acs_drivers && Object.entries(asset.acs_drivers).slice(0, 2).map(([key, value]) => (
                    <Badge key={key} variant="secondary" className="text-xs">
                      {key}: {String(value).substring(0, 10)}...
                    </Badge>
                  ))}
                  {asset.device_class && (
                    <Badge variant="secondary" className="text-xs">{asset.device_class}</Badge>
                  )}
                  {asset.acs_drivers && Object.keys(asset.acs_drivers).length > 2 && (
                    <Badge variant="outline" className="text-xs">+{Object.keys(asset.acs_drivers).length - 2}</Badge>
                  )}
              </div>
            </CardContent>
          </Card>

            {/* Vulnerabilities Count */}
            <Card className="border-2">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-muted-foreground">Vulnerabilities</span>
                  <AlertCircle className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="text-3xl font-bold">{vulnCount}</div>
                <div className="h-2 bg-muted rounded-full mt-2 overflow-hidden">
                  <div className="h-full bg-primary rounded-full" style={{ width: vulnCount > 0 ? '100%' : '0%' }} />
              </div>
            </CardContent>
          </Card>
          </div>

          {/* Tab Navigation */}
          <div className="flex gap-1 mt-6 border-b">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id 
                    ? 'border-primary text-primary bg-primary/5' 
                    : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/50'
                }`}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
                </div>
              </div>
        </div>

      {/* Tab Content */}
      <div className="p-6 space-y-6">
        {/* Details Tab */}
        {activeTab === 'details' && (
          <>
            {/* Asset Information */}
        <Card>
          <CardHeader>
                <div className="flex items-center gap-2">
                  <Monitor className="h-5 w-5" />
                  <CardTitle>Asset</CardTitle>
                </div>
                <CardDescription>General information and properties</CardDescription>
          </CardHeader>
          <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">System Type</span>
                    <span className="font-medium">{asset.system_type || asset.asset_type?.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Operating System</span>
                    <span className="font-medium">{asset.operating_system || '—'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Public</span>
                    <span className="font-medium">{asset.is_public !== false ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">IPv4 Addresses</span>
                    <span className="font-mono text-sm">
                      {(asset.ip_addresses?.length ?? 0) > 0 
                        ? asset.ip_addresses!.join(', ') 
                        : asset.ip_address 
                          ? asset.ip_address 
                          : asset.asset_type === 'ip_address' 
                            ? asset.value 
                            : '—'}
                    </span>
                  </div>
                  {asset.acs_drivers && Object.keys(asset.acs_drivers).length > 0 && (
                    <div className="col-span-2 flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">ACS Key Drivers</span>
                      <span className="font-mono text-xs text-right max-w-md">
                        {Object.entries(asset.acs_drivers).map(([k, v]) => `${k}: ${v}`).join(', ')}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Device Class</span>
                    <span className="font-medium">{asset.device_class || '—'}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Device Subclasses</span>
                    <span className="font-medium">{asset.device_subclass || '—'}</span>
                  </div>
                </div>
          </CardContent>
        </Card>

            {/* Last Seen Information */}
          <Card>
            <CardHeader>
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  <CardTitle>Last Seen</CardTitle>
                </div>
                <CardDescription>General information and properties</CardDescription>
            </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Scan Name</span>
                    <span className="font-medium">{asset.last_scan_name || asset.discovery_source || '—'}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Scan ID</span>
                    <span className="font-mono text-xs">{asset.last_scan_id || '—'}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Seen</span>
                    <span className="font-medium">{formatDate(asset.last_seen)}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Licensed Scan</span>
                    <span className="font-medium">{asset.last_scan_date ? formatDate(asset.last_scan_date) : formatDate(asset.last_seen)}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b">
                <span className="text-muted-foreground">First Seen</span>
                    <span className="font-medium">{formatDate(asset.first_seen)}</span>
              </div>
                  <div className="flex justify-between py-2 border-b">
                    <span className="text-muted-foreground">Last Scan Target</span>
                    <span className="font-mono text-sm">{asset.last_scan_target || asset.value}</span>
              </div>
              </div>
              </CardContent>
            </Card>

            {/* Tags */}
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Tag className="h-5 w-5" />
                  <CardTitle>Tags</CardTitle>
              </div>
              </CardHeader>
              <CardContent>
                {asset.tags && asset.tags.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {asset.tags.map((tag, idx) => (
                      <Badge key={idx} variant="secondary">{tag}</Badge>
                    ))}
                </div>
                ) : (
                  <p className="text-muted-foreground text-sm">No tags assigned</p>
              )}
            </CardContent>
          </Card>

            {/* Network & Location */}
          <Card>
            <CardHeader>
                <div className="flex items-center gap-2">
                <MapPin className="h-5 w-5" />
                  <CardTitle>Network & Location</CardTitle>
                </div>
            </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  {/* Always show IP addresses - including for IP address type assets */}
                  {(() => {
                    // Determine which IPs to show
                    const ips: string[] = [];
                    if (asset.ip_addresses && asset.ip_addresses.length > 0) {
                      ips.push(...asset.ip_addresses);
                    } else if (asset.ip_address) {
                      ips.push(asset.ip_address);
                    } else if (asset.asset_type === 'ip_address' && asset.value) {
                      ips.push(asset.value);
                    }
                    
                    return ips.length > 0 ? (
                      <div className="col-span-2 flex justify-between py-2 border-b">
                        <span className="text-muted-foreground">IPv4 Address{ips.length > 1 ? 'es' : ''}</span>
                        <div className="flex flex-wrap gap-1 justify-end">
                          {ips.filter(Boolean).map((ip, idx) => (
                            <Badge key={idx} variant="outline" className="font-mono text-xs">{ip}</Badge>
                    ))}
                  </div>
                </div>
                    ) : null;
                  })()}
                  
                  {/* Show netblock link if asset is linked to a netblock */}
                  {asset.netblock_id && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Netblock</span>
                      <a href={`/netblocks/${asset.netblock_id}`} className="text-primary hover:underline font-mono text-sm">
                        View CIDR Block →
                      </a>
                </div>
                  )}
                  
              {asset.asn && (
                    <div className="flex justify-between py-2 border-b">
                  <span className="text-muted-foreground">ASN</span>
                  <span className="font-mono">{asset.asn}</span>
                </div>
              )}
              {asset.isp && (
                    <div className="flex justify-between py-2 border-b">
                  <span className="text-muted-foreground">ISP</span>
                      <span className="font-medium">{asset.isp}</span>
                </div>
              )}
                  {asset.city && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">City</span>
                      <span className="font-medium">{asset.city}</span>
                </div>
              )}
                  {asset.country && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Country</span>
                      <span className="font-medium">{asset.country} {asset.country_code && `(${asset.country_code})`}</span>
                </div>
              )}
                  {asset.region && (
                    <div className="flex justify-between py-2 border-b">
                      <span className="text-muted-foreground">Region</span>
                      <span className="font-medium">{asset.region}</span>
                    </div>
                  )}
                  
                  {/* Show message only if truly no network info and not an IP asset */}
                  {asset.asset_type !== 'ip_address' && 
                   !asset.ip_address && (!asset.ip_addresses || asset.ip_addresses.length === 0) && 
                   !asset.asn && !asset.isp && !asset.city && !asset.country && !asset.netblock_id && (
                    <div className="col-span-2 text-center py-4 text-muted-foreground">
                      No network information available. Run a discovery scan to populate this data.
                    </div>
              )}
                </div>
            </CardContent>
          </Card>

            {/* DNS Records */}
            {asset.asset_type === 'domain' && asset.metadata_?.dns_records && (
          <Card>
            <CardHeader>
                  <div className="flex items-center gap-2">
                    <Globe className="h-5 w-5" />
                    <CardTitle>DNS Records</CardTitle>
                  </div>
                  <CardDescription>
                    {asset.metadata_?.dns_fetched_at 
                      ? `Last fetched: ${formatDate(asset.metadata_.dns_fetched_at)}`
                      : 'DNS information for this domain'}
                  </CardDescription>
            </CardHeader>
                <CardContent className="space-y-4">
                  {/* Summary badges */}
                  {asset.metadata_?.dns_analysis && (
              <div className="flex flex-wrap gap-2">
                      {asset.metadata_.dns_summary?.has_mail && (
                        <Badge className="bg-blue-500/20 text-blue-600">
                          <Mail className="h-3 w-3 mr-1" />
                          {asset.metadata_.dns_summary?.mail_providers?.join(', ') || 'Email Enabled'}
                        </Badge>
                      )}
                      {asset.metadata_.dns_analysis?.uses_cdn && (
                        <Badge className="bg-purple-500/20 text-purple-600">
                          CDN: {asset.metadata_.dns_analysis.uses_cdn}
                        </Badge>
                      )}
                      {asset.metadata_.dns_analysis?.security_features?.map((feature: string) => (
                        <Badge key={feature} className="bg-green-500/20 text-green-600">
                          {feature}
                  </Badge>
                ))}
              </div>
                  )}
                  
                  {/* A Records */}
                  {asset.metadata_.dns_records?.A?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">A Records (IPv4)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.A.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono">
                            {record.address}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* AAAA Records */}
                  {asset.metadata_.dns_records?.AAAA?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">AAAA Records (IPv6)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.AAAA.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono text-xs">
                            {record.address}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* MX Records */}
                  {asset.metadata_.dns_records?.MX?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">MX Records (Mail)</h4>
                      <div className="space-y-1">
                        {asset.metadata_.dns_records.MX
                          .sort((a: any, b: any) => a.priority - b.priority)
                          .map((record: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-2 text-sm">
                            <span className="text-muted-foreground w-8">{record.priority}</span>
                            <span className="font-mono">{record.target}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* NS Records */}
                  {asset.metadata_.dns_records?.NS?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">NS Records (Nameservers)</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_records.NS.map((record: any, idx: number) => (
                          <Badge key={idx} variant="outline" className="font-mono">
                            {record.target}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* TXT Records */}
                  {asset.metadata_.dns_records?.TXT?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">TXT Records ({asset.metadata_.dns_records.TXT.length})</h4>
                      <div className="space-y-2 max-h-40 overflow-y-auto">
                        {asset.metadata_.dns_records.TXT.slice(0, 10).map((record: any, idx: number) => (
                          <div key={idx} className="p-2 bg-muted/50 rounded text-xs font-mono break-all">
                            {record.value?.substring(0, 100)}{record.value?.length > 100 ? '...' : ''}
                          </div>
                        ))}
                        {asset.metadata_.dns_records.TXT.length > 10 && (
                          <p className="text-xs text-muted-foreground">
                            +{asset.metadata_.dns_records.TXT.length - 10} more records
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                  
                  {/* TXT Verifications Summary */}
                  {asset.metadata_.dns_summary?.txt_verifications?.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium mb-2">Detected Services</h4>
                      <div className="flex flex-wrap gap-2">
                        {asset.metadata_.dns_summary.txt_verifications.map((svc: string, idx: number) => (
                          <Badge key={idx} variant="secondary" className="text-xs">
                            {svc}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
            </CardContent>
          </Card>
        )}

        {/* Technologies */}
        {asset.technologies && asset.technologies.length > 0 && (
          <Card>
            <CardHeader>
                  <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5" />
                    <CardTitle>Technologies ({asset.technologies.length})</CardTitle>
                  </div>
                  <CardDescription>Detected technologies and frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                    {asset.technologies.map((tech: Technology, idx: number) => (
                      <Badge key={idx} variant="outline" className="py-1.5">
                    <span className="font-medium">{tech.name}</span>
                        {tech.version && <span className="text-muted-foreground ml-1">v{tech.version}</span>}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

            {/* Screenshot */}
            {(asset.asset_type === 'domain' || asset.asset_type === 'subdomain' || asset.asset_type === 'url') && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Camera className="h-5 w-5" />
                      <CardTitle>Screenshot</CardTitle>
                    </div>
                    <Button variant="outline" size="sm" onClick={handleCaptureScreenshot} disabled={capturingScreenshot}>
                      {capturingScreenshot ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Camera className="h-4 w-4 mr-2" />}
                      {capturingScreenshot ? 'Capturing...' : 'Capture New'}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {screenshots.length > 0 ? (
                    <a href={api.getScreenshotImageUrl(screenshots[0].id)} target="_blank" rel="noopener noreferrer">
                      <img
                        src={api.getScreenshotImageUrl(screenshots[0].id)}
                        alt={`Screenshot of ${asset.value}`}
                        className="w-full max-h-96 object-contain rounded-lg border"
                      />
                    </a>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8">
                      <ImageIcon className="h-12 w-12 text-muted-foreground mb-3" />
                      <p className="text-muted-foreground">No screenshots captured yet</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Discovery Path */}
            <Card>
              <CardHeader>
                <CardTitle>How This Asset Was Discovered</CardTitle>
                <CardDescription>Visual path from source to this asset</CardDescription>
              </CardHeader>
              <CardContent>
                <DiscoveryPath
                  value={asset.value}
                  assetType={asset.asset_type}
                  rootDomain={asset.root_domain}
                  liveUrl={asset.live_url}
                  discoverySource={asset.discovery_source}
                  discoveryChain={asset.discovery_chain}
                  associationReason={asset.association_reason}
                  associationConfidence={asset.association_confidence}
                  hostingType={asset.hosting_type}
                  hostingProvider={asset.hosting_provider}
                  isEphemeralIp={asset.is_ephemeral_ip}
                  resolvedFrom={asset.resolved_from}
                />
              </CardContent>
            </Card>
          </>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Security Findings ({vulnerabilities.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerabilities.length > 0 ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Vulnerability List */}
                  <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
                    {vulnerabilities.map((vuln) => (
                      <div
                        key={vuln.id}
                        onClick={() => setSelectedVuln(vuln)}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          selectedVuln?.id === vuln.id ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge className={getSeverityColor(vuln.severity)}>{vuln.severity?.toUpperCase()}</Badge>
                              <Badge className={getVulnStatusColor(vuln.status)}>{vuln.status?.replace('_', ' ').toUpperCase()}</Badge>
                            </div>
                            <p className="font-medium text-sm truncate">{vuln.title || vuln.name || vuln.template_id}</p>
                            {vuln.template_id && <p className="text-xs text-muted-foreground font-mono mt-1">{vuln.template_id}</p>}
                          </div>
                          {vuln.cvss_score && (
                            <div className="text-right flex-shrink-0">
                              <div className={`text-lg font-bold ${vuln.cvss_score >= 9 ? 'text-red-500' : vuln.cvss_score >= 7 ? 'text-orange-500' : 'text-yellow-500'}`}>
                                {vuln.cvss_score}
                              </div>
                              <div className="text-xs text-muted-foreground">CVSS</div>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Vulnerability Detail */}
                  <div className="border rounded-lg p-4 bg-muted/20 max-h-[600px] overflow-y-auto">
                    {selectedVuln ? (
                      <div className="space-y-4">
                        <div>
                          <h3 className="font-semibold text-lg">{selectedVuln.title || selectedVuln.name}</h3>
                          <div className="flex flex-wrap gap-2 mt-2">
                            <Badge className={getSeverityColor(selectedVuln.severity)}>{selectedVuln.severity?.toUpperCase()}</Badge>
                            <Badge className={getVulnStatusColor(selectedVuln.status)}>{selectedVuln.status?.replace('_', ' ').toUpperCase()}</Badge>
                          </div>
                        </div>

                        {selectedVuln.description && (
                          <div>
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Description</h4>
                            <p className="text-sm">{selectedVuln.description}</p>
                          </div>
                        )}

                        <div className="space-y-2 pt-2 border-t">
                          <h4 className="text-sm font-medium text-muted-foreground">Vulnerability Information</h4>
                          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                            {selectedVuln.cvss_score && (
                              <>
                                <span className="text-muted-foreground">CVSS Score</span>
                                <span className="font-bold">{selectedVuln.cvss_score}/10</span>
                              </>
                            )}
                            {selectedVuln.cve_id && (
                              <>
                                <span className="text-muted-foreground">CVE ID</span>
                                <a href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`} target="_blank" className="text-primary hover:underline font-mono">{selectedVuln.cve_id}</a>
                              </>
                            )}
                            <span className="text-muted-foreground">First Seen</span>
                            <span>{formatDate(selectedVuln.first_detected)}</span>
                            <span className="text-muted-foreground">Last Seen</span>
                            <span>{formatDate(selectedVuln.last_detected)}</span>
                            <span className="text-muted-foreground">Age</span>
                            <span>{formatVulnAge(selectedVuln.first_detected)}</span>
                          </div>
                        </div>

                        {selectedVuln.remediation && (
                          <div className="pt-2 border-t">
                            <h4 className="text-sm font-medium text-muted-foreground mb-1">Solution</h4>
                            <p className="text-sm">{selectedVuln.remediation}</p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full py-12">
                        <Shield className="h-12 w-12 text-muted-foreground mb-3" />
                        <p className="text-muted-foreground">Select a finding to view details</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                  <p className="text-muted-foreground">No security findings detected for this asset</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Open Ports Tab */}
        {activeTab === 'ports' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-5 w-5" />
                Open Ports ({asset.port_services?.length || 0})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {asset.port_services && asset.port_services.length > 0 ? (
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
                            {port.is_ssl && <Lock className="h-3 w-3 text-green-400" />}
                        </div>
                      </TableCell>
                      <TableCell>{port.product || '—'}</TableCell>
                      <TableCell className="font-mono text-sm">{port.version || '—'}</TableCell>
                      <TableCell>
                          <Badge className={port.state === 'open' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}>
                          {port.state}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {port.is_risky ? (
                            <Badge className="bg-red-500/20 text-red-400"><AlertTriangle className="h-3 w-3 mr-1" />Risky</Badge>
                          ) : '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              ) : (
                <div className="text-center py-12">
                  <Network className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No open ports detected for this asset</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Activity Tab */}
        {activeTab === 'activity' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Activity Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {asset.last_scan_date && (
                  <div className="flex items-start gap-4 p-4 border rounded-lg">
                    <div className="p-2 rounded-full bg-primary/10">
                      <Shield className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium">Last Scan</p>
                      <p className="text-sm text-muted-foreground">{asset.last_scan_name || 'Security scan'}</p>
                      <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.last_scan_date)}</p>
                    </div>
                  </div>
                )}
                <div className="flex items-start gap-4 p-4 border rounded-lg">
                  <div className="p-2 rounded-full bg-blue-500/10">
                    <Eye className="h-4 w-4 text-blue-500" />
                    </div>
                  <div>
                    <p className="font-medium">Last Seen</p>
                    <p className="text-sm text-muted-foreground">Asset was last observed</p>
                    <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.last_seen)}</p>
                  </div>
                </div>
                <div className="flex items-start gap-4 p-4 border rounded-lg">
                  <div className="p-2 rounded-full bg-green-500/10">
                    <Calendar className="h-4 w-4 text-green-500" />
                  </div>
                  <div>
                    <p className="font-medium">First Discovered</p>
                    <p className="text-sm text-muted-foreground">Asset was first discovered via {asset.discovery_source || 'external discovery'}</p>
                    <p className="text-xs text-muted-foreground mt-1">{formatDate(asset.first_seen)}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Mitigations Tab */}
        {activeTab === 'mitigations' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Mitigations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <Settings className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No mitigations configured for this asset</p>
                <p className="text-sm text-muted-foreground mt-2">Mitigations can be added to document remediation steps</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Application Stack Map */}
        <ApplicationMap
          assetValue={asset.value}
          assetType={asset.asset_type}
          portServices={asset.port_services || []}
          technologies={asset.technologies || []}
          httpStatus={asset.http_status}
          httpTitle={asset.http_title}
        />
      </div>
    </MainLayout>
  );
}
