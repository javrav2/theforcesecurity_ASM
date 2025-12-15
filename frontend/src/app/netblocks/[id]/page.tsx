'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import {
  ArrowLeft,
  Network,
  Globe,
  Building2,
  Shield,
  CheckCircle,
  XCircle,
  MapPin,
  Mail,
  Phone,
  Server,
  Calendar,
  Hash,
  ExternalLink,
  AlertCircle,
  Loader2,
  Copy,
  RefreshCw,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface NetblockDetail {
  id: number;
  organization_id: number;
  inetnum: string;
  start_ip: string;
  end_ip: string;
  cidr_notation: string;
  ip_count: number;
  ip_version: string;
  is_owned: boolean;
  in_scope: boolean;
  ownership_confidence: number;
  
  // ASN Info
  asn?: string;
  as_name?: string;
  as_type?: string;
  route?: string;
  as_domain?: string;
  
  // Network details
  netname?: string;
  nethandle?: string;
  description?: string;
  
  // Geographic
  country?: string;
  city?: string;
  address?: string;
  
  // Org details from WHOIS
  org_name?: string;
  org_email?: string;
  org_phone?: string;
  org_country?: string;
  org_city?: string;
  org_postal_code?: string;
  
  // Discovery
  discovery_source?: string;
  discovered_at: string;
  last_verified?: string;
  
  // Scan tracking
  last_scanned?: string;
  scan_count: number;
  
  tags: string[];
  created_at: string;
  updated_at: string;
}

function InfoRow({ label, value, icon: Icon, copyable = false }: { 
  label: string; 
  value: string | number | null | undefined; 
  icon?: any;
  copyable?: boolean;
}) {
  const { toast } = useToast();
  
  if (!value && value !== 0) return null;
  
  const handleCopy = () => {
    navigator.clipboard.writeText(String(value));
    toast({ title: 'Copied to clipboard' });
  };
  
  return (
    <div className="flex items-start py-2 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <div className="flex items-center min-w-[180px] text-gray-500 dark:text-gray-400">
        {Icon && <Icon className="h-4 w-4 mr-2" />}
        <span className="text-sm font-medium">{label}</span>
      </div>
      <div className="flex-1 text-sm text-gray-900 dark:text-gray-100 whitespace-pre-wrap break-all">
        {value}
        {copyable && (
          <Button
            variant="ghost"
            size="sm"
            className="ml-2 h-6 w-6 p-0"
            onClick={handleCopy}
          >
            <Copy className="h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  );
}

function SectionCard({ title, description, children, icon: Icon }: {
  title: string;
  description?: string;
  children: React.ReactNode;
  icon?: any;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="h-5 w-5 text-primary" />}
          <CardTitle className="text-lg">{title}</CardTitle>
        </div>
        {description && (
          <CardDescription>{description}</CardDescription>
        )}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export default function NetblockDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { toast } = useToast();
  const [netblock, setNetblock] = useState<NetblockDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);

  const netblockId = Number(params.id);

  useEffect(() => {
    fetchNetblock();
  }, [netblockId]);

  const fetchNetblock = async () => {
    try {
      setLoading(true);
      const data = await api.getNetblock(netblockId);
      setNetblock(data);
    } catch (error) {
      console.error('Failed to fetch netblock:', error);
      toast({
        title: 'Error',
        description: 'Failed to load netblock details',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleToggleScope = async () => {
    if (!netblock) return;
    try {
      setUpdating(true);
      await api.toggleNetblockScope(netblock.id);
      setNetblock({ ...netblock, in_scope: !netblock.in_scope });
      toast({ title: `Netblock ${netblock.in_scope ? 'removed from' : 'added to'} scope` });
    } catch (error) {
      toast({ title: 'Failed to update scope', variant: 'destructive' });
    } finally {
      setUpdating(false);
    }
  };

  const handleToggleOwnership = async () => {
    if (!netblock) return;
    try {
      setUpdating(true);
      await api.toggleNetblockOwnership(netblock.id);
      setNetblock({ ...netblock, is_owned: !netblock.is_owned });
      toast({ title: `Ownership ${netblock.is_owned ? 'removed' : 'confirmed'}` });
    } catch (error) {
      toast({ title: 'Failed to update ownership', variant: 'destructive' });
    } finally {
      setUpdating(false);
    }
  };

  const formatIPCount = (count: number) => {
    if (count >= 1e18) return '> 1 quintillion';
    if (count >= 1e15) return `${(count / 1e15).toFixed(1)} quadrillion`;
    if (count >= 1e12) return `${(count / 1e12).toFixed(1)} trillion`;
    if (count >= 1e9) return `${(count / 1e9).toFixed(1)} billion`;
    if (count >= 1e6) return `${(count / 1e6).toFixed(1)} million`;
    if (count >= 1e3) return `${(count / 1e3).toFixed(1)}K`;
    return count.toLocaleString();
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-96">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </MainLayout>
    );
  }

  if (!netblock) {
    return (
      <MainLayout>
        <div className="flex flex-col items-center justify-center h-96 gap-4">
          <AlertCircle className="h-12 w-12 text-destructive" />
          <p className="text-lg text-muted-foreground">Netblock not found</p>
          <Button onClick={() => router.push('/netblocks')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to CIDR Blocks
          </Button>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header 
        title={netblock.cidr_notation || netblock.inetnum} 
        subtitle={`CIDR Block Details • ${netblock.org_name || 'Unknown Organization'}`} 
      />

      <div className="p-6 space-y-6">
        {/* Back Button & Actions */}
        <div className="flex items-center justify-between">
          <Button variant="outline" onClick={() => router.push('/netblocks')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to CIDR Blocks
          </Button>
          <div className="flex items-center gap-4">
            <Button variant="outline" onClick={fetchNetblock} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">IP Version</p>
                  <p className="text-2xl font-bold uppercase">{netblock.ip_version}</p>
                </div>
                <Network className="h-8 w-8 text-blue-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">IP Count</p>
                  <p className="text-2xl font-bold">{formatIPCount(netblock.ip_count)}</p>
                </div>
                <Hash className="h-8 w-8 text-purple-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Ownership Confidence</p>
                  <p className="text-2xl font-bold">{netblock.ownership_confidence}%</p>
                </div>
                <Shield className="h-8 w-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Scans Completed</p>
                  <p className="text-2xl font-bold">{netblock.scan_count}</p>
                </div>
                <Globe className="h-8 w-8 text-orange-500" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Scope & Ownership Controls */}
        <Card>
          <CardHeader>
            <CardTitle>Scope & Ownership Status</CardTitle>
            <CardDescription>
              Control whether this CIDR block is included in scans and confirm ownership
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-8">
              <div className="flex items-center space-x-4">
                <Switch
                  id="in-scope"
                  checked={netblock.in_scope}
                  onCheckedChange={handleToggleScope}
                  disabled={updating}
                />
                <Label htmlFor="in-scope" className="flex items-center gap-2">
                  {netblock.in_scope ? (
                    <Badge className="bg-green-500">In Scope</Badge>
                  ) : (
                    <Badge variant="secondary">Out of Scope</Badge>
                  )}
                  <span className="text-sm text-muted-foreground">
                    Include in vulnerability scans
                  </span>
                </Label>
              </div>

              <div className="flex items-center space-x-4">
                <Switch
                  id="is-owned"
                  checked={netblock.is_owned}
                  onCheckedChange={handleToggleOwnership}
                  disabled={updating}
                />
                <Label htmlFor="is-owned" className="flex items-center gap-2">
                  {netblock.is_owned ? (
                    <Badge className="bg-blue-500">Owned</Badge>
                  ) : (
                    <Badge variant="outline">Not Owned</Badge>
                  )}
                  <span className="text-sm text-muted-foreground">
                    Confirmed ownership by organization
                  </span>
                </Label>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* IP Range Information */}
          <SectionCard title="IP Range Information" icon={Network}>
            <InfoRow label="CIDR Notation" value={netblock.cidr_notation} copyable />
            <InfoRow label="IP Range" value={netblock.inetnum} copyable />
            <InfoRow label="Start IP" value={netblock.start_ip} copyable />
            <InfoRow label="End IP" value={netblock.end_ip} copyable />
            <InfoRow label="Total IPs" value={formatIPCount(netblock.ip_count)} />
            <InfoRow label="IP Version" value={netblock.ip_version?.toUpperCase()} />
          </SectionCard>

          {/* ASN Information */}
          <SectionCard title="ASN / Network Information" icon={Server}>
            <InfoRow label="ASN" value={netblock.asn ? `AS${netblock.asn}` : null} copyable />
            <InfoRow label="AS Name" value={netblock.as_name} />
            <InfoRow label="AS Type" value={netblock.as_type} />
            <InfoRow label="BGP Route" value={netblock.route} />
            <InfoRow label="AS Domain" value={netblock.as_domain} />
            <InfoRow label="Network Name" value={netblock.netname} />
            <InfoRow label="Network Handle" value={netblock.nethandle} copyable />
          </SectionCard>

          {/* WHOIS Organization Details */}
          <SectionCard title="WHOIS Organization Details" icon={Building2} description="Organization information from WHOIS records">
            <InfoRow label="Organization Name" value={netblock.org_name} icon={Building2} />
            <InfoRow label="Organization Country" value={netblock.org_country} icon={Globe} />
            <InfoRow label="Organization City" value={netblock.org_city} icon={MapPin} />
            <InfoRow label="Postal Code" value={netblock.org_postal_code} />
            <InfoRow label="Email Contact(s)" value={netblock.org_email} icon={Mail} />
            <InfoRow label="Phone Contact(s)" value={netblock.org_phone} icon={Phone} />
          </SectionCard>

          {/* Geographic Information */}
          <SectionCard title="Network Location" icon={MapPin} description="Geographic location from WHOIS">
            <InfoRow label="Country" value={netblock.country} icon={Globe} />
            <InfoRow label="City" value={netblock.city} icon={MapPin} />
            <InfoRow label="Address" value={netblock.address} icon={MapPin} />
          </SectionCard>

          {/* Discovery Information */}
          <SectionCard title="Discovery & Tracking" icon={Calendar}>
            <InfoRow label="Discovery Source" value={netblock.discovery_source} />
            <InfoRow label="Discovered At" value={formatDate(netblock.discovered_at)} icon={Calendar} />
            <InfoRow label="Last Verified" value={netblock.last_verified ? formatDate(netblock.last_verified) : 'Never'} />
            <InfoRow label="Last Scanned" value={netblock.last_scanned ? formatDate(netblock.last_scanned) : 'Never'} />
            <InfoRow label="Scan Count" value={netblock.scan_count} />
            <InfoRow label="Created" value={formatDate(netblock.created_at)} />
            <InfoRow label="Updated" value={formatDate(netblock.updated_at)} />
          </SectionCard>

          {/* Description & Notes */}
          {netblock.description && (
            <SectionCard title="Description" icon={AlertCircle}>
              <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                {netblock.description}
              </p>
            </SectionCard>
          )}
        </div>

        {/* Accuracy Assessment Panel */}
        <Card className="border-yellow-500/50 bg-yellow-50/50 dark:bg-yellow-950/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-yellow-700 dark:text-yellow-400">
              <AlertCircle className="h-5 w-5" />
              Accuracy Assessment
            </CardTitle>
            <CardDescription>
              Use this information to verify if this CIDR block belongs to your target organization
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-white dark:bg-gray-900 rounded-lg border">
                  <h4 className="font-medium mb-2">Organization Match</h4>
                  <p className="text-sm text-muted-foreground mb-2">
                    Does "{netblock.org_name || 'Unknown'}" match your target?
                  </p>
                  <div className="flex gap-2">
                    <Badge variant={netblock.ownership_confidence >= 80 ? 'default' : 'secondary'}>
                      {netblock.ownership_confidence}% confidence
                    </Badge>
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-gray-900 rounded-lg border">
                  <h4 className="font-medium mb-2">ASN Provider</h4>
                  <p className="text-sm text-muted-foreground">
                    {netblock.as_name ? (
                      <>Network provided by <strong>{netblock.as_name}</strong></>
                    ) : (
                      'ASN information not available'
                    )}
                  </p>
                </div>

                <div className="p-4 bg-white dark:bg-gray-900 rounded-lg border">
                  <h4 className="font-medium mb-2">Location</h4>
                  <p className="text-sm text-muted-foreground">
                    {[netblock.city, netblock.country].filter(Boolean).join(', ') || 'Location unknown'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 pt-4 border-t">
                <span className="text-sm font-medium">Is this data accurate?</span>
                <Button
                  variant={netblock.is_owned ? 'default' : 'outline'}
                  size="sm"
                  onClick={handleToggleOwnership}
                  disabled={updating}
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  Yes, this is correct
                </Button>
                <Button
                  variant={!netblock.in_scope ? 'destructive' : 'outline'}
                  size="sm"
                  onClick={handleToggleScope}
                  disabled={updating}
                >
                  <XCircle className="h-4 w-4 mr-2" />
                  No, remove from scope
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
