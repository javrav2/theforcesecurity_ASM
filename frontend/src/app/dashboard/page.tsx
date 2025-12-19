'use client';

import { useEffect, useState, useMemo } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { WorldMap } from '@/components/map/WorldMap';
import {
  Globe,
  Shield,
  AlertTriangle,
  Camera,
  Activity,
  TrendingUp,
  TrendingDown,
  ArrowRight,
  RefreshCw,
  Network,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import Link from 'next/link';
import { useToast } from '@/hooks/use-toast';

interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_organizations: number;
  recent_scans: number;
}

interface NetblockStats {
  total_netblocks: number;
  owned_netblocks: number;
  in_scope_netblocks: number;
  total_ips: number;
  owned_ips: number;
  in_scope_ips: number;
  scanned_netblocks: number;
  unscanned_netblocks: number;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [netblockStats, setNetblockStats] = useState<NetblockStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [recentVulns, setRecentVulns] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const { toast } = useToast();

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [vulnSummary, orgs, assetsData, vulns, nbSummary] = await Promise.all([
        api.getVulnerabilitiesSummary(),
        api.getOrganizations(),
        api.getAssets({ limit: 100 }),
        api.getVulnerabilities({ limit: 5 }),
        api.getNetblockSummary().catch(() => null),
      ]);

      const assetsList = assetsData.items || assetsData || [];
      setAssets(assetsList);

      setStats({
        total_assets: assetsData.total || assetsList.length || 0,
        total_vulnerabilities: vulnSummary.total || 0,
        critical_count: vulnSummary.by_severity?.critical || 0,
        high_count: vulnSummary.by_severity?.high || 0,
        medium_count: vulnSummary.by_severity?.medium || 0,
        low_count: vulnSummary.by_severity?.low || 0,
        total_organizations: orgs.length || 0,
        recent_scans: 0,
      });

      if (nbSummary) {
        setNetblockStats(nbSummary);
      }

      setRecentVulns(vulns.items || vulns || []);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Transform assets for WorldMap - only include assets with geo data
  const mapAssets = useMemo(() => {
    return assets
      .filter((a: any) => a.latitude && a.longitude)
      .map((a: any) => ({
        id: a.id,
        value: a.name || a.value || '',
        type: a.asset_type?.toLowerCase() || 'subdomain',
        findingsCount: a.vulnerability_count || 0,
        geoLocation: {
          latitude: parseFloat(a.latitude),
          longitude: parseFloat(a.longitude),
          city: a.city,
          country: a.country,
          countryCode: a.country_code,
        },
      }));
  }, [assets]);

  // Count of assets without geo data
  const assetsWithoutGeo = useMemo(() => {
    return assets.filter((a: any) => !a.latitude || !a.longitude).length;
  }, [assets]);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const statCards = [
    {
      title: 'Total Assets',
      value: stats?.total_assets || 0,
      icon: Globe,
      color: 'text-blue-500',
      bgColor: 'bg-blue-500/10',
      href: '/assets',
    },
    {
      title: 'Findings',
      value: stats?.total_vulnerabilities || 0,
      icon: Shield,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      href: '/findings',
    },
    {
      title: 'Critical Issues',
      value: stats?.critical_count || 0,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-600/10',
      href: '/findings?severity=critical',
    },
    {
      title: 'Organizations',
      value: stats?.total_organizations || 0,
      icon: Activity,
      color: 'text-green-500',
      bgColor: 'bg-green-500/10',
      href: '/organizations',
    },
  ];

  return (
    <MainLayout>
      <Header title="Dashboard" subtitle="Overview of your attack surface" />

      <div className="p-6 space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {statCards.map((stat) => (
            <Link key={stat.title} href={stat.href}>
              <Card className="hover:border-primary/50 transition-colors cursor-pointer">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">{stat.title}</p>
                      <p className="text-3xl font-bold mt-1">
                        {loading ? '...' : formatNumber(stat.value)}
                      </p>
                    </div>
                    <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                      <stat.icon className={`h-6 w-6 ${stat.color}`} />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>

        {/* World Map */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg">Asset Locations</CardTitle>
            {assetsWithoutGeo > 0 && (
              <Button 
                variant="outline" 
                size="sm"
                onClick={async () => {
                  try {
                    toast({ title: 'Enriching...', description: 'Looking up geo-location data for assets' });
                    await api.enrichAssetsGeolocation();
                    toast({ title: 'Success', description: 'Geo-location data updated. Refreshing...' });
                    fetchDashboardData();
                  } catch (error) {
                    toast({ title: 'Error', description: 'Failed to enrich geo-location', variant: 'destructive' });
                  }
                }}
              >
                <Globe className="h-4 w-4 mr-2" />
                Enrich Locations ({assetsWithoutGeo} pending)
              </Button>
            )}
          </CardHeader>
          <CardContent>
            {mapAssets.length > 0 ? (
              <WorldMap 
                assets={mapAssets} 
                onAssetClick={(asset) => {
                  toast({
                    title: asset.value,
                    description: `${asset.geoLocation?.city || 'Unknown'}, ${asset.geoLocation?.country || 'Unknown'} · ${asset.findingsCount || 0} findings`,
                  });
                }} 
              />
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No assets with geo-location data</p>
                {assetsWithoutGeo > 0 && (
                  <p className="text-sm mt-2">Click "Enrich Locations" to resolve asset locations</p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Severity Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Vulnerability Breakdown</CardTitle>
              <Button variant="ghost" size="icon" onClick={fetchDashboardData}>
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { label: 'Critical', count: stats?.critical_count || 0, color: 'bg-red-600' },
                  { label: 'High', count: stats?.high_count || 0, color: 'bg-orange-500' },
                  { label: 'Medium', count: stats?.medium_count || 0, color: 'bg-yellow-500' },
                  { label: 'Low', count: stats?.low_count || 0, color: 'bg-green-500' },
                ].map((item) => {
                  const total = stats?.total_vulnerabilities || 1;
                  const percentage = (item.count / total) * 100;
                  return (
                    <div key={item.label} className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">{item.label}</span>
                        <span className="font-medium">{item.count}</span>
                      </div>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full ${item.color} rounded-full transition-all duration-500`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Recent Findings</CardTitle>
              <Link href="/findings">
                <Button variant="ghost" size="sm">
                  View All <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {recentVulns.length === 0 ? (
                  <p className="text-muted-foreground text-sm text-center py-8">
                    No findings found. Run a scan to discover issues.
                  </p>
                ) : (
                  recentVulns.slice(0, 5).map((vuln: any, index: number) => (
                    <div
                      key={vuln.id || index}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {vuln.name || vuln.template_id || 'Unknown'}
                        </p>
                        <p className="text-xs text-muted-foreground truncate">
                          {vuln.host || vuln.target || 'Unknown target'}
                        </p>
                      </div>
                      <Badge
                        variant={
                          vuln.severity?.toLowerCase() === 'critical'
                            ? 'critical'
                            : vuln.severity?.toLowerCase() === 'high'
                            ? 'high'
                            : vuln.severity?.toLowerCase() === 'medium'
                            ? 'medium'
                            : 'low'
                        }
                      >
                        {vuln.severity || 'Unknown'}
                      </Badge>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Scan Coverage */}
        {netblockStats && (netblockStats.total_netblocks > 0 || netblockStats.total_ips > 0) && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <Network className="h-5 w-5" />
                Scan Coverage
              </CardTitle>
              <Link href="/netblocks">
                <Button variant="ghost" size="sm">
                  Manage CIDR Blocks <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Network className="h-4 w-4 text-primary" />
                    <span className="text-sm text-muted-foreground">CIDR Ranges</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.total_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Owned</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.owned_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className="h-4 w-4 text-blue-500" />
                    <span className="text-sm text-muted-foreground">In Scope</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.in_scope_netblocks}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Globe className="h-4 w-4 text-purple-500" />
                    <span className="text-sm text-muted-foreground">Total IPs</span>
                  </div>
                  <p className="text-2xl font-bold">
                    {netblockStats.total_ips >= 1000000
                      ? `${(netblockStats.total_ips / 1000000).toFixed(1)}M`
                      : netblockStats.total_ips >= 1000
                      ? `${(netblockStats.total_ips / 1000).toFixed(1)}K`
                      : netblockStats.total_ips}
                  </p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Activity className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Scanned</span>
                  </div>
                  <p className="text-2xl font-bold">
                    {netblockStats.scanned_netblocks}/{netblockStats.total_netblocks}
                  </p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <XCircle className="h-4 w-4 text-orange-500" />
                    <span className="text-sm text-muted-foreground">Pending</span>
                  </div>
                  <p className="text-2xl font-bold">{netblockStats.unscanned_netblocks}</p>
                </div>
              </div>
              
              {/* Scan Progress Bar */}
              {netblockStats.total_netblocks > 0 && (
                <div className="mt-4">
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-muted-foreground">Scan Progress</span>
                    <span className="font-medium">
                      {Math.round((netblockStats.scanned_netblocks / netblockStats.total_netblocks) * 100)}%
                    </span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full transition-all duration-500"
                      style={{
                        width: `${(netblockStats.scanned_netblocks / netblockStats.total_netblocks) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Quick Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Link href="/organizations">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Activity className="h-5 w-5" />
                  <span>New Organization</span>
                </Button>
              </Link>
              <Link href="/scans">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Shield className="h-5 w-5" />
                  <span>Run Scan</span>
                </Button>
              </Link>
              <Link href="/discovery">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Globe className="h-5 w-5" />
                  <span>Asset Discovery</span>
                </Button>
              </Link>
              <Link href="/screenshots">
                <Button variant="outline" className="w-full h-auto py-4 flex flex-col gap-2">
                  <Camera className="h-5 w-5" />
                  <span>Screenshots</span>
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}












