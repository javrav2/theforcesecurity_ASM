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
  Clock,
  Target,
  Zap,
  BarChart3,
  AlertCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import Link from 'next/link';
import { useToast } from '@/hooks/use-toast';

interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;  // Excludes info
  total_all_vulnerabilities: number;  // Includes info
  info_count: number;
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

interface RemediationStats {
  period_days: number;
  new_findings: number;
  resolved_findings: number;
  resolution_rate: number;
  avg_resolution_time_days: number | null;
  mttr_days: number | null;
  open_critical: number;
  open_high: number;
  overdue_count: number;
}

interface ExposureStats {
  total_exposure_score: number;
  assets_with_vulnerabilities: number;
  total_assets: number;
  exposure_percentage: number;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_vulnerable_assets: Array<{
    asset_id: number;
    asset_name: string;
    asset_value: string;
    vulnerability_count: number;
    asset_type: string;
  }>;
  exposure_trend: 'increasing' | 'decreasing' | 'stable';
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [netblockStats, setNetblockStats] = useState<NetblockStats | null>(null);
  const [remediationStats, setRemediationStats] = useState<RemediationStats | null>(null);
  const [exposureStats, setExposureStats] = useState<ExposureStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [recentVulns, setRecentVulns] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const { toast } = useToast();

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [vulnSummary, orgs, assetsData, geoAssetsData, vulns, nbSummary, remediationData, exposureData] = await Promise.all([
        api.getVulnerabilitiesSummary(),
        api.getOrganizations(),
        api.getAssets({ limit: 10000 }), // Fetch assets for stats
        api.getAssets({ limit: 50000, has_geo: true }), // Fetch all assets with geo data for the map
        api.getVulnerabilities({ limit: 5 }),
        api.getNetblockSummary().catch(() => null),
        api.getRemediationEfficiency(30).catch(() => null),
        api.getVulnerabilityExposure().catch(() => null),
      ]);

      // Use geo assets for the map
      const geoAssetsList = geoAssetsData.items || geoAssetsData || [];
      setAssets(geoAssetsList);

      setStats({
        total_assets: assetsData.total || (assetsData.items || assetsData || []).length || 0,
        total_vulnerabilities: vulnSummary.total || 0,  // Excludes info findings
        total_all_vulnerabilities: vulnSummary.total_all || vulnSummary.total || 0,
        info_count: vulnSummary.info_count || vulnSummary.by_severity?.info || 0,
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

      if (remediationData) {
        setRemediationStats(remediationData);
      }

      if (exposureData) {
        setExposureStats(exposureData);
      }

      setRecentVulns(vulns.items || vulns || []);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Transform assets for WorldMap - only include assets with valid geo data
  const mapAssets = useMemo(() => {
    return assets
      .filter((a: any) => {
        // Handle both string and number lat/lng, exclude empty strings and null/undefined
        const lat = a.latitude;
        const lng = a.longitude;
        const hasValidLat = lat !== null && lat !== undefined && lat !== '' && !isNaN(parseFloat(lat));
        const hasValidLng = lng !== null && lng !== undefined && lng !== '' && !isNaN(parseFloat(lng));
        return hasValidLat && hasValidLng;
      })
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
          <CardHeader>
            <CardTitle className="text-lg">Global Attack Surface Heatmap</CardTitle>
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
                <p>No assets with geo-location data yet</p>
                <p className="text-sm mt-2">Run a DNS Resolution scan to resolve IPs and geo-locate assets</p>
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
                {/* Info count shown separately */}
                {stats?.info_count && stats.info_count > 0 && (
                  <div className="pt-2 border-t border-muted">
                    <div className="flex items-center justify-between text-sm text-muted-foreground">
                      <span>Informational (not counted as findings)</span>
                      <span>{stats.info_count}</span>
                    </div>
                  </div>
                )}
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

        {/* Remediation Efficiency & Vulnerability Exposure */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Remediation Efficiency */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Zap className="h-5 w-5 text-green-500" />
                  Remediation Efficiency
                </CardTitle>
                <p className="text-sm text-muted-foreground mt-1">Last 30 days</p>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <AlertCircle className="h-4 w-4 text-orange-500" />
                    <span className="text-sm text-muted-foreground">New Findings</span>
                  </div>
                  <p className="text-2xl font-bold">{remediationStats?.new_findings || 0}</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-muted-foreground">Resolved</span>
                  </div>
                  <p className="text-2xl font-bold">{remediationStats?.resolved_findings || 0}</p>
                </div>
              </div>
              
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Resolution Rate</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-green-500 rounded-full transition-all duration-500"
                        style={{ width: `${Math.min(remediationStats?.resolution_rate || 0, 100)}%` }}
                      />
                    </div>
                    <span className="font-medium text-sm">{remediationStats?.resolution_rate || 0}%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">MTTR (Mean Time to Remediate)</span>
                  <span className="font-medium">
                    {remediationStats?.mttr_days != null 
                      ? `${remediationStats.mttr_days} days`
                      : '—'}
                  </span>
                </div>
                
                <div className="pt-3 border-t border-muted flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="text-center">
                      <Badge variant="critical" className="mb-1">Critical</Badge>
                      <p className="text-lg font-bold">{remediationStats?.open_critical || 0}</p>
                    </div>
                    <div className="text-center">
                      <Badge variant="high" className="mb-1">High</Badge>
                      <p className="text-lg font-bold">{remediationStats?.open_high || 0}</p>
                    </div>
                  </div>
                  {(remediationStats?.overdue_count || 0) > 0 && (
                    <div className="flex items-center gap-2 text-red-500">
                      <Clock className="h-4 w-4" />
                      <span className="text-sm font-medium">{remediationStats?.overdue_count} overdue</span>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Vulnerability Exposure */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Target className="h-5 w-5 text-red-500" />
                  Vulnerability Exposure
                </CardTitle>
                <p className="text-sm text-muted-foreground mt-1">Current attack surface risk</p>
              </div>
              <div className="flex items-center gap-2">
                {exposureStats?.exposure_trend === 'increasing' && (
                  <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                    <TrendingUp className="h-3 w-3 mr-1" /> Increasing
                  </Badge>
                )}
                {exposureStats?.exposure_trend === 'decreasing' && (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                    <TrendingDown className="h-3 w-3 mr-1" /> Decreasing
                  </Badge>
                )}
                {exposureStats?.exposure_trend === 'stable' && (
                  <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                    Stable
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold text-red-500">{exposureStats?.total_exposure_score || 0}</p>
                  <p className="text-xs text-muted-foreground">Exposure Score</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold">{exposureStats?.assets_with_vulnerabilities || 0}</p>
                  <p className="text-xs text-muted-foreground">Vulnerable Assets</p>
                </div>
                <div className="p-4 bg-muted/50 rounded-lg text-center">
                  <p className="text-3xl font-bold">{exposureStats?.exposure_percentage || 0}%</p>
                  <p className="text-xs text-muted-foreground">Asset Exposure</p>
                </div>
              </div>
              
              {/* Severity Distribution */}
              <div className="mb-4">
                <p className="text-sm text-muted-foreground mb-2">Open Vulnerabilities by Severity</p>
                <div className="flex gap-2">
                  <div className="flex-1 h-4 bg-red-600 rounded" 
                    style={{ 
                      flex: exposureStats?.severity_distribution?.critical || 0.1 
                    }} 
                    title={`Critical: ${exposureStats?.severity_distribution?.critical || 0}`}
                  />
                  <div className="flex-1 h-4 bg-orange-500 rounded" 
                    style={{ 
                      flex: exposureStats?.severity_distribution?.high || 0.1 
                    }}
                    title={`High: ${exposureStats?.severity_distribution?.high || 0}`}
                  />
                  <div className="flex-1 h-4 bg-yellow-500 rounded" 
                    style={{ 
                      flex: exposureStats?.severity_distribution?.medium || 0.1 
                    }}
                    title={`Medium: ${exposureStats?.severity_distribution?.medium || 0}`}
                  />
                  <div className="flex-1 h-4 bg-green-500 rounded" 
                    style={{ 
                      flex: exposureStats?.severity_distribution?.low || 0.1 
                    }}
                    title={`Low: ${exposureStats?.severity_distribution?.low || 0}`}
                  />
                </div>
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>Critical: {exposureStats?.severity_distribution?.critical || 0}</span>
                  <span>High: {exposureStats?.severity_distribution?.high || 0}</span>
                  <span>Medium: {exposureStats?.severity_distribution?.medium || 0}</span>
                  <span>Low: {exposureStats?.severity_distribution?.low || 0}</span>
                </div>
              </div>

              {/* Top Vulnerable Assets */}
              {exposureStats?.top_vulnerable_assets && exposureStats.top_vulnerable_assets.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Most Vulnerable Assets</p>
                  <div className="space-y-2">
                    {exposureStats.top_vulnerable_assets.slice(0, 5).map((asset) => (
                      <Link 
                        key={asset.asset_id} 
                        href={`/assets/${asset.asset_id}`}
                        className="flex items-center justify-between p-2 rounded bg-muted/50 hover:bg-muted transition-colors"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Globe className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                          <span className="text-sm truncate">{asset.asset_name}</span>
                        </div>
                        <Badge variant="destructive" className="flex-shrink-0">
                          {asset.vulnerability_count}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
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














