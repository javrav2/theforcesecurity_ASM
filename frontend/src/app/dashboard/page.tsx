'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
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
} from 'lucide-react';
import { api } from '@/lib/api';
import { formatNumber } from '@/lib/utils';
import Link from 'next/link';

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

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [recentVulns, setRecentVulns] = useState<any[]>([]);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [vulnSummary, orgs, assets, vulns] = await Promise.all([
        api.getVulnerabilitiesSummary(),
        api.getOrganizations(),
        api.getAssets({ limit: 1 }),
        api.getVulnerabilities({ limit: 5 }),
      ]);

      setStats({
        total_assets: assets.total || assets.length || 0,
        total_vulnerabilities: vulnSummary.total || 0,
        critical_count: vulnSummary.by_severity?.critical || 0,
        high_count: vulnSummary.by_severity?.high || 0,
        medium_count: vulnSummary.by_severity?.medium || 0,
        low_count: vulnSummary.by_severity?.low || 0,
        total_organizations: orgs.length || 0,
        recent_scans: 0,
      });

      setRecentVulns(vulns.items || vulns || []);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

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
      title: 'Vulnerabilities',
      value: stats?.total_vulnerabilities || 0,
      icon: Shield,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      href: '/vulnerabilities',
    },
    {
      title: 'Critical Issues',
      value: stats?.critical_count || 0,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-600/10',
      href: '/vulnerabilities?severity=critical',
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
              <CardTitle className="text-lg">Recent Vulnerabilities</CardTitle>
              <Link href="/vulnerabilities">
                <Button variant="ghost" size="sm">
                  View All <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {recentVulns.length === 0 ? (
                  <p className="text-muted-foreground text-sm text-center py-8">
                    No vulnerabilities found. Run a scan to discover issues.
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



