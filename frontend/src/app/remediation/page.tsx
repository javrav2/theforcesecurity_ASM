'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Clock,
  AlertTriangle,
  CheckCircle,
  Zap,
  Target,
  BookOpen,
  TrendingDown,
  Calendar,
  Loader2,
  RefreshCw,
  ChevronRight,
  Shield,
  AlertCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import Link from 'next/link';

interface WorkloadSummary {
  total_findings: number;
  total_hours: number;
  total_work_weeks: number;
  work_week_hours: number;
  hours_display: string;
  weeks_display: string;
}

interface PlaybookSummary {
  id: string;
  title: string;
  count: number;
  total_hours: number;
  effort: string;
  priority: string;
}

interface FindingItem {
  id: number;
  title: string;
  severity: string;
  effort: string;
  hours: number;
  playbook_id: string | null;
  playbook_title: string;
  asset_value: string | null;
}

interface WorkloadData {
  summary: WorkloadSummary;
  by_severity: {
    hours: Record<string, number>;
    counts: Record<string, number>;
  };
  by_effort: Record<string, number>;
  by_playbook: PlaybookSummary[];
  quick_wins: FindingItem[];
  high_priority: FindingItem[];
}

interface Playbook {
  id: string;
  title: string;
  summary: string;
  priority: string;
  effort: string;
  estimated_time: string;
  tags: string[];
}

export default function RemediationPage() {
  const [workload, setWorkload] = useState<WorkloadData | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const { toast } = useToast();

  const fetchData = async () => {
    try {
      const [workloadRes, playbooksRes] = await Promise.all([
        api.get('/remediation/workload'),
        api.get('/remediation/playbooks'),
      ]);
      setWorkload(workloadRes.data);
      setPlaybooks(playbooksRes.data.playbooks || []);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load remediation data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getEffortColor = (effort: string) => {
    switch (effort.toLowerCase()) {
      case 'minimal': return 'bg-green-500/20 text-green-400';
      case 'low': return 'bg-blue-500/20 text-blue-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'high': return 'bg-orange-500/20 text-orange-400';
      case 'significant': return 'bg-red-500/20 text-red-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      default: return 'text-gray-500';
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </MainLayout>
    );
  }

  const summary = workload?.summary;
  const workWeekProgress = summary ? Math.min((summary.total_hours / 40) * 100, 100) : 0;

  return (
    <MainLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Remediation Workload</h1>
            <p className="text-muted-foreground">
              Plan and prioritize your security remediation efforts
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              Informational findings excluded — they typically don&apos;t require remediation
            </p>
          </div>
          <Button onClick={handleRefresh} disabled={refreshing} variant="outline">
            <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>

        {/* Workload Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Total Workload */}
          <Card className="border-2 border-primary/20">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <Clock className="h-5 w-5 text-primary" />
                <Badge variant="outline">vs 40hr week</Badge>
              </div>
              <div className="text-3xl font-bold">{summary?.hours_display || '0h'}</div>
              <p className="text-sm text-muted-foreground mt-1">
                {summary?.weeks_display || '0 weeks'} of work
              </p>
              <div className="mt-3 h-2 bg-muted rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all ${
                    workWeekProgress > 100 ? 'bg-red-500' : 
                    workWeekProgress > 50 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(workWeekProgress, 100)}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {workWeekProgress > 100 
                  ? `${(summary?.total_work_weeks || 0).toFixed(1)}x your weekly capacity`
                  : `${workWeekProgress.toFixed(0)}% of one work week`
                }
              </p>
            </CardContent>
          </Card>

          {/* Total Findings */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
              </div>
              <div className="text-3xl font-bold">{summary?.total_findings || 0}</div>
              <p className="text-sm text-muted-foreground">Open findings</p>
            </CardContent>
          </Card>

          {/* Critical/High */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <Shield className="h-5 w-5 text-red-500" />
              </div>
              <div className="text-3xl font-bold text-red-500">
                {(workload?.by_severity?.counts?.critical || 0) + (workload?.by_severity?.counts?.high || 0)}
              </div>
              <p className="text-sm text-muted-foreground">Critical & High severity</p>
            </CardContent>
          </Card>

          {/* Quick Wins */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-2">
                <Zap className="h-5 w-5 text-green-500" />
              </div>
              <div className="text-3xl font-bold text-green-500">
                {workload?.quick_wins?.length || 0}
              </div>
              <p className="text-sm text-muted-foreground">Quick wins available</p>
            </CardContent>
          </Card>
        </div>

        {/* Severity & Effort Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* By Severity */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Target className="h-5 w-5" />
                Hours by Severity
              </CardTitle>
              <CardDescription>Estimated remediation time by finding severity</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {['critical', 'high', 'medium', 'low'].map((severity) => {
                  const hours = workload?.by_severity?.hours?.[severity] || 0;
                  const count = workload?.by_severity?.counts?.[severity] || 0;
                  const maxHours = Math.max(...Object.values(workload?.by_severity?.hours || { a: 1 }));
                  const percentage = maxHours > 0 ? (hours / maxHours) * 100 : 0;
                  
                  return (
                    <div key={severity}>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm font-medium capitalize flex items-center gap-2">
                          <span className={`w-3 h-3 rounded-full ${getSeverityColor(severity)}`} />
                          {severity}
                        </span>
                        <span className="text-sm text-muted-foreground">
                          {count} findings • {hours.toFixed(1)}h
                        </span>
                      </div>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${getSeverityColor(severity)}`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* By Effort Level */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <TrendingDown className="h-5 w-5" />
                Findings by Effort Level
              </CardTitle>
              <CardDescription>How much work each finding requires</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { key: 'minimal', label: 'Minimal (<30 min)', time: '0.5h' },
                  { key: 'low', label: 'Low (1-2 hours)', time: '1.5h' },
                  { key: 'medium', label: 'Medium (half day)', time: '4h' },
                  { key: 'high', label: 'High (1-2 days)', time: '12h' },
                  { key: 'significant', label: 'Significant (week+)', time: '40h' },
                ].map(({ key, label, time }) => {
                  const count = workload?.by_effort?.[key] || 0;
                  const maxCount = Math.max(...Object.values(workload?.by_effort || { a: 1 }));
                  const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  
                  return (
                    <div key={key}>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm font-medium">{label}</span>
                        <span className="text-sm text-muted-foreground">
                          {count} findings
                        </span>
                      </div>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            key === 'minimal' ? 'bg-green-500' :
                            key === 'low' ? 'bg-blue-500' :
                            key === 'medium' ? 'bg-yellow-500' :
                            key === 'high' ? 'bg-orange-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Quick Wins & High Priority */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Quick Wins */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Zap className="h-5 w-5 text-green-500" />
                Quick Wins
              </CardTitle>
              <CardDescription>Low effort, high impact fixes - start here!</CardDescription>
            </CardHeader>
            <CardContent>
              {workload?.quick_wins?.length === 0 ? (
                <p className="text-muted-foreground text-sm">No quick wins identified</p>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {workload?.quick_wins?.slice(0, 10).map((item) => (
                    <Link 
                      key={item.id}
                      href={`/findings?id=${item.id}`}
                      className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <Badge className={getSeverityColor(item.severity)}>
                          {item.severity.charAt(0).toUpperCase()}
                        </Badge>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.title}</p>
                          <p className="text-xs text-muted-foreground truncate">{item.asset_value}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getEffortColor(item.effort)}>{item.hours}h</Badge>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* High Priority */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-red-500" />
                High Priority
              </CardTitle>
              <CardDescription>Critical and high severity findings to address first</CardDescription>
            </CardHeader>
            <CardContent>
              {workload?.high_priority?.length === 0 ? (
                <div className="flex items-center gap-2 text-green-500">
                  <CheckCircle className="h-5 w-5" />
                  <span>No critical/high findings!</span>
                </div>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {workload?.high_priority?.slice(0, 10).map((item) => (
                    <Link 
                      key={item.id}
                      href={`/findings?id=${item.id}`}
                      className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <Badge className={getSeverityColor(item.severity)}>
                          {item.severity.charAt(0).toUpperCase()}
                        </Badge>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.title}</p>
                          <p className="text-xs text-muted-foreground truncate">{item.asset_value}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getEffortColor(item.effort)}>{item.hours}h</Badge>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Playbook Library */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <BookOpen className="h-5 w-5" />
              Remediation Playbooks
            </CardTitle>
            <CardDescription>
              Step-by-step guides for fixing common security issues
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Playbooks by Finding Count */}
            {workload?.by_playbook && workload.by_playbook.length > 0 && (
              <div className="mb-6">
                <h4 className="text-sm font-medium mb-3">Most Used Playbooks</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {workload.by_playbook.slice(0, 6).map((pb) => (
                    <div 
                      key={pb.id}
                      className="p-3 border rounded-lg hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <Badge className={getPriorityColor(pb.priority)} variant="outline">
                          {pb.priority}
                        </Badge>
                        <span className="text-sm font-bold">{pb.count} findings</span>
                      </div>
                      <p className="font-medium text-sm">{pb.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {pb.total_hours.toFixed(1)} hours total
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* All Playbooks Table */}
            <div>
              <h4 className="text-sm font-medium mb-3">All Available Playbooks ({playbooks.length})</h4>
              <div className="rounded-lg border overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Playbook</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Effort</TableHead>
                      <TableHead>Est. Time</TableHead>
                      <TableHead>Tags</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {playbooks.slice(0, 15).map((playbook) => (
                      <TableRow key={playbook.id}>
                        <TableCell>
                          <div>
                            <p className="font-medium">{playbook.title}</p>
                            <p className="text-xs text-muted-foreground line-clamp-1">
                              {playbook.summary}
                            </p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge className={getPriorityColor(playbook.priority)} variant="outline">
                            {playbook.priority}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={getEffortColor(playbook.effort)}>
                            {playbook.effort}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">{playbook.estimated_time}</TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {playbook.tags.slice(0, 2).map((tag) => (
                              <Badge key={tag} variant="secondary" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                            {playbook.tags.length > 2 && (
                              <Badge variant="secondary" className="text-xs">
                                +{playbook.tags.length - 2}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Weekly Planning Guide */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              Weekly Planning Guide
            </CardTitle>
            <CardDescription>
              Suggested approach for a 40-hour work week
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <div className="p-4 border rounded-lg bg-red-500/10">
                <h4 className="font-medium text-red-400">Day 1: Critical</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Focus on {workload?.by_severity?.counts?.critical || 0} critical findings
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  ~{workload?.by_severity?.hours?.critical?.toFixed(1) || 0}h estimated
                </p>
              </div>
              <div className="p-4 border rounded-lg bg-orange-500/10">
                <h4 className="font-medium text-orange-400">Day 2-3: High</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Address {workload?.by_severity?.counts?.high || 0} high severity issues
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  ~{workload?.by_severity?.hours?.high?.toFixed(1) || 0}h estimated
                </p>
              </div>
              <div className="p-4 border rounded-lg bg-yellow-500/10">
                <h4 className="font-medium text-yellow-400">Day 4: Medium</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Work through {workload?.by_severity?.counts?.medium || 0} medium findings
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  ~{workload?.by_severity?.hours?.medium?.toFixed(1) || 0}h estimated
                </p>
              </div>
              <div className="p-4 border rounded-lg bg-blue-500/10">
                <h4 className="font-medium text-blue-400">Day 5: Low/Cleanup</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Handle {workload?.by_severity?.counts?.low || 0} low priority items
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  ~{workload?.by_severity?.hours?.low?.toFixed(1) || 0}h estimated
                </p>
              </div>
              <div className="p-4 border rounded-lg bg-green-500/10">
                <h4 className="font-medium text-green-400">Quick Wins</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Sprinkle in {workload?.quick_wins?.length || 0} easy fixes
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  Great for momentum!
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
