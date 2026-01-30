'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
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
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Shield,
  Search,
  Plus,
  Loader2,
  AlertCircle,
  Clock,
  FileText,
  CheckCircle,
  XCircle,
  Calendar,
  Users,
  ChevronRight,
  AlertTriangle,
  ShieldCheck,
  ShieldX,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, cn } from '@/lib/utils';

interface Exception {
  id: number;
  title: string;
  exception_type: string;
  status: string;
  justification: string;
  business_impact?: string;
  compensating_controls?: string;
  residual_risk?: string;
  organization_id: number;
  requested_by: string;
  approved_by?: string;
  effective_date: string;
  expiration_date?: string;
  review_date?: string;
  created_at: string;
  updated_at: string;
  approved_at?: string;
  findings_count: number;
  is_expired: boolean;
  is_active: boolean;
  tags: string[];
  findings?: Array<{
    id: number;
    title: string;
    severity: string;
    status: string;
    host?: string;
  }>;
}

interface Stats {
  total: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  active: number;
  expired: number;
  total_linked_findings: number;
}

const exceptionTypeConfig: Record<string, { label: string; icon: any; color: string }> = {
  risk_accepted: { label: 'Risk Accepted', icon: ShieldX, color: 'text-blue-400 bg-blue-600/20 border-blue-600/30' },
  mitigated: { label: 'Mitigated', icon: ShieldCheck, color: 'text-cyan-400 bg-cyan-600/20 border-cyan-600/30' },
  false_positive: { label: 'False Positive', icon: XCircle, color: 'text-gray-400 bg-gray-600/20 border-gray-600/30' },
  deferred: { label: 'Deferred', icon: Clock, color: 'text-yellow-400 bg-yellow-600/20 border-yellow-600/30' },
};

const statusConfig: Record<string, { label: string; color: string }> = {
  pending_approval: { label: 'Pending Approval', color: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30' },
  approved: { label: 'Approved', color: 'bg-green-600/20 text-green-400 border-green-600/30' },
  rejected: { label: 'Rejected', color: 'bg-red-600/20 text-red-400 border-red-600/30' },
  expired: { label: 'Expired', color: 'bg-gray-600/20 text-gray-400 border-gray-600/30' },
};

const residualRiskConfig: Record<string, { label: string; color: string }> = {
  critical: { label: 'Critical', color: 'text-red-400' },
  high: { label: 'High', color: 'text-orange-400' },
  medium: { label: 'Medium', color: 'text-yellow-400' },
  low: { label: 'Low', color: 'text-green-400' },
};

export default function ExceptionsPage() {
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [includeExpired, setIncludeExpired] = useState(false);
  const [selectedException, setSelectedException] = useState<Exception | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  // New exception form state
  const [newException, setNewException] = useState({
    title: '',
    exception_type: 'risk_accepted',
    justification: '',
    business_impact: '',
    compensating_controls: '',
    residual_risk: 'medium',
    expiration_date: '',
    review_date: '',
  });

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [exceptionsData, statsData] = await Promise.all([
        api.getExceptions({
          exception_type: selectedType !== 'all' ? selectedType : undefined,
          include_expired: includeExpired,
          limit: 100,
        }),
        api.getExceptionStats(),
      ]);
      setExceptions(exceptionsData);
      setStats(statsData);
    } catch (err: any) {
      console.error('Failed to fetch exceptions:', err);
      setError(err.message || 'Failed to fetch exceptions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedType, includeExpired]);

  const handleCreateException = async () => {
    if (!newException.title.trim() || !newException.justification.trim()) {
      toast({
        title: 'Validation Error',
        description: 'Title and justification are required',
        variant: 'destructive',
      });
      return;
    }

    setCreating(true);
    try {
      // Get organization_id from current user context (assuming first org for now)
      const orgs = await api.getOrganizations();
      const orgId = orgs[0]?.id || 1;

      await api.createException({
        ...newException,
        organization_id: orgId,
        expiration_date: newException.expiration_date || undefined,
        review_date: newException.review_date || undefined,
      });

      toast({
        title: 'Exception Created',
        description: 'The exception has been created successfully',
      });

      setCreateDialogOpen(false);
      setNewException({
        title: '',
        exception_type: 'risk_accepted',
        justification: '',
        business_impact: '',
        compensating_controls: '',
        residual_risk: 'medium',
        expiration_date: '',
        review_date: '',
      });
      fetchData();
    } catch (err: any) {
      toast({
        title: 'Error',
        description: `Failed to create exception: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteException = async (exceptionId: number) => {
    try {
      await api.deleteException(exceptionId);
      toast({
        title: 'Exception Deleted',
        description: 'The exception has been deleted and linked findings reset to open',
      });
      setSelectedException(null);
      fetchData();
    } catch (err: any) {
      toast({
        title: 'Error',
        description: `Failed to delete: ${err.message || 'Unknown error'}`,
        variant: 'destructive',
      });
    }
  };

  const handleSelectException = async (exception: Exception) => {
    try {
      const details = await api.getException(exception.id);
      setSelectedException(details);
    } catch (err) {
      console.error('Failed to fetch exception details:', err);
      setSelectedException(exception);
    }
  };

  // Filter exceptions by search
  const filteredExceptions = exceptions.filter(exc => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      exc.title.toLowerCase().includes(query) ||
      exc.justification.toLowerCase().includes(query) ||
      exc.requested_by.toLowerCase().includes(query)
    );
  });

  return (
    <MainLayout>
      <Header title="Exceptions" subtitle="Manage risk accepted, mitigated, and false positive findings" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-600/20">
                  <FileText className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.total || 0}</p>
                  <p className="text-sm text-muted-foreground">Total Exceptions</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-600/20">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.active || 0}</p>
                  <p className="text-sm text-muted-foreground">Active</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-gray-600/20">
                  <Clock className="h-5 w-5 text-gray-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.expired || 0}</p>
                  <p className="text-sm text-muted-foreground">Expired</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-600/20">
                  <Shield className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{stats?.total_linked_findings || 0}</p>
                  <p className="text-sm text-muted-foreground">Linked Findings</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Filters and Actions */}
        <div className="flex gap-4 flex-wrap items-center">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search exceptions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-secondary/50"
            />
          </div>
          <Select value={selectedType} onValueChange={setSelectedType}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Filter by type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="risk_accepted">Risk Accepted</SelectItem>
              <SelectItem value="mitigated">Mitigated</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
              <SelectItem value="deferred">Deferred</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center gap-2">
            <Checkbox
              id="include-expired"
              checked={includeExpired}
              onCheckedChange={(checked) => setIncludeExpired(checked === true)}
            />
            <label htmlFor="include-expired" className="text-sm text-muted-foreground cursor-pointer">
              Include expired
            </label>
          </div>
          <div className="flex-1" />
          <Button onClick={() => setCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Create Exception
          </Button>
        </div>

        {/* Error State */}
        {error && (
          <Card className="border-red-600/30 bg-red-600/10">
            <CardContent className="p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-red-400 font-medium">Failed to load exceptions</p>
                <p className="text-sm text-muted-foreground">{error}</p>
              </div>
              <Button variant="outline" size="sm" onClick={fetchData} className="ml-auto">
                Retry
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Exceptions Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Residual Risk</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Requested By</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Loader2 className="h-8 w-8 animate-spin text-primary" />
                      <p className="text-muted-foreground">Loading exceptions...</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : filteredExceptions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <FileText className="h-12 w-12 text-muted-foreground/50" />
                      <p className="text-muted-foreground">
                        {searchQuery
                          ? 'No exceptions match your search.'
                          : 'No exceptions created yet.'}
                      </p>
                      <Button variant="outline" size="sm" onClick={() => setCreateDialogOpen(true)}>
                        <Plus className="h-4 w-4 mr-2" />
                        Create First Exception
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredExceptions.map((exc) => {
                  const typeConfig = exceptionTypeConfig[exc.exception_type] || exceptionTypeConfig.risk_accepted;
                  const TypeIcon = typeConfig.icon;
                  const sConfig = exc.is_expired
                    ? statusConfig.expired
                    : statusConfig[exc.status] || statusConfig.approved;

                  return (
                    <TableRow
                      key={exc.id}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => handleSelectException(exc)}
                    >
                      <TableCell>
                        <Badge className={cn('border', typeConfig.color)}>
                          <TypeIcon className="h-3 w-3 mr-1" />
                          {typeConfig.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{exc.title}</span>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn('border', sConfig.color)}>
                          {sConfig.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {exc.residual_risk ? (
                          <span className={cn('font-medium capitalize', residualRiskConfig[exc.residual_risk]?.color)}>
                            {exc.residual_risk}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{exc.findings_count}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{exc.requested_by}</span>
                      </TableCell>
                      <TableCell>
                        {exc.expiration_date ? (
                          <span className={cn('text-sm', exc.is_expired ? 'text-red-400' : 'text-muted-foreground')}>
                            {formatDate(exc.expiration_date)}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">Never</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </Card>

        {/* Exception Detail Dialog */}
        <Dialog open={!!selectedException} onOpenChange={() => setSelectedException(null)}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            {selectedException && (
              <>
                <DialogHeader>
                  <div className="flex items-center gap-2">
                    <Badge className={cn('border', exceptionTypeConfig[selectedException.exception_type]?.color)}>
                      {exceptionTypeConfig[selectedException.exception_type]?.label || selectedException.exception_type}
                    </Badge>
                    <Badge className={cn('border', selectedException.is_expired ? statusConfig.expired.color : statusConfig[selectedException.status]?.color)}>
                      {selectedException.is_expired ? 'Expired' : statusConfig[selectedException.status]?.label}
                    </Badge>
                  </div>
                  <DialogTitle className="text-xl mt-2">{selectedException.title}</DialogTitle>
                  <DialogDescription>Exception details and linked findings</DialogDescription>
                </DialogHeader>

                <div className="space-y-6 py-4">
                  {/* Justification */}
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Justification</p>
                    <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                      {selectedException.justification}
                    </p>
                  </div>

                  {/* Business Impact */}
                  {selectedException.business_impact && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium">Business Impact</p>
                      <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                        {selectedException.business_impact}
                      </p>
                    </div>
                  )}

                  {/* Compensating Controls */}
                  {selectedException.compensating_controls && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-green-400" />
                        Compensating Controls
                      </p>
                      <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                        {selectedException.compensating_controls}
                      </p>
                    </div>
                  )}

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Residual Risk</p>
                      <p className={cn('font-medium capitalize', residualRiskConfig[selectedException.residual_risk || 'medium']?.color)}>
                        {selectedException.residual_risk || 'Not specified'}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Requested By</p>
                      <p className="font-medium">{selectedException.requested_by}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Approved By</p>
                      <p className="font-medium">{selectedException.approved_by || '-'}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Created</p>
                      <p className="font-medium">{formatDate(selectedException.created_at)}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Expires</p>
                      <p className={cn('font-medium', selectedException.is_expired && 'text-red-400')}>
                        {selectedException.expiration_date ? formatDate(selectedException.expiration_date) : 'Never'}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Review Date</p>
                      <p className="font-medium">
                        {selectedException.review_date ? formatDate(selectedException.review_date) : 'Not set'}
                      </p>
                    </div>
                  </div>

                  {/* Linked Findings */}
                  {selectedException.findings && selectedException.findings.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-sm font-medium flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Linked Findings ({selectedException.findings.length})
                      </p>
                      <div className="border rounded-lg divide-y">
                        {selectedException.findings.map((finding) => (
                          <div key={finding.id} className="p-3 flex items-center gap-3">
                            <Badge className={cn(
                              'text-xs',
                              finding.severity === 'critical' ? 'bg-red-600' :
                              finding.severity === 'high' ? 'bg-orange-500' :
                              finding.severity === 'medium' ? 'bg-yellow-500' :
                              'bg-blue-500'
                            )}>
                              {finding.severity}
                            </Badge>
                            <div className="flex-1">
                              <p className="text-sm font-medium">{finding.title}</p>
                              {finding.host && (
                                <p className="text-xs text-muted-foreground">{finding.host}</p>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <DialogFooter>
                  <Button
                    variant="destructive"
                    onClick={() => handleDeleteException(selectedException.id)}
                  >
                    Delete Exception
                  </Button>
                </DialogFooter>
              </>
            )}
          </DialogContent>
        </Dialog>

        {/* Create Exception Dialog */}
        <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create Exception</DialogTitle>
              <DialogDescription>
                Document a risk acceptance, mitigation, or false positive for findings.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Title *</label>
                <Input
                  placeholder="e.g., Legacy system SSL certificate exception"
                  value={newException.title}
                  onChange={(e) => setNewException({ ...newException, title: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Exception Type *</label>
                  <Select
                    value={newException.exception_type}
                    onValueChange={(value) => setNewException({ ...newException, exception_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="risk_accepted">Risk Accepted</SelectItem>
                      <SelectItem value="mitigated">Mitigated</SelectItem>
                      <SelectItem value="false_positive">False Positive</SelectItem>
                      <SelectItem value="deferred">Deferred</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Residual Risk</label>
                  <Select
                    value={newException.residual_risk}
                    onValueChange={(value) => setNewException({ ...newException, residual_risk: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Justification *</label>
                <textarea
                  className="w-full min-h-[100px] rounded-md border border-input bg-background px-3 py-2 text-sm"
                  placeholder="Why is this exception being requested? What is the business justification?"
                  value={newException.justification}
                  onChange={(e) => setNewException({ ...newException, justification: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Business Impact</label>
                <textarea
                  className="w-full min-h-[80px] rounded-md border border-input bg-background px-3 py-2 text-sm"
                  placeholder="What is the business impact of not remediating?"
                  value={newException.business_impact}
                  onChange={(e) => setNewException({ ...newException, business_impact: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Compensating Controls</label>
                <textarea
                  className="w-full min-h-[80px] rounded-md border border-input bg-background px-3 py-2 text-sm"
                  placeholder="What controls are in place to mitigate the risk?"
                  value={newException.compensating_controls}
                  onChange={(e) => setNewException({ ...newException, compensating_controls: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Expiration Date</label>
                  <Input
                    type="date"
                    value={newException.expiration_date}
                    onChange={(e) => setNewException({ ...newException, expiration_date: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Review Date</label>
                  <Input
                    type="date"
                    value={newException.review_date}
                    onChange={(e) => setNewException({ ...newException, review_date: e.target.value })}
                  />
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateException} disabled={creating}>
                {creating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Create Exception
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}
