'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent } from '@/components/ui/card';
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Shield,
  Search,
  Download,
  Loader2,
  ExternalLink,
  ChevronRight,
  Filter,
  AlertCircle,
  Clock,
  Tag,
  FileCode,
  Target,
  Activity,
  User,
  Calendar,
  Link as LinkIcon,
  Info,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV, cn } from '@/lib/utils';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  id: number;
  title: string;
  name?: string;
  template_id: string;
  severity: string;
  host: string;
  matched_at?: string;
  description?: string;
  references?: string[];
  reference?: string[];
  tags?: string[];
  created_at: string;
  updated_at?: string;
  first_detected?: string;
  last_detected?: string;
  // Extended metadata
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  status?: string;
  assigned_to?: string;
  evidence?: string;
  proof_of_concept?: string;
  remediation?: string;
  remediation_deadline?: string;
  detected_by?: string;
  matcher_name?: string;
  asset_id?: number;
  scan_id?: number;
  resolved_at?: string;
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const severityConfig: Record<Severity, { color: string; bgColor: string; textColor: string; borderColor: string }> = {
  critical: { 
    color: 'bg-red-600', 
    bgColor: 'bg-red-600/10', 
    textColor: 'text-red-400',
    borderColor: 'border-red-600/30'
  },
  high: { 
    color: 'bg-orange-500', 
    bgColor: 'bg-orange-500/10', 
    textColor: 'text-orange-400',
    borderColor: 'border-orange-500/30'
  },
  medium: { 
    color: 'bg-yellow-500', 
    bgColor: 'bg-yellow-500/10', 
    textColor: 'text-yellow-400',
    borderColor: 'border-yellow-500/30'
  },
  low: { 
    color: 'bg-green-500', 
    bgColor: 'bg-green-500/10', 
    textColor: 'text-green-400',
    borderColor: 'border-green-500/30'
  },
  info: { 
    color: 'bg-blue-500', 
    bgColor: 'bg-blue-500/10', 
    textColor: 'text-blue-400',
    borderColor: 'border-blue-500/30'
  },
};

const statusConfig: Record<string, { label: string; color: string }> = {
  open: { label: 'Open', color: 'bg-red-600/20 text-red-400 border-red-600/30' },
  in_progress: { label: 'In Progress', color: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30' },
  resolved: { label: 'Resolved', color: 'bg-green-600/20 text-green-400 border-green-600/30' },
  accepted: { label: 'Accepted', color: 'bg-blue-600/20 text-blue-400 border-blue-600/30' },
  false_positive: { label: 'False Positive', color: 'bg-gray-600/20 text-gray-400 border-gray-600/30' },
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [stats, setStats] = useState<any>(null);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch findings and summary in parallel
      const [findingsData, summaryData] = await Promise.all([
        api.getFindings({
          severity: selectedSeverity || undefined,
          limit: 100,
        }),
        api.getFindingsSummary(),
      ]);

      // Handle both array and paginated responses
      const items = Array.isArray(findingsData) ? findingsData : (findingsData.items || []);
      setFindings(items);
      setStats(summaryData);
    } catch (err: any) {
      console.error('Failed to fetch findings:', err);
      // Provide more specific error message
      const errorMessage = err.response?.data?.detail || err.message || 'Failed to fetch findings';
      setError(errorMessage);
      toast({
        title: 'Error',
        description: `Failed to fetch findings: ${errorMessage}`,
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedSeverity]);

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const handleSeverityFilter = (severity: Severity | null) => {
    setSelectedSeverity(severity === selectedSeverity ? null : severity);
  };

  const handleExport = () => {
    if (filteredFindings.length === 0) {
      toast({
        title: 'No Data',
        description: 'No findings to export.',
        variant: 'destructive',
      });
      return;
    }

    downloadCSV(
      filteredFindings.map((f) => ({
        title: f.title || f.name || '',
        severity: f.severity,
        host: f.host || '',
        template_id: f.template_id || '',
        cve_id: f.cve_id || '',
        cvss_score: f.cvss_score || '',
        status: f.status || 'open',
        detected_by: f.detected_by || '',
        matched_at: f.matched_at || '',
        first_detected: f.first_detected || f.created_at,
        description: f.description || '',
      })),
      'findings'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  // Filter findings by search query
  const filteredFindings = findings.filter((f) => {
    const searchLower = searchQuery.toLowerCase();
    return (
      (f.title || f.name || '').toLowerCase().includes(searchLower) ||
      (f.host || '').toLowerCase().includes(searchLower) ||
      (f.template_id || '').toLowerCase().includes(searchLower) ||
      (f.description || '').toLowerCase().includes(searchLower) ||
      (f.cve_id || '').toLowerCase().includes(searchLower)
    );
  });

  // Calculate severity counts
  const severityCounts: Record<Severity, number> = {
    critical: stats?.by_severity?.critical || 0,
    high: stats?.by_severity?.high || 0,
    medium: stats?.by_severity?.medium || 0,
    low: stats?.by_severity?.low || 0,
    info: stats?.by_severity?.info || 0,
  };

  const totalCount = stats?.total || findings.length;

  const getSeverityBadgeClass = (severity: string) => {
    const config = severityConfig[severity.toLowerCase() as Severity];
    return config 
      ? `${config.bgColor} ${config.textColor} ${config.borderColor} border` 
      : 'bg-gray-600/20 text-gray-400 border-gray-600/30 border';
  };

  const getStatusBadge = (status: string) => {
    const config = statusConfig[status] || statusConfig.open;
    return (
      <Badge className={`${config.color} border`}>
        {config.label}
      </Badge>
    );
  };

  return (
    <MainLayout>
      <Header title="Findings" subtitle="Security vulnerabilities and issues discovered in your assets" />

      <div className="p-6 space-y-6">
        {/* Severity Filter Pills */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleSeverityFilter(null)}
            className={cn(
              'rounded-full px-4 py-2 text-sm font-medium transition-all',
              !selectedSeverity
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
            )}
          >
            All ({totalCount})
          </button>
          {severities.map((severity) => {
            const config = severityConfig[severity];
            return (
              <button
                key={severity}
                onClick={() => handleSeverityFilter(severity)}
                className={cn(
                  'rounded-full px-4 py-2 text-sm font-medium transition-all flex items-center gap-2',
                  selectedSeverity === severity
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-secondary text-muted-foreground hover:bg-secondary/80'
                )}
              >
                <span className={cn('w-2 h-2 rounded-full', config.color)} />
                <span className="capitalize">{severity}</span>
                <span className={cn('text-xs px-1.5 py-0.5 rounded-full', config.bgColor, config.textColor)}>
                  {severityCounts[severity]}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search and Actions */}
        <div className="flex gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search findings by title, host, CVE, template..."
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              className="pl-10 bg-secondary/50 border-border"
            />
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm">
              <Filter className="h-4 w-4 mr-2" />
              More Filters
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </Button>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <Card className="border-red-600/30 bg-red-600/10">
            <CardContent className="p-4 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-red-400 font-medium">Failed to load findings</p>
                <p className="text-sm text-muted-foreground">{error}</p>
              </div>
              <Button variant="outline" size="sm" onClick={fetchData} className="ml-auto">
                Retry
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Findings Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[100px]">Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Detected</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Loader2 className="h-8 w-8 animate-spin text-primary" />
                      <p className="text-muted-foreground">Loading findings...</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : filteredFindings.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="h-12 w-12 text-muted-foreground/50" />
                      <p className="text-muted-foreground">
                        {searchQuery 
                          ? 'No findings match your search criteria.' 
                          : 'No findings discovered yet. Run a scan to discover security issues.'}
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredFindings.map((finding) => (
                  <TableRow
                    key={finding.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <TableCell>
                      <Badge className={getSeverityBadgeClass(finding.severity)}>
                        {finding.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
                          <span className="font-medium line-clamp-1">
                            {finding.title || finding.name || finding.template_id}
                          </span>
                        </div>
                        {finding.cve_id && (
                          <span className="text-xs text-primary font-mono">{finding.cve_id}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {finding.host ? (
                        <a
                          href={`https://${finding.host}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline flex items-center gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="truncate max-w-[200px]">{finding.host}</span>
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {getStatusBadge(finding.status || 'open')}
                    </TableCell>
                    <TableCell>
                      {finding.cvss_score ? (
                        <span className={cn(
                          'font-mono font-medium',
                          finding.cvss_score >= 9 ? 'text-red-400' :
                          finding.cvss_score >= 7 ? 'text-orange-400' :
                          finding.cvss_score >= 4 ? 'text-yellow-400' :
                          'text-green-400'
                        )}>
                          {finding.cvss_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(finding.first_detected || finding.created_at)}
                    </TableCell>
                    <TableCell>
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {/* Finding Detail Dialog */}
        <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className={getSeverityBadgeClass(selectedFinding?.severity || '')}>
                  {selectedFinding?.severity}
                </Badge>
                {selectedFinding?.status && getStatusBadge(selectedFinding.status)}
                {selectedFinding?.cvss_score && (
                  <Badge variant="outline" className="font-mono">
                    CVSS: {selectedFinding.cvss_score.toFixed(1)}
                  </Badge>
                )}
              </div>
              <DialogTitle className="text-xl mt-2">
                {selectedFinding?.title || selectedFinding?.name || selectedFinding?.template_id}
              </DialogTitle>
              <DialogDescription>
                Complete finding details and remediation information
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-4">
              {/* Quick Info Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="flex items-start gap-2">
                  <Target className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Host</p>
                    {selectedFinding?.host ? (
                      <a
                        href={`https://${selectedFinding.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.host}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <p className="text-sm text-muted-foreground">-</p>
                    )}
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <FileCode className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Template ID</p>
                    <p className="text-sm font-mono">{selectedFinding?.template_id || '-'}</p>
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <Activity className="h-4 w-4 text-muted-foreground mt-0.5" />
                  <div>
                    <p className="text-xs text-muted-foreground">Detected By</p>
                    <p className="text-sm">{selectedFinding?.detected_by || 'Nuclei'}</p>
                  </div>
                </div>

                {selectedFinding?.cve_id && (
                  <div className="flex items-start gap-2">
                    <AlertCircle className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVE ID</p>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cve_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cwe_id && (
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CWE ID</p>
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {selectedFinding.cwe_id}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}

                {selectedFinding?.cvss_vector && (
                  <div className="flex items-start gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">CVSS Vector</p>
                      <p className="text-sm font-mono text-xs">{selectedFinding.cvss_vector}</p>
                    </div>
                  </div>
                )}

                {selectedFinding?.assigned_to && (
                  <div className="flex items-start gap-2">
                    <User className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">Assigned To</p>
                      <p className="text-sm">{selectedFinding.assigned_to}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Timestamps */}
              <div className="flex flex-wrap gap-4 text-sm">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Clock className="h-4 w-4" />
                  <span>First Detected: {formatDate(selectedFinding?.first_detected || selectedFinding?.created_at || '')}</span>
                </div>
                {selectedFinding?.last_detected && selectedFinding.last_detected !== selectedFinding.first_detected && (
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Calendar className="h-4 w-4" />
                    <span>Last Detected: {formatDate(selectedFinding.last_detected)}</span>
                  </div>
                )}
                {selectedFinding?.resolved_at && (
                  <div className="flex items-center gap-2 text-green-400">
                    <Clock className="h-4 w-4" />
                    <span>Resolved: {formatDate(selectedFinding.resolved_at)}</span>
                  </div>
                )}
              </div>

              {/* Matched At / Evidence */}
              {selectedFinding?.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    Matched At
                  </p>
                  <div className="p-3 bg-secondary/50 rounded-lg">
                    <code className="text-sm break-all">{selectedFinding.matched_at}</code>
                  </div>
                </div>
              )}

              {/* Description */}
              {selectedFinding?.description && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Description</p>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

              {/* Evidence */}
              {selectedFinding?.evidence && selectedFinding.evidence !== selectedFinding.matched_at && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Evidence</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                </div>
              )}

              {/* Proof of Concept */}
              {selectedFinding?.proof_of_concept && (
                <div className="space-y-2">
                  <p className="text-sm font-medium">Proof of Concept</p>
                  <div className="p-3 bg-secondary/50 rounded-lg overflow-x-auto">
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
                      {selectedFinding.proof_of_concept}
                    </pre>
                  </div>
                </div>
              )}

              {/* Remediation */}
              {selectedFinding?.remediation && (
                <div className="space-y-2">
                  <p className="text-sm font-medium text-green-400">Remediation</p>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {selectedFinding.remediation}
                  </p>
                  {selectedFinding.remediation_deadline && (
                    <p className="text-xs text-yellow-400">
                      Deadline: {formatDate(selectedFinding.remediation_deadline)}
                    </p>
                  )}
                </div>
              )}

              {/* Tags */}
              {selectedFinding?.tags && selectedFinding.tags.length > 0 && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <Tag className="h-4 w-4" />
                    Tags
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {selectedFinding.tags.map((tag, i) => (
                      <Badge key={i} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {((selectedFinding?.references && selectedFinding.references.length > 0) ||
                (selectedFinding?.reference && selectedFinding.reference.length > 0)) && (
                <div className="space-y-2">
                  <p className="text-sm font-medium flex items-center gap-2">
                    <LinkIcon className="h-4 w-4" />
                    References
                  </p>
                  <div className="space-y-1">
                    {(selectedFinding.references || selectedFinding.reference || []).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1 break-all"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}
