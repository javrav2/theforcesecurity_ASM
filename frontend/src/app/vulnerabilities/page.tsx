'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
  AlertTriangle,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV, getSeverityBgColor } from '@/lib/utils';

interface Vulnerability {
  id: number;
  template_id: string;
  name: string;
  severity: string;
  host: string;
  matched_at?: string;
  description?: string;
  reference?: string[];
  tags?: string[];
  created_at: string;
}

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [stats, setStats] = useState<any>(null);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [vulnsData, summaryData] = await Promise.all([
        api.getVulnerabilities({
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          limit: 100,
        }),
        api.getVulnerabilitiesSummary(),
      ]);

      setVulnerabilities(vulnsData.items || vulnsData || []);
      setStats(summaryData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch vulnerabilities',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [severityFilter]);

  const handleExport = () => {
    downloadCSV(
      vulnerabilities.map((v) => ({
        name: v.name,
        severity: v.severity,
        host: v.host,
        template_id: v.template_id,
        matched_at: v.matched_at || '',
        created_at: v.created_at,
      })),
      'vulnerabilities'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  const filteredVulns = vulnerabilities.filter(
    (v) =>
      v.name?.toLowerCase().includes(search.toLowerCase()) ||
      v.host?.toLowerCase().includes(search.toLowerCase()) ||
      v.template_id?.toLowerCase().includes(search.toLowerCase())
  );

  const severityCounts = {
    critical: stats?.by_severity?.critical || 0,
    high: stats?.by_severity?.high || 0,
    medium: stats?.by_severity?.medium || 0,
    low: stats?.by_severity?.low || 0,
  };

  return (
    <MainLayout>
      <Header title="Vulnerabilities" subtitle="Security findings from vulnerability scans" />

      <div className="p-6 space-y-6">
        {/* Severity Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Critical', count: severityCounts.critical, color: 'bg-red-600', textColor: 'text-red-400' },
            { label: 'High', count: severityCounts.high, color: 'bg-orange-500', textColor: 'text-orange-400' },
            { label: 'Medium', count: severityCounts.medium, color: 'bg-yellow-500', textColor: 'text-yellow-400' },
            { label: 'Low', count: severityCounts.low, color: 'bg-green-500', textColor: 'text-green-400' },
          ].map((item) => (
            <Card
              key={item.label}
              className={`cursor-pointer transition-all ${
                severityFilter === item.label.toLowerCase() ? 'ring-2 ring-primary' : ''
              }`}
              onClick={() =>
                setSeverityFilter(
                  severityFilter === item.label.toLowerCase() ? 'all' : item.label.toLowerCase()
                )
              }
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">{item.label}</p>
                    <p className={`text-2xl font-bold ${item.textColor}`}>{item.count}</p>
                  </div>
                  <div className={`w-3 h-12 rounded-full ${item.color}`} />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search vulnerabilities..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="flex items-center gap-2">
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>

            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {/* Vulnerabilities Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Vulnerability</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Template</TableHead>
                <TableHead>Discovered</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : filteredVulns.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No vulnerabilities found. Run a scan to discover security issues.
                  </TableCell>
                </TableRow>
              ) : (
                filteredVulns.map((vuln) => (
                  <TableRow
                    key={vuln.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedVuln(vuln)}
                  >
                    <TableCell>
                      <Badge className={getSeverityBgColor(vuln.severity)}>
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{vuln.name || vuln.template_id}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <a
                        href={`https://${vuln.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline flex items-center gap-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {vuln.host}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {vuln.template_id}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {formatDate(vuln.created_at)}
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

        {/* Vulnerability Detail Dialog */}
        <Dialog open={!!selectedVuln} onOpenChange={() => setSelectedVuln(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <div className="flex items-center gap-2">
                <Badge className={getSeverityBgColor(selectedVuln?.severity || '')}>
                  {selectedVuln?.severity}
                </Badge>
                <DialogTitle>{selectedVuln?.name || selectedVuln?.template_id}</DialogTitle>
              </div>
              <DialogDescription>Vulnerability details and remediation information</DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Host</p>
                  <a
                    href={`https://${selectedVuln?.host}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline flex items-center gap-1"
                  >
                    {selectedVuln?.host}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Template ID</p>
                  <p className="font-mono text-sm">{selectedVuln?.template_id}</p>
                </div>
              </div>

              {selectedVuln?.matched_at && (
                <div>
                  <p className="text-sm text-muted-foreground">Matched At</p>
                  <p className="font-mono text-sm break-all">{selectedVuln.matched_at}</p>
                </div>
              )}

              {selectedVuln?.description && (
                <div>
                  <p className="text-sm text-muted-foreground">Description</p>
                  <p className="text-sm">{selectedVuln.description}</p>
                </div>
              )}

              {selectedVuln?.tags && selectedVuln.tags.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Tags</p>
                  <div className="flex flex-wrap gap-1">
                    {selectedVuln.tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {selectedVuln?.reference && selectedVuln.reference.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">References</p>
                  <div className="space-y-1">
                    {selectedVuln.reference.map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1"
                      >
                        {ref}
                        <ExternalLink className="h-3 w-3" />
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



