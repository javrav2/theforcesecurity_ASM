'use client';

import { useState } from 'react';
import { Finding, Asset, SeverityLevel } from '@/types/asm';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { formatDistanceToNow } from 'date-fns';
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
import { ShieldAlert, CheckCircle, XCircle, Globe, ArrowUpDown, ExternalLink, Copy } from 'lucide-react';
import { TableCustomization } from '@/components/table/TableCustomization';
import { useToast } from '@/hooks/use-toast';

interface FindingsTableProps {
  findings: Finding[];
  assets: Asset[];
  onStatusChange?: (findingId: number, status: string) => void;
}

const severityColors: Record<SeverityLevel, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};

export function FindingsTable({ findings, assets, onStatusChange }: FindingsTableProps) {
  const { toast } = useToast();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [sortColumn, setSortColumn] = useState<string>('severity');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [columns, setColumns] = useState([
    { key: 'severity', label: 'Severity', visible: true },
    { key: 'asset', label: 'Asset', visible: true },
    { key: 'title', label: 'Title', visible: true },
    { key: 'category', label: 'Category', visible: true },
    { key: 'status', label: 'Status', visible: true },
    { key: 'discovered', label: 'Discovered', visible: true },
  ]);

  const getAssetForFinding = (finding: Finding) => {
    return assets.find(a => a.id === finding.assetId);
  };

  // Severity priority for sorting
  const severityPriority: Record<SeverityLevel, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  // Filter and sort findings
  let displayedFindings = findings.filter(finding => {
    const matchesSeverity = filterSeverity === 'all' || finding.severity === filterSeverity;
    const matchesStatus = filterStatus === 'all' || finding.status === filterStatus;
    const asset = getAssetForFinding(finding);
    const matchesSearch = searchQuery === '' || 
      finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset?.value.toLowerCase().includes(searchQuery.toLowerCase());
    
    return matchesSeverity && matchesStatus && matchesSearch;
  });

  // Sort findings
  if (sortColumn) {
    displayedFindings = [...displayedFindings].sort((a, b) => {
      let aVal: any = a[sortColumn as keyof Finding];
      let bVal: any = b[sortColumn as keyof Finding];

      if (sortColumn === 'asset') {
        aVal = getAssetForFinding(a)?.value || '';
        bVal = getAssetForFinding(b)?.value || '';
      }

      if (sortColumn === 'severity') {
        aVal = severityPriority[a.severity];
        bVal = severityPriority[b.severity];
      }

      if (sortColumn === 'discovered') {
        aVal = new Date(a.discoveredAt).getTime();
        bVal = new Date(b.discoveredAt).getTime();
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }

  const handleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('desc');
    }
  };

  const handleExport = () => {
    const csv = [
      ['Severity', 'Asset', 'Title', 'Category', 'Status', 'Discovered', 'CVE', 'CVSS'],
      ...displayedFindings.map(f => [
        f.severity,
        getAssetForFinding(f)?.value || 'N/A',
        f.title,
        f.category,
        f.status,
        new Date(f.discoveredAt).toISOString(),
        f.cveId || '',
        f.cvssScore?.toString() || '',
      ]),
    ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: 'Copied to clipboard' });
  };

  const handleStatusChange = (findingId: number, newStatus: string) => {
    if (onStatusChange) {
      onStatusChange(findingId, newStatus);
    }
    setSelectedFinding(null);
  };

  const visibleColumns = columns.filter(c => c.visible);

  // Count by severity
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <>
      {/* Summary Cards */}
      <div className="grid grid-cols-5 gap-2 mb-4">
        {(['critical', 'high', 'medium', 'low', 'info'] as SeverityLevel[]).map(severity => (
          <div 
            key={severity}
            className={`p-3 rounded-lg cursor-pointer transition-all ${
              filterSeverity === severity ? 'ring-2 ring-primary' : ''
            } ${severityColors[severity]}`}
            onClick={() => setFilterSeverity(filterSeverity === severity ? 'all' : severity)}
          >
            <div className="text-2xl font-bold">{severityCounts[severity] || 0}</div>
            <div className="text-sm capitalize">{severity}</div>
          </div>
        ))}
      </div>

      <TableCustomization
        columns={columns}
        onColumnVisibilityChange={setColumns}
        onExport={handleExport}
        onSort={handleSort}
        onSearch={setSearchQuery}
        filters={[
          {
            key: 'severity',
            label: 'Severity',
            options: [
              { label: 'Critical', value: 'critical' },
              { label: 'High', value: 'high' },
              { label: 'Medium', value: 'medium' },
              { label: 'Low', value: 'low' },
              { label: 'Info', value: 'info' },
            ],
          },
          {
            key: 'status',
            label: 'Status',
            options: [
              { label: 'Open', value: 'open' },
              { label: 'Resolved', value: 'resolved' },
              { label: 'Ignored', value: 'ignored' },
              { label: 'False Positive', value: 'false_positive' },
            ],
          },
        ]}
        onFilterChange={(key, value) => {
          if (key === 'severity') setFilterSeverity(value);
          if (key === 'status') setFilterStatus(value);
        }}
      >
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                {visibleColumns.map(col => (
                  <TableHead 
                    key={col.key} 
                    className="text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort(col.key)}
                  >
                    <div className="flex items-center gap-1">
                      {col.label}
                      <ArrowUpDown className={`h-3 w-3 ${sortColumn === col.key ? 'text-primary' : ''}`} />
                    </div>
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayedFindings.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={visibleColumns.length} className="text-center py-8 text-muted-foreground">
                    No findings match your filters
                  </TableCell>
                </TableRow>
              ) : (
                displayedFindings.map((finding) => {
                  const asset = getAssetForFinding(finding);
                  return (
                    <TableRow
                      key={finding.id}
                      className="border-border cursor-pointer transition-colors hover:bg-secondary/50"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      {columns.find(c => c.key === 'severity')?.visible && (
                        <TableCell>
                          <Badge className={severityColors[finding.severity]}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </TableCell>
                      )}
                      {columns.find(c => c.key === 'asset')?.visible && (
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4 text-muted-foreground" />
                            <code className="font-mono text-xs text-foreground truncate max-w-[200px]">
                              {asset?.value || 'N/A'}
                            </code>
                          </div>
                        </TableCell>
                      )}
                      {columns.find(c => c.key === 'title')?.visible && (
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            <span className="font-medium text-foreground truncate max-w-[300px]">
                              {finding.title}
                            </span>
                            {finding.cveId && (
                              <Badge variant="outline" className="text-xs">
                                {finding.cveId}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                      )}
                      {columns.find(c => c.key === 'category')?.visible && (
                        <TableCell>
                          <code className="font-mono text-xs text-muted-foreground">
                            {finding.category}
                          </code>
                        </TableCell>
                      )}
                      {columns.find(c => c.key === 'status')?.visible && (
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            {finding.status === 'open' ? (
                              <XCircle className="h-4 w-4 text-red-500" />
                            ) : finding.status === 'resolved' ? (
                              <CheckCircle className="h-4 w-4 text-green-500" />
                            ) : (
                              <div className="h-4 w-4 rounded-full bg-gray-400" />
                            )}
                            <span className="text-sm capitalize">{finding.status.replace('_', ' ')}</span>
                          </div>
                        </TableCell>
                      )}
                      {columns.find(c => c.key === 'discovered')?.visible && (
                        <TableCell className="text-muted-foreground text-sm">
                          {formatDistanceToNow(new Date(finding.discoveredAt), { addSuffix: true })}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </TableCustomization>

      {/* Finding Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={() => setSelectedFinding(null)}>
        <DialogContent className="max-w-3xl bg-card border-border max-h-[80vh] overflow-y-auto">
          {selectedFinding && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-3 flex-wrap">
                  <Badge className={severityColors[selectedFinding.severity]}>
                    {selectedFinding.severity.toUpperCase()}
                  </Badge>
                  {selectedFinding.cveId && (
                    <Badge variant="outline">{selectedFinding.cveId}</Badge>
                  )}
                  {selectedFinding.cvssScore && (
                    <Badge variant="secondary">CVSS: {selectedFinding.cvssScore}</Badge>
                  )}
                  <Badge variant={selectedFinding.status === 'open' ? 'destructive' : 'secondary'}>
                    {selectedFinding.status.replace('_', ' ').toUpperCase()}
                  </Badge>
                </div>
                <DialogTitle className="text-foreground text-xl mt-2">
                  {selectedFinding.title}
                </DialogTitle>
                <DialogDescription className="text-muted-foreground mt-2">
                  {selectedFinding.description}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 mt-4">
                {/* Asset Info */}
                <div className="rounded-lg bg-secondary/50 p-4">
                  <h4 className="text-sm font-medium text-foreground mb-2">Affected Asset</h4>
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-muted-foreground" />
                    <code className="font-mono text-sm">
                      {getAssetForFinding(selectedFinding)?.value || 'Unknown'}
                    </code>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopy(getAssetForFinding(selectedFinding)?.value || '')}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>

                {/* Category & Template */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="rounded-lg bg-secondary/50 p-4">
                    <h4 className="text-sm font-medium text-foreground mb-2">Category</h4>
                    <code className="font-mono text-sm">{selectedFinding.category}</code>
                  </div>
                  {selectedFinding.templateId && (
                    <div className="rounded-lg bg-secondary/50 p-4">
                      <h4 className="text-sm font-medium text-foreground mb-2">Template ID</h4>
                      <code className="font-mono text-sm">{selectedFinding.templateId}</code>
                    </div>
                  )}
                </div>

                {/* Matched At / Evidence */}
                {selectedFinding.matchedAt && (
                  <div className="rounded-lg bg-secondary/50 p-4">
                    <h4 className="text-sm font-medium text-foreground mb-2">Matched At</h4>
                    <code className="font-mono text-xs break-all">{selectedFinding.matchedAt}</code>
                  </div>
                )}

                {/* Details */}
                {selectedFinding.details && Object.keys(selectedFinding.details).length > 0 && (
                  <div className="rounded-lg bg-secondary/50 p-4">
                    <h4 className="text-sm font-medium text-foreground mb-2">Details</h4>
                    <pre className="text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(selectedFinding.details, null, 2)}
                    </pre>
                  </div>
                )}

                {/* References */}
                {selectedFinding.reference && selectedFinding.reference.length > 0 && (
                  <div className="rounded-lg bg-secondary/50 p-4">
                    <h4 className="text-sm font-medium text-foreground mb-2">References</h4>
                    <ul className="space-y-1">
                      {selectedFinding.reference.map((ref, idx) => (
                        <li key={idx}>
                          <a 
                            href={ref} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-sm text-primary hover:underline flex items-center gap-1"
                          >
                            {ref}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Remediation */}
                {selectedFinding.remediation && (
                  <div className="rounded-lg bg-green-500/10 border border-green-500/20 p-4">
                    <h4 className="text-sm font-medium text-green-600 dark:text-green-400 mb-2">
                      Remediation
                    </h4>
                    <p className="text-sm text-foreground whitespace-pre-wrap">
                      {selectedFinding.remediation}
                    </p>
                  </div>
                )}

                {/* Discovery Info */}
                <div className="text-xs text-muted-foreground">
                  Discovered {formatDistanceToNow(new Date(selectedFinding.discoveredAt), { addSuffix: true })}
                </div>

                {/* Actions */}
                <div className="flex gap-3 pt-4 border-t">
                  <Button 
                    variant="default" 
                    className="flex-1"
                    onClick={() => handleStatusChange(selectedFinding.id, 'resolved')}
                    disabled={selectedFinding.status === 'resolved'}
                  >
                    <CheckCircle className="h-4 w-4 mr-2" />
                    Mark as Resolved
                  </Button>
                  <Button 
                    variant="outline" 
                    className="flex-1"
                    onClick={() => handleStatusChange(selectedFinding.id, 'false_positive')}
                    disabled={selectedFinding.status === 'false_positive'}
                  >
                    False Positive
                  </Button>
                  <Button 
                    variant="outline" 
                    className="flex-1"
                    onClick={() => handleStatusChange(selectedFinding.id, 'ignored')}
                    disabled={selectedFinding.status === 'ignored'}
                  >
                    Ignore
                  </Button>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

