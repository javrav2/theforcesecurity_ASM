'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
  Download,
  ExternalLink,
  FileWarning,
  Globe,
  History,
  Loader2,
  Play,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Link,
  FileText,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface DomainResult {
  domain: string;
  success: boolean;
  url_count: number;
  interesting_count: number;
  elapsed_time: number;
  error?: string;
}

interface WaybackResult {
  domain?: string;
  domains_scanned?: number;
  total_urls: number;
  total_interesting?: number;
  interesting_count?: number;
  url_count?: number;
  unique_paths_count?: number;
  file_extensions: Record<string, number>;
  urls: string[];
  interesting_urls: string[];
  unique_paths?: string[];
  domain_results?: DomainResult[];
  elapsed_time?: number;
}

export default function WaybackPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<WaybackResult | null>(null);
  const [mode, setMode] = useState<'single' | 'organization'>('single');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | 'interesting' | 'extensions'>('interesting');
  const [toolStatus, setToolStatus] = useState<{ installed: boolean } | null>(null);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [orgsData, status] = await Promise.all([
        api.getOrganizations(),
        api.get('/waybackurls/status').then(r => r.data).catch(() => null)
      ]);
      setOrganizations(orgsData);
      setToolStatus(status);
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunWayback = async () => {
    if (mode === 'single' && !domain) {
      toast({
        title: 'Error',
        description: 'Please enter a domain',
        variant: 'destructive',
      });
      return;
    }

    if (mode === 'organization' && !selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please select an organization',
        variant: 'destructive',
      });
      return;
    }

    setRunning(true);
    setResults(null);
    try {
      let result;
      if (mode === 'single') {
        const response = await api.post('/waybackurls/fetch', {
          domain,
          no_subs: !includeSubdomains,
          timeout: 120
        });
        result = response.data;
      } else {
        const response = await api.post('/waybackurls/fetch/organization', {
          organization_id: parseInt(selectedOrg),
          include_subdomains: includeSubdomains,
          timeout_per_domain: 120,
          max_concurrent: 3
        });
        result = response.data;
      }

      setResults(result);
      
      const totalUrls = result.total_urls || result.url_count || 0;
      const interestingCount = result.total_interesting || result.interesting_count || 0;
      
      toast({
        title: 'Wayback Scan Complete',
        description: `Found ${totalUrls} URLs, ${interestingCount} potentially interesting`,
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to run wayback scan',
        variant: 'destructive',
      });
    } finally {
      setRunning(false);
    }
  };

  const downloadResults = () => {
    if (!results) return;
    
    const data = {
      timestamp: new Date().toISOString(),
      mode,
      ...results
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wayback-${mode === 'single' ? domain : `org-${selectedOrg}`}-${Date.now()}.json`;
    a.click();
  };

  const totalUrls = results?.total_urls || results?.url_count || 0;
  const interestingCount = results?.total_interesting || results?.interesting_count || 0;
  const uniquePathsCount = results?.unique_paths_count || results?.unique_paths?.length || 0;

  return (
    <MainLayout>
      <Header title="Wayback URLs" subtitle="Fetch historical URLs from the Wayback Machine" />

      <div className="p-6 space-y-6">
        {/* Tool Status */}
        {toolStatus && !toolStatus.installed && (
          <Card className="border-destructive">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <span>waybackurls tool is not installed. Please rebuild the backend container.</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Run Wayback Scan */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Wayback URL Scanner
            </CardTitle>
            <CardDescription>
              Fetch all historical URLs known to the Wayback Machine for domains and subdomains.
              Useful for finding old endpoints, APIs, and sensitive files.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Mode Selection */}
            <div className="flex gap-4">
              <Button
                variant={mode === 'single' ? 'default' : 'outline'}
                onClick={() => setMode('single')}
              >
                Single Domain
              </Button>
              <Button
                variant={mode === 'organization' ? 'default' : 'outline'}
                onClick={() => setMode('organization')}
              >
                Organization Assets
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {mode === 'single' ? (
                <div className="space-y-2">
                  <Label>Domain</Label>
                  <Input
                    placeholder="example.com"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <Label>Organization</Label>
                  <Select value={selectedOrg} onValueChange={setSelectedOrg}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select organization" />
                    </SelectTrigger>
                    <SelectContent>
                      {organizations.map((org) => (
                        <SelectItem key={org.id} value={org.id.toString()}>
                          {org.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <div className="flex items-center gap-2 pt-7">
                <Switch
                  checked={includeSubdomains}
                  onCheckedChange={setIncludeSubdomains}
                />
                <Label>Include Subdomains</Label>
              </div>

              <div className="flex items-end">
                <Button
                  onClick={handleRunWayback}
                  disabled={running || (mode === 'single' ? !domain : !selectedOrg)}
                  className="w-full"
                >
                  {running ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Fetching...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Fetch URLs
                    </>
                  )}
                </Button>
              </div>
            </div>

            {running && (
              <div className="p-4 bg-muted rounded-lg">
                <div className="flex items-center gap-3">
                  <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  <div>
                    <p className="font-medium">Fetching historical URLs...</p>
                    <p className="text-sm text-muted-foreground">
                      Querying the Wayback Machine. This may take a while for domains with many URLs.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <Link className="h-8 w-8 text-blue-500" />
                    <div>
                      <p className="text-2xl font-bold">{totalUrls.toLocaleString()}</p>
                      <p className="text-sm text-muted-foreground">Total URLs</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <FileWarning className="h-8 w-8 text-orange-500" />
                    <div>
                      <p className="text-2xl font-bold">{interestingCount.toLocaleString()}</p>
                      <p className="text-sm text-muted-foreground">Interesting</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <FileText className="h-8 w-8 text-green-500" />
                    <div>
                      <p className="text-2xl font-bold">{uniquePathsCount.toLocaleString()}</p>
                      <p className="text-sm text-muted-foreground">Unique Paths</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <Clock className="h-8 w-8 text-gray-500" />
                    <div>
                      <p className="text-2xl font-bold">
                        {(results.elapsed_time || 0).toFixed(1)}s
                      </p>
                      <p className="text-sm text-muted-foreground">Elapsed</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Domain Results (for organization mode) */}
            {results.domain_results && results.domain_results.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Domain Results</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Domain</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead className="text-right">URLs</TableHead>
                        <TableHead className="text-right">Interesting</TableHead>
                        <TableHead className="text-right">Time</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.domain_results.map((dr) => (
                        <TableRow key={dr.domain}>
                          <TableCell className="font-mono text-sm">{dr.domain}</TableCell>
                          <TableCell>
                            {dr.success ? (
                              <Badge variant="default" className="bg-green-600">
                                <CheckCircle className="h-3 w-3 mr-1" />
                                Success
                              </Badge>
                            ) : (
                              <Badge variant="destructive">
                                <XCircle className="h-3 w-3 mr-1" />
                                {dr.error?.substring(0, 20) || 'Failed'}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-right">{dr.url_count}</TableCell>
                          <TableCell className="text-right">{dr.interesting_count}</TableCell>
                          <TableCell className="text-right">{dr.elapsed_time.toFixed(1)}s</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}

            {/* File Extensions */}
            {Object.keys(results.file_extensions).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>File Extensions Found</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(results.file_extensions).slice(0, 30).map(([ext, count]) => (
                      <Badge key={ext} variant="secondary" className="flex items-center gap-1">
                        {ext}
                        <span className="text-xs bg-muted px-1 rounded">{count}</span>
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* URLs */}
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle>Discovered URLs</CardTitle>
                  <Button variant="outline" size="sm" onClick={downloadResults}>
                    <Download className="h-4 w-4 mr-2" />
                    Export JSON
                  </Button>
                </div>
                <div className="flex gap-2 mt-2">
                  <Button
                    variant={activeTab === 'interesting' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('interesting')}
                  >
                    <AlertTriangle className="h-4 w-4 mr-1" />
                    Interesting ({results.interesting_urls.length})
                  </Button>
                  <Button
                    variant={activeTab === 'all' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('all')}
                  >
                    All URLs ({results.urls.length})
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="max-h-96 overflow-y-auto space-y-1">
                  {activeTab === 'interesting' && (
                    results.interesting_urls.length > 0 ? (
                      results.interesting_urls.slice(0, 200).map((url, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                          <a
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex-1 truncate text-primary hover:underline"
                          >
                            {url}
                          </a>
                          <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        </div>
                      ))
                    ) : (
                      <p className="text-muted-foreground">No interesting URLs found</p>
                    )
                  )}
                  {activeTab === 'all' && (
                    results.urls.length > 0 ? (
                      results.urls.slice(0, 500).map((url, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                          <a
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex-1 truncate text-primary hover:underline"
                          >
                            {url}
                          </a>
                          <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                        </div>
                      ))
                    ) : (
                      <p className="text-muted-foreground">No URLs found</p>
                    )
                  )}
                  {((activeTab === 'interesting' && results.interesting_urls.length > 200) ||
                    (activeTab === 'all' && results.urls.length > 500)) && (
                    <p className="text-sm text-muted-foreground p-2">
                      Showing first {activeTab === 'interesting' ? 200 : 500} URLs. Export JSON for full list.
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Help Section */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">About Wayback URLs</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>
              <strong>What is waybackurls?</strong> A tool by{' '}
              <a href="https://github.com/tomnomnom/waybackurls" target="_blank" rel="noopener noreferrer" className="text-primary underline">
                tomnomnom
              </a>{' '}
              that fetches all URLs the Wayback Machine has archived for a domain.
            </p>
            <p>
              <strong>Why is this useful?</strong> Historical URLs can reveal:
            </p>
            <ul className="list-disc pl-6 space-y-1">
              <li>Old/forgotten endpoints that may still be accessible</li>
              <li>API endpoints with parameters</li>
              <li>Backup files, config files, and sensitive data</li>
              <li>Admin panels and login pages</li>
              <li>Development/staging environments</li>
            </ul>
            <p>
              <strong>Interesting patterns:</strong> URLs containing admin, api, backup, config, .sql, .bak, .env, etc. are automatically highlighted.
            </p>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}











