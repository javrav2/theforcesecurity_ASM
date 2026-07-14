'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
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
  Code,
  Download,
  ExternalLink,
  FileCode,
  FolderTree,
  Globe,
  Hash,
  Loader2,
  RefreshCw,
  Route,
  Search,
  AlertTriangle,
  Server,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface AppStructureSummary {
  total_paths: number;
  total_urls: number;
  total_parameters: number;
  total_js_files: number;
  total_api_endpoints: number;
  total_interesting_urls: number;
  scans_included: number;
}

interface AppStructureData {
  summary: AppStructureSummary;
  paths: string[];
  urls: string[];
  parameters: string[];
  js_files: string[];
  api_endpoints: string[];
  interesting_urls: string[];
  file_extensions: Record<string, number>;
  source_breakdown: Record<string, Record<string, number>>;
}

interface AppStructureScan {
  id: number;
  name: string;
  scan_type: string;
  targets: string[];
  completed_at: string;
  organization_id: number;
  item_counts: Record<string, number>;
}

type TabType = 'paths' | 'urls' | 'parameters' | 'js_files' | 'api_endpoints' | 'interesting';

export default function AppStructureContent() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrg, setSelectedOrg] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<TabType>('paths');
  const [data, setData] = useState<AppStructureData | null>(null);
  const [scans, setScans] = useState<AppStructureScan[]>([]);
  const [copiedItem, setCopiedItem] = useState<string | null>(null);
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [orgsData, structureData, scansData] = await Promise.all([
        api.getOrganizations(),
        api.getAppStructure({
          organization_id: selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined,
          search: searchQuery || undefined,
        }),
        api.getAppStructureScans(
          selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined
        ),
      ]);
      setOrganizations(orgsData);
      setData(structureData);
      setScans(scansData);
    } catch (error: any) {
      console.error('Failed to fetch data:', error);
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to load application structure',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedOrg]);

  const handleSearch = () => {
    fetchData();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(text);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const downloadData = () => {
    if (!data) return;

    const exportData = {
      timestamp: new Date().toISOString(),
      organization_id: selectedOrg !== 'all' ? parseInt(selectedOrg) : 'all',
      summary: data.summary,
      paths: data.paths,
      urls: data.urls,
      parameters: data.parameters,
      js_files: data.js_files,
      api_endpoints: data.api_endpoints,
      interesting_urls: data.interesting_urls,
      file_extensions: data.file_extensions,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `app-structure-${selectedOrg}-${Date.now()}.json`;
    a.click();
  };

  const getTabItems = (): string[] => {
    if (!data) return [];
    switch (activeTab) {
      case 'paths':
        return data.paths;
      case 'urls':
        return data.urls;
      case 'parameters':
        return data.parameters;
      case 'js_files':
        return data.js_files;
      case 'api_endpoints':
        return data.api_endpoints;
      case 'interesting':
        return data.interesting_urls;
      default:
        return [];
    }
  };

  const getTabIcon = (tab: TabType) => {
    switch (tab) {
      case 'paths':
        return Route;
      case 'urls':
        return Globe;
      case 'parameters':
        return Hash;
      case 'js_files':
        return FileCode;
      case 'api_endpoints':
        return Server;
      case 'interesting':
        return AlertTriangle;
      default:
        return Code;
    }
  };

  const tabs: { id: TabType; label: string; count: number }[] = data
    ? [
        { id: 'paths', label: 'Paths', count: data.summary.total_paths },
        { id: 'urls', label: 'URLs', count: data.summary.total_urls },
        { id: 'parameters', label: 'Parameters', count: data.summary.total_parameters },
        { id: 'js_files', label: 'JS Files', count: data.summary.total_js_files },
        { id: 'api_endpoints', label: 'API Endpoints', count: data.summary.total_api_endpoints },
        { id: 'interesting', label: 'Interesting', count: data.summary.total_interesting_urls },
      ]
    : [];

  const items = getTabItems();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderTree className="h-5 w-5" />
            Application Structure
          </CardTitle>
          <CardDescription>
            Discovered paths, URLs, parameters, and JS files from Katana, ParamSpider, and Wayback scans.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Organization</label>
              <Select value={selectedOrg} onValueChange={setSelectedOrg}>
                <SelectTrigger>
                  <SelectValue placeholder="All Organizations" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Organizations</SelectItem>
                  {organizations.map((org) => (
                    <SelectItem key={org.id} value={org.id.toString()}>
                      {org.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2 md:col-span-2">
              <label className="text-sm font-medium">Search</label>
              <div className="flex gap-2">
                <Input
                  placeholder="Search paths, URLs, parameters..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                />
                <Button onClick={handleSearch} disabled={loading}>
                  <Search className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex items-end gap-2">
              <Button variant="outline" onClick={fetchData} disabled={loading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button variant="outline" onClick={downloadData} disabled={!data}>
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {data ? (
        <>
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Route className="h-8 w-8 text-blue-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_paths.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">Paths</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Globe className="h-8 w-8 text-green-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_urls.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">URLs</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Hash className="h-8 w-8 text-purple-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_parameters.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">Parameters</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <FileCode className="h-8 w-8 text-yellow-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_js_files.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">JS Files</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Server className="h-8 w-8 text-cyan-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_api_endpoints.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">API Endpoints</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-8 w-8 text-orange-500" />
                  <div>
                    <p className="text-2xl font-bold">{data.summary.total_interesting_urls.toLocaleString()}</p>
                    <p className="text-sm text-muted-foreground">Interesting</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Source Breakdown */}
          {data.source_breakdown && Object.keys(data.source_breakdown).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Source Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {Object.entries(data.source_breakdown).map(([source, counts]) => (
                    <div key={source} className="p-4 bg-muted/50 rounded-lg">
                      <h4 className="font-medium capitalize mb-2">{source}</h4>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(counts).map(([key, value]) => (
                          <Badge key={key} variant="secondary">
                            {key.replace(/_/g, ' ')}: {value}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* File Extensions */}
          {Object.keys(data.file_extensions).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">File Extensions Found</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(data.file_extensions).slice(0, 30).map(([ext, count]) => (
                    <Badge key={ext} variant="secondary" className="flex items-center gap-1">
                      {ext}
                      <span className="text-xs bg-muted px-1 rounded">{count}</span>
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tabbed Content */}
          <Card>
            <CardHeader>
              <div className="flex flex-wrap gap-2">
                {tabs.map((tab) => {
                  const Icon = getTabIcon(tab.id);
                  return (
                    <Button
                      key={tab.id}
                      variant={activeTab === tab.id ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setActiveTab(tab.id)}
                    >
                      <Icon className="h-4 w-4 mr-1" />
                      {tab.label} ({tab.count.toLocaleString()})
                    </Button>
                  );
                })}
              </div>
            </CardHeader>
            <CardContent>
              {items.length > 0 ? (
                <div className="max-h-[500px] overflow-y-auto space-y-1">
                  {items.slice(0, 500).map((item, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted group"
                    >
                      <span className="flex-1 truncate">{item}</span>
                      <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(item)}
                          className="h-6 w-6 p-0"
                        >
                          {copiedItem === item ? (
                            <Check className="h-3 w-3 text-green-500" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </Button>
                        {(activeTab === 'urls' || activeTab === 'js_files' || activeTab === 'interesting') && (
                          <a
                            href={item}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center justify-center h-6 w-6 rounded hover:bg-muted-foreground/20"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                  {items.length > 500 && (
                    <p className="text-sm text-muted-foreground p-2">
                      Showing first 500 items. Export JSON for full list.
                    </p>
                  )}
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <FolderTree className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No {activeTab.replace(/_/g, ' ')} found</p>
                  <p className="text-sm">Run Katana, ParamSpider, or Wayback scans to discover application structure</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Contributing Scans */}
          {scans.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Contributing Scans ({scans.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Targets</TableHead>
                      <TableHead>Items Found</TableHead>
                      <TableHead>Completed</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.slice(0, 20).map((scan) => (
                      <TableRow key={scan.id}>
                        <TableCell className="font-medium">{scan.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{scan.scan_type}</Badge>
                        </TableCell>
                        <TableCell className="max-w-[200px] truncate">
                          {scan.targets?.join(', ') || '-'}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {Object.entries(scan.item_counts).map(([key, value]) => (
                              <Badge key={key} variant="secondary" className="text-xs">
                                {key}: {value}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {scan.completed_at
                            ? new Date(scan.completed_at).toLocaleDateString()
                            : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      ) : (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <FolderTree className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No application structure data available</p>
            <p className="text-sm">Run Katana, ParamSpider, or Wayback scans to discover paths, URLs, and parameters</p>
          </CardContent>
        </Card>
      )}

      {/* Help Section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">About Application Structure</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            <strong>What is this?</strong> A unified view of your application's attack surface structure,
            aggregated from multiple scanning tools.
          </p>
          <p>
            <strong>Data Sources:</strong>
          </p>
          <ul className="list-disc pl-6 space-y-1">
            <li><strong>Katana:</strong> Deep web crawling with JavaScript parsing - discovers endpoints, JS files, API routes, and parameters</li>
            <li><strong>ParamSpider:</strong> Mines Wayback Machine and Common Crawl for URL parameters</li>
            <li><strong>WaybackURLs:</strong> Fetches historical URLs from the Wayback Machine, including interesting/sensitive endpoints</li>
          </ul>
          <p>
            <strong>Use Cases:</strong> Identify hidden endpoints, discover attack vectors, find forgotten APIs,
            locate potentially sensitive files, and map the full application surface for testing.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
