'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';


import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
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
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Network,
  Search,
  Download,
  Loader2,
  CheckCircle,
  XCircle,
  Globe,
  Shield,
  RefreshCw,
  Filter,
  Building2,
  Eye,
  ExternalLink,
  Play,
  CheckSquare,
  Square,
  Target,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate, downloadCSV } from '@/lib/utils';

interface Netblock {
  id: number;
  organization_id: number;
  inetnum: string;
  start_ip: string;
  end_ip: string;
  cidr_notation: string;
  ip_count: number;
  ip_version: string;
  is_owned: boolean;
  in_scope: boolean;
  ownership_confidence: number;
  asn?: string;
  as_name?: string;
  netname?: string;
  description?: string;
  org_name?: string;
  country?: string;
  city?: string;
  last_scanned?: string;
  scan_count: number;
  created_at: string;
}

interface NetblockSummary {
  total_netblocks: number;
  owned_netblocks: number;
  in_scope_netblocks: number;
  out_of_scope_netblocks: number;
  total_ips: number;
  owned_ips: number;
  in_scope_ips: number;
  ipv4_netblocks: number;
  ipv6_netblocks: number;
  scanned_netblocks: number;
  unscanned_netblocks: number;
}

export default function NetblocksContent() {
  const router = useRouter();
  const [netblocks, setNetblocks] = useState<Netblock[]>([]);
  const [summary, setSummary] = useState<NetblockSummary | null>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedOrg, setSelectedOrg] = useState<string>('all');
  const [ownershipFilter, setOwnershipFilter] = useState<string>('all');
  const [scopeFilter, setScopeFilter] = useState<string>('all');
  const [ipVersionFilter, setIpVersionFilter] = useState<string>('all');
  const [discoverDialogOpen, setDiscoverDialogOpen] = useState(false);
  const [searchTerms, setSearchTerms] = useState('');
  const { toast } = useToast();
  
  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [scanDialogOpen, setScanDialogOpen] = useState(false);
  const [scanType, setScanType] = useState<string>('port_scan');
  const [scanName, setScanName] = useState('');
  const [submittingScan, setSubmittingScan] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 200 };
      if (selectedOrg !== 'all') {
        params.organization_id = parseInt(selectedOrg);
      }
      if (ownershipFilter !== 'all') {
        params.is_owned = ownershipFilter === 'owned';
      }
      if (scopeFilter !== 'all') {
        params.in_scope = scopeFilter === 'in_scope';
      }
      if (ipVersionFilter !== 'all') {
        params.ip_version = ipVersionFilter;
      }

      const [netblocksData, summaryData, orgsData] = await Promise.all([
        api.getNetblocks(params),
        api.getNetblockSummary(selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined),
        api.getOrganizations(),
      ]);

      setNetblocks(netblocksData);
      setSummary(summaryData);
      setOrganizations(orgsData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch netblocks',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedOrg, ownershipFilter, scopeFilter, ipVersionFilter]);

  const handleDiscover = async () => {
    if (!selectedOrg || selectedOrg === 'all') {
      toast({
        title: 'Error',
        description: 'Please select an organization first',
        variant: 'destructive',
      });
      return;
    }

    const terms = searchTerms.split(',').map(t => t.trim()).filter(t => t);
    if (terms.length === 0) {
      toast({
        title: 'Error',
        description: 'Please enter at least one search term',
        variant: 'destructive',
      });
      return;
    }

    setDiscovering(true);
    try {
      const result = await api.discoverNetblocks({
        organization_id: parseInt(selectedOrg),
        search_terms: terms,
        include_variations: true,
      });

      toast({
        title: 'Discovery Complete',
        description: `Found ${result.netblocks_found} netblocks, created ${result.netblocks_created} new. ${result.owned_count} owned by organization.`,
      });

      setDiscoverDialogOpen(false);
      setSearchTerms('');
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Discovery Failed',
        description: error.response?.data?.detail || 'Failed to discover netblocks',
        variant: 'destructive',
      });
    } finally {
      setDiscovering(false);
    }
  };

  const handleToggleScope = async (netblock: Netblock) => {
    try {
      await api.toggleNetblockScope(netblock.id);
      setNetblocks(prev =>
        prev.map(n =>
          n.id === netblock.id ? { ...n, in_scope: !n.in_scope } : n
        )
      );
      toast({
        title: 'Updated',
        description: `${netblock.cidr_notation || netblock.inetnum} is now ${!netblock.in_scope ? 'in scope' : 'out of scope'}`,
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update scope',
        variant: 'destructive',
      });
    }
  };

  const handleToggleOwnership = async (netblock: Netblock) => {
    try {
      await api.toggleNetblockOwnership(netblock.id);
      setNetblocks(prev =>
        prev.map(n =>
          n.id === netblock.id ? { ...n, is_owned: !n.is_owned } : n
        )
      );
      toast({
        title: 'Updated',
        description: `${netblock.cidr_notation || netblock.inetnum} ownership ${!netblock.is_owned ? 'confirmed' : 'removed'}`,
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update ownership',
        variant: 'destructive',
      });
    }
  };

  const handleExport = () => {
    downloadCSV(
      netblocks.map(n => ({
        cidr: n.cidr_notation || n.inetnum,
        start_ip: n.start_ip,
        end_ip: n.end_ip,
        ip_count: n.ip_count,
        ip_version: n.ip_version,
        is_owned: n.is_owned ? 'Yes' : 'No',
        in_scope: n.in_scope ? 'Yes' : 'No',
        asn: n.asn,
        as_name: n.as_name,
        org_name: n.org_name,
        country: n.country,
      })),
      'netblocks'
    );
    toast({
      title: 'Export Started',
      description: 'Your CSV file is being downloaded.',
    });
  };

  // Selection handlers
  const toggleSelect = (id: number) => {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filteredNetblocks.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredNetblocks.map(n => n.id)));
    }
  };

  const getSelectedIpCount = () => {
    return filteredNetblocks
      .filter(n => selectedIds.has(n.id))
      .reduce((sum, n) => sum + (n.ip_count || 0), 0);
  };

  const handleScanSelected = async () => {
    if (selectedIds.size === 0) {
      toast({
        title: 'Error',
        description: 'Please select at least one netblock',
        variant: 'destructive',
      });
      return;
    }

    // Get organization ID from selected netblocks
    const firstSelected = netblocks.find(n => selectedIds.has(n.id));
    if (!firstSelected) return;

    setSubmittingScan(true);
    try {
      // Get targets from selected netblocks
      const targetsResponse = await api.request('/netblocks/targets/by-ids', {
        method: 'POST',
        body: JSON.stringify(Array.from(selectedIds)),
      });

      if (!targetsResponse.targets || targetsResponse.targets.length === 0) {
        toast({
          title: 'Error',
          description: 'No valid CIDR targets found in selected netblocks',
          variant: 'destructive',
        });
        return;
      }

      // Create scan
      await api.createScan({
        name: scanName || `Netblock Scan - ${new Date().toLocaleDateString()}`,
        organization_id: firstSelected.organization_id,
        scan_type: scanType,
        targets: targetsResponse.targets,
        config: scanType === 'port_scan' ? { scanner: 'naabu' } : undefined,
      });

      toast({
        title: 'Scan Created',
        description: `Scan queued for ${targetsResponse.count} CIDR blocks (${formatIpCount(targetsResponse.total_ips)} IPs)`,
      });

      setScanDialogOpen(false);
      setSelectedIds(new Set());
      setScanName('');
      router.push('/scans');
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create scan',
        variant: 'destructive',
      });
    } finally {
      setSubmittingScan(false);
    }
  };

  const filteredNetblocks = useMemo(() => {
    return netblocks.filter(
      n =>
        n.cidr_notation?.toLowerCase().includes(search.toLowerCase()) ||
        n.inetnum?.toLowerCase().includes(search.toLowerCase()) ||
        n.start_ip?.toLowerCase().includes(search.toLowerCase()) ||
        n.asn?.toLowerCase().includes(search.toLowerCase()) ||
        n.org_name?.toLowerCase().includes(search.toLowerCase()) ||
        n.netname?.toLowerCase().includes(search.toLowerCase())
    );
  }, [netblocks, search]);

  const formatIpCount = (count: number) => {
    if (count >= 1000000) return `${(count / 1000000).toFixed(1)}M`;
    if (count >= 1000) return `${(count / 1000).toFixed(1)}K`;
    return count.toString();
  };

  return (
    <>

      <div className="p-6 space-y-6">
        {/* Summary Stats */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Network className="h-5 w-5 text-primary" />
                  <div>
                    <p className="text-sm text-muted-foreground">Total Ranges</p>
                    <p className="text-2xl font-bold">{summary.total_netblocks}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <div>
                    <p className="text-sm text-muted-foreground">Owned</p>
                    <p className="text-2xl font-bold">{summary.owned_netblocks}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-500" />
                  <div>
                    <p className="text-sm text-muted-foreground">In Scope</p>
                    <p className="text-2xl font-bold">{summary.in_scope_netblocks}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-purple-500" />
                  <div>
                    <p className="text-sm text-muted-foreground">Total IPs</p>
                    <p className="text-2xl font-bold">{formatIpCount(summary.total_ips)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div>
                  <p className="text-sm text-muted-foreground">IPv4 / IPv6</p>
                  <p className="text-2xl font-bold">{summary.ipv4_netblocks} / {summary.ipv6_netblocks}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div>
                  <p className="text-sm text-muted-foreground">Scanned</p>
                  <p className="text-2xl font-bold">{summary.scanned_netblocks} / {summary.total_netblocks}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="relative min-w-[250px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search CIDR, IP, ASN, org..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>

            <Select value={selectedOrg} onValueChange={setSelectedOrg}>
              <SelectTrigger className="w-[180px]">
                <Building2 className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Organization" />
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

            <Select value={ownershipFilter} onValueChange={setOwnershipFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Ownership" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="owned">Owned</SelectItem>
                <SelectItem value="not_owned">Not Owned</SelectItem>
              </SelectContent>
            </Select>

            <Select value={scopeFilter} onValueChange={setScopeFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Scope" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="in_scope">In Scope</SelectItem>
                <SelectItem value="out_of_scope">Out of Scope</SelectItem>
              </SelectContent>
            </Select>

            <Select value={ipVersionFilter} onValueChange={setIpVersionFilter}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="IP Version" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All IPs</SelectItem>
                <SelectItem value="ipv4">IPv4 Only</SelectItem>
                <SelectItem value="ipv6">IPv6 Only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            {selectedIds.size > 0 && (
              <div className="flex items-center gap-2 mr-2 px-3 py-1 bg-primary/10 rounded-lg">
                <Target className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">
                  {selectedIds.size} selected ({formatIpCount(getSelectedIpCount())} IPs)
                </span>
                <Button 
                  size="sm" 
                  onClick={() => setScanDialogOpen(true)}
                  className="ml-2"
                >
                  <Play className="h-4 w-4 mr-1" />
                  Scan Selected
                </Button>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  onClick={() => setSelectedIds(new Set())}
                >
                  Clear
                </Button>
              </div>
            )}
            <Button variant="outline" size="sm" onClick={fetchData}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
            <Button onClick={() => setDiscoverDialogOpen(true)}>
              <Network className="h-4 w-4 mr-2" />
              Discover CIDR Blocks
            </Button>
          </div>
        </div>

        {/* Netblocks Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40px]">
                  <button
                    onClick={toggleSelectAll}
                    className="p-1 hover:bg-muted rounded"
                  >
                    {selectedIds.size === filteredNetblocks.length && filteredNetblocks.length > 0 ? (
                      <CheckSquare className="h-4 w-4 text-primary" />
                    ) : (
                      <Square className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                </TableHead>
                <TableHead>CIDR / Range</TableHead>
                <TableHead>IPs</TableHead>
                <TableHead>ASN</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Country</TableHead>
                <TableHead className="text-center">Owned</TableHead>
                <TableHead className="text-center">In Scope</TableHead>
                <TableHead>Scanned</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={10} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : filteredNetblocks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} className="text-center py-8 text-muted-foreground">
                    No netblocks found. Click "Discover CIDR Blocks" to find IP ranges.
                  </TableCell>
                </TableRow>
              ) : (
                filteredNetblocks.map((netblock) => (
                  <TableRow 
                    key={netblock.id} 
                    className={`cursor-pointer hover:bg-muted/50 ${selectedIds.has(netblock.id) ? 'bg-primary/5' : ''}`}
                    onClick={() => router.push(`/netblocks/${netblock.id}`)}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => toggleSelect(netblock.id)}
                        className="p-1 hover:bg-muted rounded"
                      >
                        {selectedIds.has(netblock.id) ? (
                          <CheckSquare className="h-4 w-4 text-primary" />
                        ) : (
                          <Square className="h-4 w-4 text-muted-foreground" />
                        )}
                      </button>
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-mono font-medium text-primary hover:underline">
                          {netblock.cidr_notation || netblock.inetnum}
                        </div>
                        {netblock.netname && (
                          <div className="text-xs text-muted-foreground">{netblock.netname}</div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {formatIpCount(netblock.ip_count)} {netblock.ip_version}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {netblock.asn && (
                        <div>
                          <div className="font-mono text-sm">{netblock.asn}</div>
                          {netblock.as_name && (
                            <div className="text-xs text-muted-foreground truncate max-w-[150px]">
                              {netblock.as_name}
                            </div>
                          )}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="truncate max-w-[200px]">
                        {netblock.org_name || '-'}
                      </div>
                    </TableCell>
                    <TableCell>{netblock.country || '-'}</TableCell>
                    <TableCell className="text-center" onClick={(e) => e.stopPropagation()}>
                      <Switch
                        checked={netblock.is_owned}
                        onCheckedChange={() => handleToggleOwnership(netblock)}
                      />
                    </TableCell>
                    <TableCell className="text-center" onClick={(e) => e.stopPropagation()}>
                      <Switch
                        checked={netblock.in_scope}
                        onCheckedChange={() => handleToggleScope(netblock)}
                      />
                    </TableCell>
                    <TableCell>
                      {netblock.last_scanned ? (
                        <Badge variant="secondary">{netblock.scan_count}x</Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground">Never</Badge>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => router.push(`/netblocks/${netblock.id}`)}
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {/* Discover Dialog */}
        <Dialog open={discoverDialogOpen} onOpenChange={setDiscoverDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Discover CIDR Blocks</DialogTitle>
              <DialogDescription>
                Search WhoisXML API to find IP ranges owned by an organization.
                Requires WhoisXML API key configured in Settings.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
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

              <div className="space-y-2">
                <Label>Search Terms (comma-separated)</Label>
                <Input
                  placeholder="e.g., Rockwell Automation, Rockwell"
                  value={searchTerms}
                  onChange={(e) => setSearchTerms(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Enter organization names to search for in WHOIS records.
                  Variations like "Inc", "Inc." are automatically included.
                </p>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setDiscoverDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleDiscover} disabled={discovering || selectedOrg === 'all'}>
                {discovering ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Discovering...
                  </>
                ) : (
                  <>
                    <Network className="h-4 w-4 mr-2" />
                    Discover
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Scan Selected Dialog */}
        <Dialog open={scanDialogOpen} onOpenChange={setScanDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Scan Selected CIDR Blocks</DialogTitle>
              <DialogDescription>
                Create a scan for {selectedIds.size} selected netblocks ({formatIpCount(getSelectedIpCount())} total IPs)
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Scan Name</Label>
                <Input
                  placeholder="e.g., Weekly Port Scan"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label>Scan Type</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="port_scan">Port Scan (Fast)</SelectItem>
                    <SelectItem value="vulnerability">Vulnerability Scan (Nuclei)</SelectItem>
                    <SelectItem value="full">Full Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="p-3 bg-muted/50 rounded-lg space-y-1">
                <p className="text-sm font-medium">Selected Targets:</p>
                <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                  {filteredNetblocks
                    .filter(n => selectedIds.has(n.id))
                    .slice(0, 10)
                    .map(n => (
                      <Badge key={n.id} variant="secondary" className="font-mono text-xs">
                        {n.cidr_notation || n.inetnum}
                      </Badge>
                    ))}
                  {selectedIds.size > 10 && (
                    <Badge variant="outline" className="text-xs">
                      +{selectedIds.size - 10} more
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setScanDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleScanSelected} disabled={submittingScan}>
                {submittingScan ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Creating Scan...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}




