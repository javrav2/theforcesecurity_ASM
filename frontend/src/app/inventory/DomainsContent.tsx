'use client';

import { useEffect, useState } from 'react';


import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
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
  Globe,
  Search,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Eye,
  Loader2,
  ExternalLink,
  Filter,
  Download,
  Upload,
  Trash2,
  Check,
  X,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Domain {
  id: number;
  value: string;
  asset_type: string;
  discovery_source: string;
  association_reason: string;
  in_scope: boolean;
  is_live: boolean;
  http_status: number | null;
  created_at: string;
  metadata_: {
    suspicion_score?: number;
    suspicion_reasons?: string[];
    is_parked?: boolean;
    is_private?: boolean;
    validation_recommendation?: string;
    validated_at?: string;
  };
}

interface Stats {
  total: number;
  in_scope: number;
  out_of_scope: number;
  validated: number;
  suspicious: number;
  parked: number;
}

export default function DomainsContent() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [scopeFilter, setScopeFilter] = useState<string>('all');
  const [suspicionFilter, setSuspicionFilter] = useState<string>('all');
  const [stats, setStats] = useState<Stats>({
    total: 0,
    in_scope: 0,
    out_of_scope: 0,
    validated: 0,
    suspicious: 0,
    parked: 0,
  });
  const [selectedDomains, setSelectedDomains] = useState<Set<number>>(new Set());
  const { toast } = useToast();

  const fetchDomains = async () => {
    try {
      setLoading(true);
      // Fetch domains (asset_type = domain)
      const response = await api.getAssets({ 
        asset_type: 'domain',
        limit: 500 
      });
      
      const domainAssets = response.items || response || [];
      setDomains(domainAssets);
      
      // Calculate stats
      const newStats: Stats = {
        total: domainAssets.length,
        in_scope: domainAssets.filter((d: Domain) => d.in_scope).length,
        out_of_scope: domainAssets.filter((d: Domain) => !d.in_scope).length,
        validated: domainAssets.filter((d: Domain) => d.metadata_?.validated_at).length,
        suspicious: domainAssets.filter((d: Domain) => (d.metadata_?.suspicion_score || 0) >= 50).length,
        parked: domainAssets.filter((d: Domain) => d.metadata_?.is_parked).length,
      };
      setStats(newStats);
      
    } catch (error) {
      console.error('Error fetching domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch domains',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDomains();
  }, []);

  const handleValidateAll = async () => {
    try {
      setValidating(true);
      const response = await api.client.post('/external-discovery/validate-domains', {
        organization_id: 1,
        validate_all_whoxy: true,
        limit: 100,
      });
      
      toast({
        title: 'Validation Complete',
        description: `Validated ${response.data.total} domains. ${response.data.suspicious} suspicious, ${response.data.auto_removed} auto-removed.`,
      });
      
      fetchDomains();
    } catch (error) {
      console.error('Error validating domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to validate domains',
        variant: 'destructive',
      });
    } finally {
      setValidating(false);
    }
  };

  const handleToggleScope = async (domain: Domain) => {
    try {
      await api.updateAsset(domain.id, { in_scope: !domain.in_scope });
      
      setDomains(prev => prev.map(d => 
        d.id === domain.id ? { ...d, in_scope: !d.in_scope } : d
      ));
      
      toast({
        title: domain.in_scope ? 'Removed from Scope' : 'Added to Scope',
        description: `${domain.value} is now ${domain.in_scope ? 'out of' : 'in'} scope`,
      });
    } catch (error) {
      console.error('Error updating domain:', error);
      toast({
        title: 'Error',
        description: 'Failed to update domain scope',
        variant: 'destructive',
      });
    }
  };

  const handleBulkScope = async (inScope: boolean) => {
    if (selectedDomains.size === 0) return;
    
    try {
      for (const domainId of selectedDomains) {
        await api.updateAsset(domainId, { in_scope: inScope });
      }
      
      toast({
        title: 'Bulk Update Complete',
        description: `Updated ${selectedDomains.size} domains to ${inScope ? 'in' : 'out of'} scope`,
      });
      
      setSelectedDomains(new Set());
      fetchDomains();
    } catch (error) {
      console.error('Error bulk updating domains:', error);
      toast({
        title: 'Error',
        description: 'Failed to update domains',
        variant: 'destructive',
      });
    }
  };

  const toggleSelectDomain = (domainId: number) => {
    const newSelected = new Set(selectedDomains);
    if (newSelected.has(domainId)) {
      newSelected.delete(domainId);
    } else {
      newSelected.add(domainId);
    }
    setSelectedDomains(newSelected);
  };

  const selectAllVisible = () => {
    const visibleIds = filteredDomains.map(d => d.id);
    setSelectedDomains(new Set(visibleIds));
  };

  const deselectAll = () => {
    setSelectedDomains(new Set());
  };

  // Filter domains
  const filteredDomains = domains.filter(domain => {
    // Search filter
    if (searchTerm && !domain.value.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    
    // Source filter
    if (sourceFilter !== 'all') {
      if (sourceFilter === 'whoxy' && !domain.discovery_source?.toLowerCase().includes('whoxy')) {
        return false;
      }
      if (sourceFilter === 'other' && domain.discovery_source?.toLowerCase().includes('whoxy')) {
        return false;
      }
    }
    
    // Scope filter
    if (scopeFilter === 'in_scope' && !domain.in_scope) return false;
    if (scopeFilter === 'out_of_scope' && domain.in_scope) return false;
    
    // Suspicion filter
    if (suspicionFilter === 'suspicious' && (domain.metadata_?.suspicion_score || 0) < 50) return false;
    if (suspicionFilter === 'clean' && (domain.metadata_?.suspicion_score || 0) >= 50) return false;
    if (suspicionFilter === 'parked' && !domain.metadata_?.is_parked) return false;
    if (suspicionFilter === 'unvalidated' && domain.metadata_?.validated_at) return false;
    
    return true;
  });

  const getSuspicionBadge = (domain: Domain) => {
    const score = domain.metadata_?.suspicion_score || 0;
    const isParked = domain.metadata_?.is_parked;
    
    if (isParked) {
      return <Badge variant="destructive" className="gap-1"><AlertTriangle className="h-3 w-3" /> Parked</Badge>;
    }
    if (score >= 75) {
      return <Badge variant="destructive" className="gap-1"><XCircle className="h-3 w-3" /> High Risk</Badge>;
    }
    if (score >= 50) {
      return <Badge variant="secondary" className="gap-1 bg-yellow-500/20 text-yellow-700"><AlertTriangle className="h-3 w-3" /> Suspicious</Badge>;
    }
    if (domain.metadata_?.validated_at) {
      return <Badge variant="secondary" className="gap-1 bg-green-500/20 text-green-700"><CheckCircle className="h-3 w-3" /> Verified</Badge>;
    }
    return <Badge variant="outline" className="gap-1"><Eye className="h-3 w-3" /> Not Validated</Badge>;
  };

  return (
    <>
        title="Domain Inventory" 
        subtitle="Manage and validate discovered domains from Whoxy and other sources"
      />
      
      <div className="p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{stats.total}</div>
              <div className="text-xs text-muted-foreground">Total Domains</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-green-600">{stats.in_scope}</div>
              <div className="text-xs text-muted-foreground">In Scope</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-gray-500">{stats.out_of_scope}</div>
              <div className="text-xs text-muted-foreground">Out of Scope</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-blue-600">{stats.validated}</div>
              <div className="text-xs text-muted-foreground">Validated</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-yellow-600">{stats.suspicious}</div>
              <div className="text-xs text-muted-foreground">Suspicious</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-red-600">{stats.parked}</div>
              <div className="text-xs text-muted-foreground">Parked</div>
            </CardContent>
          </Card>
        </div>

        {/* Filters and Actions */}
        <Card>
          <CardHeader>
            <div className="flex flex-col md:flex-row gap-4 justify-between">
              <div className="flex flex-wrap gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search domains..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-9 w-64"
                  />
                </div>
                
                <Select value={sourceFilter} onValueChange={setSourceFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Source" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Sources</SelectItem>
                    <SelectItem value="whoxy">Whoxy</SelectItem>
                    <SelectItem value="other">Other</SelectItem>
                  </SelectContent>
                </Select>
                
                <Select value={scopeFilter} onValueChange={setScopeFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Scope" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="in_scope">In Scope</SelectItem>
                    <SelectItem value="out_of_scope">Out of Scope</SelectItem>
                  </SelectContent>
                </Select>
                
                <Select value={suspicionFilter} onValueChange={setSuspicionFilter}>
                  <SelectTrigger className="w-44">
                    <SelectValue placeholder="Validation" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="suspicious">Suspicious</SelectItem>
                    <SelectItem value="parked">Parked</SelectItem>
                    <SelectItem value="clean">Clean</SelectItem>
                    <SelectItem value="unvalidated">Not Validated</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  onClick={handleValidateAll}
                  disabled={validating}
                >
                  {validating ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Shield className="h-4 w-4 mr-2" />
                  )}
                  Validate Whoxy Domains
                </Button>
                <Button variant="outline" onClick={fetchDomains} disabled={loading}>
                  <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
              </div>
            </div>
          </CardHeader>
          
          {/* Bulk Actions */}
          {selectedDomains.size > 0 && (
            <div className="px-6 pb-4 flex items-center gap-4 bg-muted/50 mx-6 rounded-lg py-3">
              <span className="text-sm font-medium">{selectedDomains.size} selected</span>
              <Button size="sm" variant="outline" onClick={() => handleBulkScope(true)}>
                <Check className="h-4 w-4 mr-1" /> Add to Scope
              </Button>
              <Button size="sm" variant="outline" onClick={() => handleBulkScope(false)}>
                <X className="h-4 w-4 mr-1" /> Remove from Scope
              </Button>
              <Button size="sm" variant="ghost" onClick={deselectAll}>
                Clear Selection
              </Button>
            </div>
          )}
          
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : filteredDomains.length === 0 ? (
              <div className="text-center py-12">
                <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No domains found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Run an External Discovery with Whoxy to discover domains
                </p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">
                        <input
                          type="checkbox"
                          checked={selectedDomains.size === filteredDomains.length && filteredDomains.length > 0}
                          onChange={(e) => e.target.checked ? selectAllVisible() : deselectAll()}
                          className="rounded"
                        />
                      </TableHead>
                      <TableHead>Domain</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead>Discovered</TableHead>
                      <TableHead>Suspicion Reasons</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredDomains.map((domain) => (
                      <TableRow key={domain.id} className={!domain.in_scope ? 'opacity-60' : ''}>
                        <TableCell>
                          <input
                            type="checkbox"
                            checked={selectedDomains.has(domain.id)}
                            onChange={() => toggleSelectDomain(domain.id)}
                            className="rounded"
                          />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4 text-muted-foreground" />
                            <a 
                              href={`https://${domain.value}`} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="font-mono text-sm hover:underline flex items-center gap-1"
                            >
                              {domain.value}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {domain.discovery_source || 'unknown'}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {getSuspicionBadge(domain)}
                        </TableCell>
                        <TableCell>
                          {domain.in_scope ? (
                            <Badge className="bg-green-500/20 text-green-700 hover:bg-green-500/30">
                              <CheckCircle className="h-3 w-3 mr-1" /> In Scope
                            </Badge>
                          ) : (
                            <Badge variant="secondary">
                              <XCircle className="h-3 w-3 mr-1" /> Out of Scope
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {formatDate(domain.created_at)}
                        </TableCell>
                        <TableCell className="max-w-xs">
                          {domain.metadata_?.suspicion_reasons?.length > 0 ? (
                            <span className="text-xs text-muted-foreground">
                              {domain.metadata_.suspicion_reasons.join('; ')}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant={domain.in_scope ? "destructive" : "default"}
                              onClick={() => handleToggleScope(domain)}
                            >
                              {domain.in_scope ? (
                                <>
                                  <XCircle className="h-4 w-4 mr-1" /> Remove
                                </>
                              ) : (
                                <>
                                  <CheckCircle className="h-4 w-4 mr-1" /> Add
                                </>
                              )}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => window.open(`/assets/${domain.id}`, '_blank')}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
