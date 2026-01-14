'use client';

import React, { useEffect, useState } from 'react';


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
  Database,
  Mail,
  Server,
  Trash2,
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
  ip_address?: string;
  metadata_: {
    suspicion_score?: number;
    suspicion_reasons?: string[];
    is_parked?: boolean;
    is_private?: boolean;
    validation_recommendation?: string;
    validated_at?: string;
    dns_records?: {
      A?: { address: string; ttl: number }[];
      AAAA?: { address: string; ttl: number }[];
      MX?: { target: string; priority: number; ttl: number }[];
      NS?: { target: string; ttl: number }[];
      TXT?: { value: string; ttl: number }[];
      SOA?: { admin: string; host: string; serial: number };
    };
    dns_summary?: {
      has_mail?: boolean;
      mail_providers?: string[];
      nameservers?: string[];
      ip_addresses?: string[];
      txt_verifications?: string[];
    };
    dns_analysis?: {
      is_active?: boolean;
      has_email?: boolean;
      uses_cdn?: string;
      security_features?: string[];
    };
    dns_fetched_at?: string;
  };
}

interface Stats {
  total: number;
  in_scope: number;
  out_of_scope: number;
  validated: number;
  suspicious: number;
  parked: number;
  dns_enriched: number;
  has_mail: number;
}

export default function DomainsContent() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [validating, setValidating] = useState(false);
  const [enrichingDns, setEnrichingDns] = useState(false);
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
    dns_enriched: 0,
    has_mail: 0,
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
        dns_enriched: domainAssets.filter((d: Domain) => d.metadata_?.dns_fetched_at).length,
        has_mail: domainAssets.filter((d: Domain) => d.metadata_?.dns_summary?.has_mail).length,
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
      const response = await api.post('/external-discovery/validate-domains', {
        organization_id: 1,
        validate_all_whoxy: true,
        limit: 100,
      });
      
      toast({
        title: 'Validation Complete',
        description: `Validated ${response.data?.total ?? 0} domains. ${response.data?.suspicious ?? 0} suspicious, ${response.data?.auto_removed ?? 0} auto-removed.`,
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

  const handleEnrichDns = async () => {
    try {
      setEnrichingDns(true);
      const response = await api.enrichDomainsDns({
        organizationId: 1,
        limit: 50,
      });
      
      toast({
        title: 'DNS Enrichment Complete',
        description: `Enriched ${response.enriched} of ${response.total_domains} domains with DNS records.`,
      });
      
      fetchDomains();
    } catch (error: any) {
      console.error('Error enriching DNS:', error);
      const message = error.response?.data?.detail || 'Failed to enrich DNS records';
      toast({
        title: 'Error',
        description: message,
        variant: 'destructive',
      });
    } finally {
      setEnrichingDns(false);
    }
  };

  const handleToggleScope = async (domain: Domain) => {
    try {
      await api.updateAsset(domain.id, { in_scope: !domain.in_scope });
      
      setDomains((prev: Domain[]) => prev.map((d: Domain) => 
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
      const domainIds: number[] = Array.from(selectedDomains);
      for (let i = 0; i < domainIds.length; i++) {
        await api.updateAsset(domainIds[i], { in_scope: inScope });
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
    const visibleIds = filteredDomains.map((d: Domain) => d.id);
    setSelectedDomains(new Set(visibleIds));
  };

  const deselectAll = () => {
    setSelectedDomains(new Set());
  };

  // Filter domains
  const filteredDomains = domains.filter((domain: Domain) => {
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
      <div className="p-6 space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
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
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-purple-600">{stats.dns_enriched}</div>
              <div className="text-xs text-muted-foreground">DNS Enriched</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-cyan-600">{stats.has_mail}</div>
              <div className="text-xs text-muted-foreground">Has Email</div>
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
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchTerm(e.target.value)}
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
                  onClick={handleEnrichDns}
                  disabled={enrichingDns}
                >
                  {enrichingDns ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Database className="h-4 w-4 mr-2" />
                  )}
                  Enrich DNS
                </Button>
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
                  Validate Whoxy
                </Button>
                <Button variant="outline" onClick={fetchDomains} disabled={loading}>
                  <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
                {stats.out_of_scope > 0 && (
                  <Button 
                    variant="outline"
                    className="text-red-500 border-red-500/50 hover:bg-red-500/10"
                    onClick={async () => {
                      if (confirm(`Delete ${stats.out_of_scope} out-of-scope domains? This cannot be undone.`)) {
                        try {
                          const outOfScopeIds = domains.filter((d: Domain) => !d.in_scope).map((d: Domain) => d.id);
                          const result = await api.bulkDeleteAssets(outOfScopeIds);
                          toast({
                            title: 'Domains Deleted',
                            description: `Deleted ${result.deleted} out-of-scope domains.`,
                          });
                          fetchDomains();
                        } catch (error) {
                          toast({
                            title: 'Error',
                            description: 'Failed to delete domains',
                            variant: 'destructive',
                          });
                        }
                      }
                    }}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete {stats.out_of_scope} Out of Scope
                  </Button>
                )}
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
              <Button 
                size="sm" 
                variant="outline"
                className="text-red-500 border-red-500/50 hover:bg-red-500/10"
                onClick={async () => {
                  if (confirm(`Delete ${selectedDomains.size} selected domains? This cannot be undone.`)) {
                    try {
                      const result = await api.bulkDeleteAssets(Array.from(selectedDomains));
                      toast({
                        title: 'Domains Deleted',
                        description: `Deleted ${result.deleted} domains.`,
                      });
                      setSelectedDomains(new Set());
                      fetchDomains();
                    } catch (error) {
                      toast({
                        title: 'Error',
                        description: 'Failed to delete domains',
                        variant: 'destructive',
                      });
                    }
                  }
                }}
              >
                <Trash2 className="h-4 w-4 mr-1" /> Delete Selected
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
                          onChange={(e: React.ChangeEvent<HTMLInputElement>) => e.target.checked ? selectAllVisible() : deselectAll()}
                          className="rounded"
                        />
                      </TableHead>
                      <TableHead>Domain</TableHead>
                      <TableHead>IP / DNS</TableHead>
                      <TableHead>Mail / Security</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredDomains.map((domain: Domain) => (
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
                          <div className="flex flex-col gap-1">
                            {domain.ip_address || (domain.metadata_?.dns_summary?.ip_addresses?.length ?? 0) > 0 ? (
                              <span className="font-mono text-xs">
                                {domain.ip_address || domain.metadata_?.dns_summary?.ip_addresses?.[0]}
                              </span>
                            ) : (
                              <span className="text-xs text-muted-foreground">No DNS</span>
                            )}
                            {(domain.metadata_?.dns_summary?.nameservers?.length ?? 0) > 0 && (
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <Server className="h-3 w-3" />
                                {domain.metadata_?.dns_summary?.nameservers?.[0]?.split('.').slice(-2).join('.') || 'NS'}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            {domain.metadata_?.dns_summary?.has_mail ? (
                              <span className="text-xs flex items-center gap-1 text-green-600">
                                <Mail className="h-3 w-3" />
                                {(domain.metadata_.dns_summary.mail_providers?.length ?? 0) > 0 
                                  ? domain.metadata_.dns_summary.mail_providers![0]
                                  : 'Email'}
                              </span>
                            ) : domain.metadata_?.dns_fetched_at ? (
                              <span className="text-xs text-muted-foreground">No email</span>
                            ) : null}
                            {(domain.metadata_?.dns_analysis?.security_features?.length ?? 0) > 0 && (
                              <div className="flex gap-1 flex-wrap">
                                {domain.metadata_!.dns_analysis!.security_features!.map((f: string) => (
                                  <Badge key={f} variant="outline" className="text-[10px] px-1 py-0">
                                    {f}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </div>
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
                              <XCircle className="h-3 w-3 mr-1" /> Out
                            </Badge>
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
