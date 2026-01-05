'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Search,
  Globe,
  Loader2,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  RefreshCw,
  Key,
  Shield,
  Server,
  Network,
  Plus,
  X,
  Building2,
  Mail,
  Settings,
  ChevronDown,
  ChevronUp,
  History,
  AlertTriangle,
  FileWarning,
  FileText,
  ExternalLink,
  Link,
  Radar,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

// Types for External Discovery
interface SourceResult {
  source: string;
  success: boolean;
  domains_found: number;
  subdomains_found: number;
  ips_found: number;
  cidrs_found: number;
  elapsed_time: number;
  error?: string;
}

interface DiscoveryResult {
  domain: string;
  organization_id: number;
  total_domains: number;
  total_subdomains: number;
  total_ips: number;
  total_cidrs: number;
  source_results: SourceResult[];
  domains: string[];
  subdomains: string[];
  ip_addresses: string[];
  ip_ranges: string[];
  assets_created: number;
  assets_skipped: number;
  total_elapsed_time: number;
}

// Types for Wayback URLs
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

export default function DiscoveryPage() {
  // Common state
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [domain, setDomain] = useState('');
  const { toast } = useToast();

  // External Discovery state
  const [discoveryRunning, setDiscoveryRunning] = useState(false);
  const [discoveryResults, setDiscoveryResults] = useState<DiscoveryResult | null>(null);
  const [discoveryActiveTab, setDiscoveryActiveTab] = useState<'subdomains' | 'ips' | 'domains' | 'ranges'>('subdomains');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [includePaid, setIncludePaid] = useState(true);
  const [includeFree, setIncludeFree] = useState(true);
  const [createAssets, setCreateAssets] = useState(true);
  const [enumerateDiscoveredDomains, setEnumerateDiscoveredDomains] = useState(true);
  const [maxDomainsToEnumerate, setMaxDomainsToEnumerate] = useState(50);
  const [orgNames, setOrgNames] = useState<string[]>([]);
  const [newOrgName, setNewOrgName] = useState('');
  const [regEmails, setRegEmails] = useState<string[]>([]);
  const [newRegEmail, setNewRegEmail] = useState('');
  
  // Common Crawl comprehensive search options
  const [ccOrgName, setCcOrgName] = useState('');
  const [ccKeywords, setCcKeywords] = useState<string[]>([]);
  const [newCcKeyword, setNewCcKeyword] = useState('');
  
  // Technology scanning options
  const [runTechScan, setRunTechScan] = useState(true);
  const [maxTechScan, setMaxTechScan] = useState(500);

  // Wayback URLs state
  const [waybackRunning, setWaybackRunning] = useState(false);
  const [waybackResults, setWaybackResults] = useState<WaybackResult | null>(null);
  const [waybackMode, setWaybackMode] = useState<'single' | 'organization'>('single');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [waybackActiveTab, setWaybackActiveTab] = useState<'interesting' | 'all'>('interesting');

  const fetchData = async () => {
    setLoading(true);
    try {
      const orgsData = await api.getOrganizations();
      setOrganizations(orgsData || []);
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
      toast({
        title: 'Error',
        description: 'Failed to load organizations. Please check your connection.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // External Discovery handlers
  const handleRunDiscovery = async () => {
    if (!selectedOrg || !domain) {
      toast({
        title: 'Error',
        description: 'Please select an organization and enter a domain',
        variant: 'destructive',
      });
      return;
    }

    setDiscoveryRunning(true);
    setDiscoveryResults(null);
    try {
      const result = await api.runExternalDiscovery({
        organization_id: parseInt(selectedOrg),
        domain,
        include_paid_sources: includePaid,
        include_free_sources: includeFree,
        create_assets: createAssets,
        skip_existing: true,
        enumerate_discovered_domains: enumerateDiscoveredDomains,
        max_domains_to_enumerate: maxDomainsToEnumerate,
        organization_names: orgNames.length > 0 ? orgNames : undefined,
        registration_emails: regEmails.length > 0 ? regEmails : undefined,
        commoncrawl_org_name: ccOrgName || undefined,
        commoncrawl_keywords: ccKeywords.length > 0 ? ccKeywords : undefined,
        run_technology_scan: runTechScan,
        max_technology_scan: maxTechScan,
      });

      setDiscoveryResults(result);
      toast({
        title: 'Discovery Complete',
        description: `Found ${result.total_subdomains} subdomains, ${result.total_ips} IPs. Created ${result.assets_created} new assets.`,
      });
    } catch (error: any) {
      console.error('Discovery error:', error);
      toast({
        title: 'Discovery Failed',
        description: error.response?.data?.detail || error.message || 'Failed to run discovery. Check API keys in Settings.',
        variant: 'destructive',
      });
    } finally {
      setDiscoveryRunning(false);
    }
  };

  const downloadDiscoveryResults = () => {
    if (!discoveryResults) return;
    
    const data = {
      domain: discoveryResults.domain,
      timestamp: new Date().toISOString(),
      subdomains: discoveryResults.subdomains,
      domains: discoveryResults.domains,
      ip_addresses: discoveryResults.ip_addresses,
      ip_ranges: discoveryResults.ip_ranges,
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `discovery-${discoveryResults.domain}-${Date.now()}.json`;
    a.click();
  };

  const addOrgName = () => {
    if (newOrgName && !orgNames.includes(newOrgName)) {
      setOrgNames([...orgNames, newOrgName]);
      setNewOrgName('');
    }
  };

  const removeOrgName = (name: string) => {
    setOrgNames(orgNames.filter(n => n !== name));
  };

  const addRegEmail = () => {
    if (newRegEmail && !regEmails.includes(newRegEmail)) {
      setRegEmails([...regEmails, newRegEmail]);
      setNewRegEmail('');
    }
  };

  const removeRegEmail = (email: string) => {
    setRegEmails(regEmails.filter(e => e !== email));
  };

  const addCcKeyword = () => {
    if (newCcKeyword && !ccKeywords.includes(newCcKeyword)) {
      setCcKeywords([...ccKeywords, newCcKeyword]);
      setNewCcKeyword('');
    }
  };

  const removeCcKeyword = (keyword: string) => {
    setCcKeywords(ccKeywords.filter(k => k !== keyword));
  };

  // Wayback URLs handlers
  const handleRunWayback = async () => {
    if (waybackMode === 'single' && !domain) {
      toast({
        title: 'Error',
        description: 'Please enter a domain',
        variant: 'destructive',
      });
      return;
    }

    if (waybackMode === 'organization' && !selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please select an organization',
        variant: 'destructive',
      });
      return;
    }

    setWaybackRunning(true);
    setWaybackResults(null);
    try {
      let result;
      if (waybackMode === 'single') {
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

      setWaybackResults(result);
      
      const totalUrls = result.total_urls || result.url_count || 0;
      const interestingCount = result.total_interesting || result.interesting_count || 0;
      
      toast({
        title: 'Wayback Scan Complete',
        description: `Found ${totalUrls} URLs, ${interestingCount} potentially interesting`,
      });
    } catch (error: any) {
      console.error('Wayback error:', error);
      toast({
        title: 'Wayback Scan Failed',
        description: error.response?.data?.detail || error.message || 'Failed to run wayback scan',
        variant: 'destructive',
      });
    } finally {
      setWaybackRunning(false);
    }
  };

  const downloadWaybackResults = () => {
    if (!waybackResults) return;
    
    const data = {
      timestamp: new Date().toISOString(),
      mode: waybackMode,
      ...waybackResults
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wayback-${waybackMode === 'single' ? domain : `org-${selectedOrg}`}-${Date.now()}.json`;
    a.click();
  };

  const discoveryMethods = [
    { name: 'Certificate Transparency (crt.sh)', key: 'crtsh', description: 'SSL/TLS certificate logs', icon: '🔐', free: true },
    { name: 'Wayback Machine', key: 'wayback', description: 'Historical web archives', icon: '📜', free: true },
    { name: 'RapidDNS', key: 'rapiddns', description: 'DNS enumeration', icon: '🌐', free: true },
    { name: 'Microsoft 365', key: 'm365', description: 'Federated tenant domains', icon: '☁️', free: true },
    { name: 'AlienVault OTX', key: 'otx', description: 'Threat intelligence DNS', icon: '👽', free: true },
    { name: 'VirusTotal', key: 'virustotal', description: 'VT subdomain database', icon: '🦠', free: false },
    { name: 'WhoisXML API', key: 'whoisxml', description: 'IP ranges by org name', icon: '📋', free: false },
    { name: 'Whoxy', key: 'whoxy', description: 'Reverse WHOIS by email', icon: '🔍', free: false },
    { name: 'Chained Subdomain Enum', key: 'chained', description: 'Auto-enum on discovered domains', icon: '🔄', free: true },
  ];

  const getSourceStatus = (sourceKey: string) => {
    if (!discoveryResults) return null;
    return discoveryResults.source_results.find(s => s.source.toLowerCase().includes(sourceKey));
  };

  const totalWaybackUrls = waybackResults?.total_urls || waybackResults?.url_count || 0;
  const interestingCount = waybackResults?.total_interesting || waybackResults?.interesting_count || 0;

  return (
    <MainLayout>
      <Header title="Asset Discovery" subtitle="Discover subdomains, IPs, historical URLs, and more from multiple sources" />

      <div className="p-6 space-y-6">
        {/* Organization & Domain Selection - Shared */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5" />
              Discovery Configuration
            </CardTitle>
            <CardDescription>
              Select an organization and target domain to begin discovery
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Organization *</Label>
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
                <Label>Target Domain *</Label>
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Main Tabs */}
        <Tabs defaultValue="external" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 lg:w-[400px]">
            <TabsTrigger value="external" className="flex items-center gap-2">
              <Search className="h-4 w-4" />
              External Discovery
            </TabsTrigger>
            <TabsTrigger value="wayback" className="flex items-center gap-2">
              <History className="h-4 w-4" />
              Wayback URLs
            </TabsTrigger>
          </TabsList>

          {/* External Discovery Tab */}
          <TabsContent value="external" className="space-y-6">
            {/* Run Discovery Card */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  External Asset Discovery
                </CardTitle>
                <CardDescription>
                  Discover subdomains, IPs, and related domains using certificate transparency, DNS, and threat intelligence sources
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Button
                    onClick={handleRunDiscovery}
                    disabled={discoveryRunning || !selectedOrg || !domain}
                    className="flex-1 md:flex-none"
                  >
                    {discoveryRunning ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Discovering...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Start Discovery
                      </>
                    )}
                  </Button>
                </div>

                {/* Advanced Options Toggle */}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="text-muted-foreground"
                >
                  {showAdvanced ? <ChevronUp className="h-4 w-4 mr-2" /> : <ChevronDown className="h-4 w-4 mr-2" />}
                  Advanced Options
                </Button>

                {showAdvanced && (
                  <div className="space-y-4 p-4 bg-muted/50 rounded-lg">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div className="flex items-center gap-2">
                        <Switch checked={includeFree} onCheckedChange={setIncludeFree} />
                        <Label>Free Sources</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={includePaid} onCheckedChange={setIncludePaid} />
                        <Label>Paid Sources</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={createAssets} onCheckedChange={setCreateAssets} />
                        <Label>Create Assets</Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <Switch checked={enumerateDiscoveredDomains} onCheckedChange={setEnumerateDiscoveredDomains} />
                        <Label>Auto-Enumerate Subdomains</Label>
                      </div>
                    </div>
                    
                    {enumerateDiscoveredDomains && (
                      <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                        <p className="text-sm text-green-400 font-medium">🔄 Chained Subdomain Enumeration Enabled</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          When domains are discovered via Whoxy or other sources, subdomain enumeration (crt.sh, brute-force) 
                          will automatically run on up to {maxDomainsToEnumerate} discovered domains.
                        </p>
                      </div>
                    )}

                    <div className="space-y-2">
                      <Label className="flex items-center gap-2">
                        <Building2 className="h-4 w-4" />
                        Organization Names (WhoisXML IP Range Discovery)
                      </Label>
                      <div className="flex gap-2">
                        <Input
                          placeholder="e.g., Acme Corporation"
                          value={newOrgName}
                          onChange={(e) => setNewOrgName(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && addOrgName()}
                        />
                        <Button onClick={addOrgName} variant="outline" size="icon">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {orgNames.map((name) => (
                          <Badge key={name} variant="secondary" className="flex items-center gap-1">
                            {name}
                            <button onClick={() => removeOrgName(name)} className="ml-1 hover:text-destructive">
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label className="flex items-center gap-2">
                        <Mail className="h-4 w-4" />
                        Registration Emails (Whoxy Reverse WHOIS)
                      </Label>
                      <div className="flex gap-2">
                        <Input
                          placeholder="e.g., domains@company.com"
                          value={newRegEmail}
                          onChange={(e) => setNewRegEmail(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && addRegEmail()}
                        />
                        <Button onClick={addRegEmail} variant="outline" size="icon">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {regEmails.map((email) => (
                          <Badge key={email} variant="secondary" className="flex items-center gap-1">
                            {email}
                            <button onClick={() => removeRegEmail(email)} className="ml-1 hover:text-destructive">
                              <X className="h-3 w-3" />
                            </button>
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* Technology Fingerprinting */}
                    <div className="border-t pt-4 mt-4">
                      <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
                        <Settings className="h-4 w-4" />
                        Technology Fingerprinting (Wappalyzer)
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Automatically scan all discovered domains and subdomains to identify web technologies (CMS, frameworks, servers, etc.) and add technology tags.
                      </p>
                      
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Switch 
                              checked={runTechScan} 
                              onCheckedChange={setRunTechScan} 
                              id="tech-scan"
                            />
                            <Label htmlFor="tech-scan">Run Technology Scan on All Hosts</Label>
                          </div>
                        </div>
                        
                        {runTechScan && (
                          <div className="space-y-2">
                            <Label>Maximum Hosts to Scan</Label>
                            <Input
                              type="number"
                              value={maxTechScan}
                              onChange={(e) => setMaxTechScan(parseInt(e.target.value) || 500)}
                              min={1}
                              max={2000}
                            />
                            <p className="text-xs text-muted-foreground">
                              Hosts are scanned in batches in the background. Each host is probed for technologies like WordPress, Nginx, React, etc.
                            </p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Common Crawl Comprehensive Search */}
                    <div className="border-t pt-4 mt-4">
                      <h4 className="font-medium text-sm mb-3 flex items-center gap-2">
                        <Radar className="h-4 w-4" />
                        Common Crawl Deep Search
                      </h4>
                      <p className="text-xs text-muted-foreground mb-3">
                        Search Common Crawl's billions of URLs for organization-related domains.
                        Use this to find domains like org.*, *org*, and keyword matches like *rockwell*.
                      </p>
                      
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label>Organization Name (for TLD search)</Label>
                          <Input
                            placeholder="e.g., rockwellautomation (finds rockwellautomation.net, .io, .cloud...)"
                            value={ccOrgName}
                            onChange={(e) => setCcOrgName(e.target.value)}
                          />
                          <p className="text-xs text-muted-foreground">
                            Searches for <code>{ccOrgName || 'orgname'}.*</code> across all TLDs
                          </p>
                        </div>
                        
                        <div className="space-y-2">
                          <Label>Keywords (for wildcard search)</Label>
                          <div className="flex gap-2">
                            <Input
                              placeholder="e.g., rockwell (finds *rockwell* domains)"
                              value={newCcKeyword}
                              onChange={(e) => setNewCcKeyword(e.target.value)}
                              onKeyDown={(e) => e.key === 'Enter' && addCcKeyword()}
                            />
                            <Button onClick={addCcKeyword} variant="outline" size="icon">
                              <Plus className="h-4 w-4" />
                            </Button>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Each keyword searches for <code>*keyword*</code> pattern in domain names
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {ccKeywords.map((keyword) => (
                              <Badge key={keyword} variant="secondary" className="flex items-center gap-1">
                                *{keyword}*
                                <button onClick={() => removeCcKeyword(keyword)} className="ml-1 hover:text-destructive">
                                  <X className="h-3 w-3" />
                                </button>
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    <p className="text-xs text-muted-foreground">
                      💡 Configure API keys in <a href="/settings" className="text-primary underline">Settings</a> for VirusTotal, WhoisXML, OTX, and Whoxy.
                    </p>
                  </div>
                )}

                {discoveryRunning && (
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-3">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                      <div>
                        <p className="font-medium">Discovery in progress...</p>
                        <p className="text-sm text-muted-foreground">
                          Querying crt.sh, Wayback, RapidDNS, OTX, and other sources...
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Discovery Results */}
            {discoveryResults && (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-8 w-8 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_subdomains}</p>
                          <p className="text-sm text-muted-foreground">Subdomains</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Server className="h-8 w-8 text-green-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_ips}</p>
                          <p className="text-sm text-muted-foreground">IP Addresses</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Network className="h-8 w-8 text-purple-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_cidrs}</p>
                          <p className="text-sm text-muted-foreground">IP Ranges</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Shield className="h-8 w-8 text-orange-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.assets_created}</p>
                          <p className="text-sm text-muted-foreground">Assets Created</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Clock className="h-8 w-8 text-gray-500" />
                        <div>
                          <p className="text-2xl font-bold">{discoveryResults.total_elapsed_time.toFixed(1)}s</p>
                          <p className="text-sm text-muted-foreground">Total Time</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Source Results */}
                <Card>
                  <CardHeader>
                    <div className="flex justify-between items-center">
                      <CardTitle>Source Results</CardTitle>
                      <Button variant="outline" size="sm" onClick={downloadDiscoveryResults}>
                        <Download className="h-4 w-4 mr-2" />
                        Export JSON
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Source</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Subdomains</TableHead>
                          <TableHead className="text-right">IPs</TableHead>
                          <TableHead className="text-right">CIDRs</TableHead>
                          <TableHead className="text-right">Time</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {discoveryResults.source_results.map((source) => (
                          <TableRow key={source.source}>
                            <TableCell className="font-medium">{source.source}</TableCell>
                            <TableCell>
                              {source.success ? (
                                <Badge variant="default" className="bg-green-600">
                                  <CheckCircle className="h-3 w-3 mr-1" />
                                  Success
                                </Badge>
                              ) : (
                                <Badge variant="destructive">
                                  <XCircle className="h-3 w-3 mr-1" />
                                  {source.error?.substring(0, 30) || 'Failed'}
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-right">{source.subdomains_found}</TableCell>
                            <TableCell className="text-right">{source.ips_found}</TableCell>
                            <TableCell className="text-right">{source.cidrs_found}</TableCell>
                            <TableCell className="text-right">{source.elapsed_time.toFixed(2)}s</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Discovered Assets */}
                <Card>
                  <CardHeader>
                    <CardTitle>Discovered Assets</CardTitle>
                    <div className="flex gap-2 mt-2">
                      <Button variant={discoveryActiveTab === 'subdomains' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('subdomains')}>
                        Subdomains ({discoveryResults.subdomains.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'ips' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('ips')}>
                        IPs ({discoveryResults.ip_addresses.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'domains' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('domains')}>
                        Domains ({discoveryResults.domains.length})
                      </Button>
                      <Button variant={discoveryActiveTab === 'ranges' ? 'default' : 'outline'} size="sm" onClick={() => setDiscoveryActiveTab('ranges')}>
                        Ranges ({discoveryResults.ip_ranges.length})
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-96 overflow-y-auto">
                      {discoveryActiveTab === 'subdomains' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                          {discoveryResults.subdomains.slice(0, 100).map((subdomain) => (
                            <div key={subdomain} className="p-2 bg-muted rounded text-sm font-mono">{subdomain}</div>
                          ))}
                          {discoveryResults.subdomains.length > 100 && (
                            <div className="p-2 text-muted-foreground text-sm col-span-full">
                              ...and {discoveryResults.subdomains.length - 100} more
                            </div>
                          )}
                        </div>
                      )}
                      {discoveryActiveTab === 'ips' && (
                        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-2">
                          {discoveryResults.ip_addresses.slice(0, 100).map((ip) => (
                            <div key={ip} className="p-2 bg-muted rounded text-sm font-mono">{ip}</div>
                          ))}
                          {discoveryResults.ip_addresses.length > 100 && (
                            <div className="p-2 text-muted-foreground text-sm col-span-full">
                              ...and {discoveryResults.ip_addresses.length - 100} more
                            </div>
                          )}
                        </div>
                      )}
                      {discoveryActiveTab === 'domains' && (
                        discoveryResults.domains.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {discoveryResults.domains.map((d) => (
                              <div key={d} className="p-2 bg-muted rounded text-sm font-mono">{d}</div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-muted-foreground">No additional domains discovered</p>
                        )
                      )}
                      {discoveryActiveTab === 'ranges' && (
                        discoveryResults.ip_ranges.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {discoveryResults.ip_ranges.map((range) => (
                              <div key={range} className="p-2 bg-muted rounded text-sm font-mono">{range}</div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-muted-foreground">No IP ranges discovered (requires WhoisXML API key + organization names)</p>
                        )
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Discovery Sources Grid */}
            <div>
              <h2 className="text-lg font-semibold mb-4">Available Discovery Sources</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {discoveryMethods.map((method) => {
                  const status = getSourceStatus(method.key);
                  return (
                    <Card key={method.name} className="hover:border-primary/50 transition-colors">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="text-2xl mb-2">{method.icon}</div>
                          <div className="flex gap-1">
                            {status && (
                              status.success ? (
                                <Badge variant="default" className="bg-green-600 text-xs">
                                  ✓ {status.subdomains_found + status.ips_found + status.cidrs_found}
                                </Badge>
                              ) : (
                                <Badge variant="destructive" className="text-xs">✗</Badge>
                              )
                            )}
                            <Badge variant={method.free ? 'secondary' : 'outline'} className="text-xs">
                              {method.free ? 'Free' : <Key className="h-3 w-3" />}
                            </Badge>
                          </div>
                        </div>
                        <h3 className="font-medium text-sm">{method.name}</h3>
                        <p className="text-xs text-muted-foreground mt-1">{method.description}</p>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </div>
          </TabsContent>

          {/* Wayback URLs Tab */}
          <TabsContent value="wayback" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="h-5 w-5" />
                  Wayback URL Scanner
                </CardTitle>
                <CardDescription>
                  Fetch all historical URLs from the Wayback Machine to find old endpoints, APIs, and sensitive files
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-4">
                  <Button variant={waybackMode === 'single' ? 'default' : 'outline'} onClick={() => setWaybackMode('single')}>
                    Single Domain
                  </Button>
                  <Button variant={waybackMode === 'organization' ? 'default' : 'outline'} onClick={() => setWaybackMode('organization')}>
                    Organization Assets
                  </Button>
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <Switch checked={includeSubdomains} onCheckedChange={setIncludeSubdomains} />
                    <Label>Include Subdomains</Label>
                  </div>

                  <Button
                    onClick={handleRunWayback}
                    disabled={waybackRunning || (waybackMode === 'single' ? !domain : !selectedOrg)}
                  >
                    {waybackRunning ? (
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

                {waybackRunning && (
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-3">
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                      <div>
                        <p className="font-medium">Fetching historical URLs...</p>
                        <p className="text-sm text-muted-foreground">This may take a while for domains with many URLs.</p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Wayback Results */}
            {waybackResults && (
              <div className="space-y-6">
                {/* Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Link className="h-8 w-8 text-blue-500" />
                        <div>
                          <p className="text-2xl font-bold">{totalWaybackUrls.toLocaleString()}</p>
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
                          <p className="text-2xl font-bold">{(waybackResults.unique_paths_count || waybackResults.unique_paths?.length || 0).toLocaleString()}</p>
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
                          <p className="text-2xl font-bold">{(waybackResults.elapsed_time || 0).toFixed(1)}s</p>
                          <p className="text-sm text-muted-foreground">Elapsed</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Domain Results (organization mode) */}
                {waybackResults.domain_results && waybackResults.domain_results.length > 0 && (
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
                          {waybackResults.domain_results.map((dr) => (
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
                {Object.keys(waybackResults.file_extensions || {}).length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>File Extensions Found</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(waybackResults.file_extensions).slice(0, 30).map(([ext, count]) => (
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
                      <Button variant="outline" size="sm" onClick={downloadWaybackResults}>
                        <Download className="h-4 w-4 mr-2" />
                        Export JSON
                      </Button>
                    </div>
                    <div className="flex gap-2 mt-2">
                      <Button variant={waybackActiveTab === 'interesting' ? 'default' : 'outline'} size="sm" onClick={() => setWaybackActiveTab('interesting')}>
                        <AlertTriangle className="h-4 w-4 mr-1" />
                        Interesting ({waybackResults.interesting_urls?.length || 0})
                      </Button>
                      <Button variant={waybackActiveTab === 'all' ? 'default' : 'outline'} size="sm" onClick={() => setWaybackActiveTab('all')}>
                        All URLs ({waybackResults.urls?.length || 0})
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-96 overflow-y-auto space-y-1">
                      {waybackActiveTab === 'interesting' && (
                        waybackResults.interesting_urls?.length > 0 ? (
                          waybackResults.interesting_urls.slice(0, 200).map((url, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                              <a href={url} target="_blank" rel="noopener noreferrer" className="flex-1 truncate text-primary hover:underline">
                                {url}
                              </a>
                              <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            </div>
                          ))
                        ) : (
                          <p className="text-muted-foreground">No interesting URLs found</p>
                        )
                      )}
                      {waybackActiveTab === 'all' && (
                        waybackResults.urls?.length > 0 ? (
                          waybackResults.urls.slice(0, 500).map((url, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm font-mono hover:bg-muted">
                              <a href={url} target="_blank" rel="noopener noreferrer" className="flex-1 truncate text-primary hover:underline">
                                {url}
                              </a>
                              <ExternalLink className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            </div>
                          ))
                        ) : (
                          <p className="text-muted-foreground">No URLs found</p>
                        )
                      )}
                      {((waybackActiveTab === 'interesting' && (waybackResults.interesting_urls?.length || 0) > 200) ||
                        (waybackActiveTab === 'all' && (waybackResults.urls?.length || 0) > 500)) && (
                        <p className="text-sm text-muted-foreground p-2">
                          Showing first {waybackActiveTab === 'interesting' ? 200 : 500} URLs. Export JSON for full list.
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
                  <strong>What is waybackurls?</strong> Fetches all URLs the Wayback Machine has archived for a domain.
                </p>
                <p>
                  <strong>Why is this useful?</strong> Historical URLs can reveal:
                </p>
                <ul className="list-disc pl-6 space-y-1">
                  <li>Old/forgotten endpoints that may still be accessible</li>
                  <li>API endpoints with parameters</li>
                  <li>Backup files, config files, and sensitive data</li>
                  <li>Admin panels and login pages</li>
                </ul>
                <p>
                  <strong>Interesting patterns:</strong> URLs containing admin, api, backup, config, .sql, .bak, .env are highlighted.
                </p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}
