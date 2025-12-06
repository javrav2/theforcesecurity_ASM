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
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

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

export default function DiscoveryPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<DiscoveryResult | null>(null);
  const [activeTab, setActiveTab] = useState<'subdomains' | 'ips' | 'domains' | 'ranges'>('subdomains');
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  // Advanced options
  const [includePaid, setIncludePaid] = useState(true);
  const [includeFree, setIncludeFree] = useState(true);
  const [createAssets, setCreateAssets] = useState(true);
  
  // Organization names for WhoisXML
  const [orgNames, setOrgNames] = useState<string[]>([]);
  const [newOrgName, setNewOrgName] = useState('');
  
  // Registration emails for Whoxy
  const [regEmails, setRegEmails] = useState<string[]>([]);
  const [newRegEmail, setNewRegEmail] = useState('');
  
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const orgsData = await api.getOrganizations();
      setOrganizations(orgsData);
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunDiscovery = async () => {
    if (!selectedOrg || !domain) {
      toast({
        title: 'Error',
        description: 'Please select an organization and enter a domain',
        variant: 'destructive',
      });
      return;
    }

    setRunning(true);
    setResults(null);
    try {
      const result = await api.runExternalDiscovery({
        organization_id: parseInt(selectedOrg),
        domain,
        include_paid_sources: includePaid,
        include_free_sources: includeFree,
        create_assets: createAssets,
        skip_existing: true,
        organization_names: orgNames.length > 0 ? orgNames : undefined,
        registration_emails: regEmails.length > 0 ? regEmails : undefined,
      });

      setResults(result);
      toast({
        title: 'Discovery Complete',
        description: `Found ${result.total_subdomains} subdomains, ${result.total_ips} IPs. Created ${result.assets_created} new assets.`,
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to run discovery',
        variant: 'destructive',
      });
    } finally {
      setRunning(false);
    }
  };

  const downloadResults = () => {
    if (!results) return;
    
    const data = {
      domain: results.domain,
      timestamp: new Date().toISOString(),
      subdomains: results.subdomains,
      domains: results.domains,
      ip_addresses: results.ip_addresses,
      ip_ranges: results.ip_ranges,
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `discovery-${results.domain}-${Date.now()}.json`;
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

  const discoveryMethods = [
    {
      name: 'Certificate Transparency (crt.sh)',
      key: 'crtsh',
      description: 'Discover subdomains from SSL/TLS certificate logs',
      icon: '🔐',
      free: true,
    },
    {
      name: 'Wayback Machine',
      key: 'wayback',
      description: 'Find historical URLs and subdomains from web archives',
      icon: '📜',
      free: true,
    },
    {
      name: 'RapidDNS',
      key: 'rapiddns',
      description: 'DNS enumeration and subdomain discovery',
      icon: '🌐',
      free: true,
    },
    {
      name: 'Microsoft 365 Federation',
      key: 'm365',
      description: 'Discover federated M365 tenant domains',
      icon: '☁️',
      free: true,
    },
    {
      name: 'AlienVault OTX',
      key: 'otx',
      description: 'Threat intelligence passive DNS data',
      icon: '👽',
      free: true,
    },
    {
      name: 'VirusTotal',
      key: 'virustotal',
      description: 'Subdomain discovery via VT database',
      icon: '🦠',
      free: false,
    },
    {
      name: 'WhoisXML API',
      key: 'whoisxml',
      description: 'IP ranges & CIDRs by organization name',
      icon: '📋',
      free: false,
    },
    {
      name: 'Whoxy',
      key: 'whoxy',
      description: 'Reverse WHOIS by registration email',
      icon: '🔍',
      free: false,
    },
  ];

  const getSourceStatus = (sourceKey: string) => {
    if (!results) return null;
    return results.source_results.find(s => s.source.toLowerCase().includes(sourceKey));
  };

  return (
    <MainLayout>
      <Header title="External Discovery" subtitle="Discover assets using certificate transparency, DNS, and threat intelligence" />

      <div className="p-6 space-y-6">
        {/* Run Discovery */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Run External Discovery
            </CardTitle>
            <CardDescription>
              Enter a domain to discover subdomains, related domains, and IP addresses from multiple sources
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
                <Label>Target Domain</Label>
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </div>

              <div className="flex items-end gap-2">
                <Button
                  onClick={handleRunDiscovery}
                  disabled={running || !selectedOrg || !domain}
                  className="flex-1"
                >
                  {running ? (
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
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center gap-2">
                    <Switch checked={includeFree} onCheckedChange={setIncludeFree} />
                    <Label>Include Free Sources</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={includePaid} onCheckedChange={setIncludePaid} />
                    <Label>Include Paid Sources</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={createAssets} onCheckedChange={setCreateAssets} />
                    <Label>Create Assets in Database</Label>
                  </div>
                </div>

                {/* Organization Names for WhoisXML */}
                <div className="space-y-2">
                  <Label className="flex items-center gap-2">
                    <Building2 className="h-4 w-4" />
                    Organization Names (for WhoisXML IP Range Discovery)
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="e.g., Rockwell Automation"
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

                {/* Registration Emails for Whoxy */}
                <div className="space-y-2">
                  <Label className="flex items-center gap-2">
                    <Mail className="h-4 w-4" />
                    Registration Emails (for Whoxy Reverse WHOIS)
                  </Label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="e.g., domains@yourcompany.com"
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

                <p className="text-xs text-muted-foreground">
                  💡 Configure API keys in <a href="/settings" className="text-primary underline">Settings</a> to enable VirusTotal, WhoisXML, OTX, and Whoxy.
                </p>
              </div>
            )}

            {running && (
              <div className="p-4 bg-muted rounded-lg">
                <div className="flex items-center gap-3">
                  <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  <div>
                    <p className="font-medium">Discovery in progress...</p>
                    <p className="text-sm text-muted-foreground">
                      Querying crt.sh, Wayback Machine, RapidDNS, OTX, and other sources...
                    </p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results Summary */}
        {results && (
          <div className="space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <Globe className="h-8 w-8 text-blue-500" />
                    <div>
                      <p className="text-2xl font-bold">{results.total_subdomains}</p>
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
                      <p className="text-2xl font-bold">{results.total_ips}</p>
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
                      <p className="text-2xl font-bold">{results.total_cidrs}</p>
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
                      <p className="text-2xl font-bold">{results.assets_created}</p>
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
                      <p className="text-2xl font-bold">{results.total_elapsed_time.toFixed(1)}s</p>
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
                  <Button variant="outline" size="sm" onClick={downloadResults}>
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
                    {results.source_results.map((source) => (
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
                  <Button
                    variant={activeTab === 'subdomains' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('subdomains')}
                  >
                    Subdomains ({results.subdomains.length})
                  </Button>
                  <Button
                    variant={activeTab === 'ips' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('ips')}
                  >
                    IPs ({results.ip_addresses.length})
                  </Button>
                  <Button
                    variant={activeTab === 'domains' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('domains')}
                  >
                    Domains ({results.domains.length})
                  </Button>
                  <Button
                    variant={activeTab === 'ranges' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setActiveTab('ranges')}
                  >
                    Ranges ({results.ip_ranges.length})
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="max-h-96 overflow-y-auto">
                  {activeTab === 'subdomains' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                      {results.subdomains.slice(0, 100).map((subdomain) => (
                        <div key={subdomain} className="p-2 bg-muted rounded text-sm font-mono">
                          {subdomain}
                        </div>
                      ))}
                      {results.subdomains.length > 100 && (
                        <div className="p-2 text-muted-foreground text-sm col-span-full">
                          ...and {results.subdomains.length - 100} more
                        </div>
                      )}
                    </div>
                  )}
                  {activeTab === 'ips' && (
                    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-2">
                      {results.ip_addresses.slice(0, 100).map((ip) => (
                        <div key={ip} className="p-2 bg-muted rounded text-sm font-mono">
                          {ip}
                        </div>
                      ))}
                      {results.ip_addresses.length > 100 && (
                        <div className="p-2 text-muted-foreground text-sm col-span-full">
                          ...and {results.ip_addresses.length - 100} more
                        </div>
                      )}
                    </div>
                  )}
                  {activeTab === 'domains' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {results.domains.map((domain) => (
                        <div key={domain} className="p-2 bg-muted rounded text-sm font-mono">
                          {domain}
                        </div>
                      ))}
                      {results.domains.length === 0 && (
                        <p className="text-muted-foreground">No additional domains discovered</p>
                      )}
                    </div>
                  )}
                  {activeTab === 'ranges' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {results.ip_ranges.map((range) => (
                        <div key={range} className="p-2 bg-muted rounded text-sm font-mono">
                          {range}
                        </div>
                      ))}
                      {results.ip_ranges.length === 0 && (
                        <p className="text-muted-foreground">No IP ranges discovered (requires WhoisXML API key + organization names)</p>
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Discovery Methods Grid */}
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
                          {method.free ? 'Free' : <><Key className="h-3 w-3" /></>}
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

        {/* Help Section */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">How External Discovery Works</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>
              <strong>Certificate Transparency (crt.sh):</strong> Queries public CT logs for SSL certificates 
              issued to your domain, revealing subdomains that have been issued certificates.
            </p>
            <p>
              <strong>Wayback Machine:</strong> Searches the Internet Archive for historical URLs 
              associated with your domain, uncovering old or forgotten subdomains.
            </p>
            <p>
              <strong>RapidDNS:</strong> Queries DNS databases for subdomain enumeration.
            </p>
            <p>
              <strong>Microsoft 365:</strong> Discovers federated domains associated with your M365 tenant.
            </p>
            <p>
              <strong>AlienVault OTX:</strong> Leverages threat intelligence to find passive DNS records and related domains.
            </p>
            <p>
              <strong>WhoisXML API:</strong> Discovers IP ranges (CIDRs) registered to your organization name.
            </p>
            <p>
              <strong>Whoxy:</strong> Finds all domains registered using your company email addresses.
            </p>
            <p className="pt-2 border-t">
              <strong>💡 Tip:</strong> Configure API keys in <a href="/settings" className="text-primary underline">Settings</a> and 
              add organization names + registration emails in Advanced Options for comprehensive IP range and domain discovery.
            </p>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
