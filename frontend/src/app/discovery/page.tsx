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
  Search,
  Globe,
  Loader2,
  Play,
  CheckCircle,
  Database,
  Key,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface DiscoveryService {
  name: string;
  description: string;
  requires_api_key: boolean;
  is_free: boolean;
  configured: boolean;
}

export default function DiscoveryPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [services, setServices] = useState<DiscoveryService[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [domain, setDomain] = useState('');
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [orgsData, servicesData] = await Promise.all([
        api.getOrganizations(),
        api.getExternalDiscoveryServices().catch(() => ({ services: [] })),
      ]);

      setOrganizations(orgsData);
      setServices(servicesData.services || []);
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
    try {
      await api.runExternalDiscovery({
        organization_id: parseInt(selectedOrg),
        domain,
      });

      toast({
        title: 'Discovery Started',
        description: 'External discovery scan has been started. Check back for results.',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to start discovery',
        variant: 'destructive',
      });
    } finally {
      setRunning(false);
    }
  };

  const discoveryMethods = [
    {
      name: 'Certificate Transparency',
      description: 'Discover subdomains from CT logs (crt.sh)',
      icon: '🔐',
      free: true,
    },
    {
      name: 'Wayback Machine',
      description: 'Find historical URLs and subdomains',
      icon: '📜',
      free: true,
    },
    {
      name: 'RapidDNS',
      description: 'DNS enumeration and subdomain discovery',
      icon: '🌐',
      free: true,
    },
    {
      name: 'Microsoft 365',
      description: 'Discover M365 tenant information',
      icon: '☁️',
      free: true,
    },
    {
      name: 'VirusTotal',
      description: 'Subdomain discovery via VT API',
      icon: '🦠',
      free: false,
    },
    {
      name: 'AlienVault OTX',
      description: 'Threat intelligence and domain data',
      icon: '👽',
      free: true,
    },
    {
      name: 'WhoisXML API',
      description: 'WHOIS and reverse DNS lookups',
      icon: '📋',
      free: false,
    },
    {
      name: 'Whoxy',
      description: 'WHOIS history and reverse lookups',
      icon: '🔍',
      free: false,
    },
  ];

  return (
    <MainLayout>
      <Header title="Discovery" subtitle="External asset discovery and enumeration" />

      <div className="p-6 space-y-6">
        {/* Run Discovery */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Run External Discovery
            </CardTitle>
            <CardDescription>
              Discover assets using multiple external data sources
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
                <Label>Domain</Label>
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </div>

              <div className="flex items-end">
                <Button
                  onClick={handleRunDiscovery}
                  disabled={running || !selectedOrg || !domain}
                  className="w-full"
                >
                  {running ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Running...
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
          </CardContent>
        </Card>

        {/* Discovery Methods */}
        <div>
          <h2 className="text-lg font-semibold mb-4">Discovery Methods</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {discoveryMethods.map((method) => (
              <Card key={method.name} className="hover:border-primary/50 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="text-2xl mb-2">{method.icon}</div>
                    <Badge variant={method.free ? 'secondary' : 'outline'}>
                      {method.free ? 'Free' : 'API Key Required'}
                    </Badge>
                  </div>
                  <h3 className="font-medium">{method.name}</h3>
                  <p className="text-sm text-muted-foreground mt-1">{method.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Built-in Tools */}
        <div>
          <h2 className="text-lg font-semibold mb-4">Built-in Discovery Tools</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Globe className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium">Subfinder</h3>
                    <p className="text-sm text-muted-foreground">Passive subdomain enumeration</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Database className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium">HTTPX</h3>
                    <p className="text-sm text-muted-foreground">HTTP probing and tech detection</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Search className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium">DNSX</h3>
                    <p className="text-sm text-muted-foreground">DNS resolution and brute-forcing</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}

