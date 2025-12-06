'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { Settings, Key, Bell, Shield, Database, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface ApiConfig {
  id: number;
  service_name: string;
  api_key_masked: string | null;
  is_active: boolean;
  is_valid: boolean;
  last_used: string | null;
  usage_count: number;
}

const API_SERVICES = [
  { name: 'virustotal', label: 'VirusTotal', description: 'Subdomain discovery via VT database', free: false },
  { name: 'whoisxml', label: 'WhoisXML API', description: 'WHOIS and IP range lookups', free: false },
  { name: 'otx', label: 'AlienVault OTX', description: 'Threat intelligence data (free API key)', free: true },
  { name: 'whoxy', label: 'Whoxy', description: 'Reverse WHOIS lookups', free: false },
];

export default function SettingsPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [apiConfigs, setApiConfigs] = useState<ApiConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const orgsData = await api.getOrganizations();
      setOrganizations(orgsData);
      if (orgsData.length > 0) {
        setSelectedOrg(orgsData[0].id.toString());
      }
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchApiConfigs = async (orgId: number) => {
    try {
      const data = await api.getApiConfigs(orgId);
      setApiConfigs(data.configs || []);
    } catch (error) {
      console.error('Failed to fetch API configs:', error);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedOrg) {
      fetchApiConfigs(parseInt(selectedOrg));
    }
  }, [selectedOrg]);

  const getConfigForService = (serviceName: string) => {
    return apiConfigs.find(c => c.service_name === serviceName);
  };

  const handleSaveApiKey = async (serviceName: string) => {
    const key = apiKeys[serviceName];
    if (!key || !selectedOrg) {
      toast({
        title: 'Error',
        description: 'Please enter an API key',
        variant: 'destructive',
      });
      return;
    }

    setSaving(serviceName);
    try {
      await api.saveApiConfig(parseInt(selectedOrg), {
        service_name: serviceName,
        api_key: key,
      });
      
      toast({
        title: 'Success',
        description: `${serviceName} API key saved successfully`,
      });
      
      setApiKeys({ ...apiKeys, [serviceName]: '' });
      fetchApiConfigs(parseInt(selectedOrg));
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to save API key',
        variant: 'destructive',
      });
    } finally {
      setSaving(null);
    }
  };

  return (
    <MainLayout>
      <Header title="Settings" subtitle="Configure platform settings and integrations" />

      <div className="p-6 space-y-6">
        {/* Organization Selector */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              Organization Settings
            </CardTitle>
            <CardDescription>
              API keys are configured per organization
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="w-64">
              <Label>Select Organization</Label>
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
          </CardContent>
        </Card>

        {/* API Keys */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              External Discovery API Keys
            </CardTitle>
            <CardDescription>
              Configure API keys to enable additional discovery sources. These keys are encrypted at rest.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {API_SERVICES.map((service) => {
              const config = getConfigForService(service.name);
              return (
                <div key={service.name} className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{service.label}</h3>
                        {config?.is_valid && (
                          <Badge variant="default" className="bg-green-600">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Configured
                          </Badge>
                        )}
                        {config && !config.is_valid && (
                          <Badge variant="destructive">
                            <AlertCircle className="h-3 w-3 mr-1" />
                            Invalid
                          </Badge>
                        )}
                        <Badge variant={service.free ? 'secondary' : 'outline'}>
                          {service.free ? 'Free Tier' : 'Paid'}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{service.description}</p>
                    </div>
                  </div>
                  
                  {config?.api_key_masked && (
                    <div className="text-sm text-muted-foreground">
                      Current key: <code className="bg-muted px-1 rounded">{config.api_key_masked}</code>
                      {config.usage_count > 0 && (
                        <span className="ml-2">• Used {config.usage_count} times</span>
                      )}
                    </div>
                  )}
                  
                  <div className="flex gap-2">
                    <Input
                      type="password"
                      placeholder={config ? 'Enter new API key to update...' : 'Enter API key...'}
                      value={apiKeys[service.name] || ''}
                      onChange={(e) => setApiKeys({ ...apiKeys, [service.name]: e.target.value })}
                      className="flex-1"
                    />
                    <Button
                      onClick={() => handleSaveApiKey(service.name)}
                      disabled={saving === service.name || !apiKeys[service.name]}
                    >
                      {saving === service.name ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        'Save'
                      )}
                    </Button>
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Free Sources Info */}
        <Card>
          <CardHeader>
            <CardTitle>Free Discovery Sources</CardTitle>
            <CardDescription>These sources work without API keys</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🔐 crt.sh</p>
                <p className="text-xs text-muted-foreground">Certificate Transparency</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">📜 Wayback Machine</p>
                <p className="text-xs text-muted-foreground">Historical URLs</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🌐 RapidDNS</p>
                <p className="text-xs text-muted-foreground">DNS Enumeration</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">☁️ Microsoft 365</p>
                <p className="text-xs text-muted-foreground">Federated Domains</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5" />
              Notifications
            </CardTitle>
            <CardDescription>Configure alert and notification preferences</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Critical Vulnerability Alerts</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when critical vulnerabilities are discovered
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">New Asset Discovery</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when new assets are discovered
                </p>
              </div>
              <Switch defaultChecked />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Scan Completion</p>
                <p className="text-sm text-muted-foreground">
                  Get notified when scans complete
                </p>
              </div>
              <Switch />
            </div>
          </CardContent>
        </Card>

        {/* Scan Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Scan Settings
            </CardTitle>
            <CardDescription>Configure default scan parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Default Severity Filter</Label>
                <div className="flex gap-2">
                  <Badge variant="critical">Critical</Badge>
                  <Badge variant="high">High</Badge>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Scan Rate Limit</Label>
                <Input type="number" placeholder="150" defaultValue={150} />
                <p className="text-xs text-muted-foreground">Requests per second</p>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Auto-update Nuclei Templates</p>
                <p className="text-sm text-muted-foreground">
                  Automatically update templates before each scan
                </p>
              </div>
              <Switch defaultChecked />
            </div>
          </CardContent>
        </Card>

        {/* System Info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              System Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Version</p>
                <p className="font-medium">1.0.0</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Nuclei Version</p>
                <p className="font-medium">v3.x</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Templates</p>
                <p className="font-medium">8000+</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Database</p>
                <p className="font-medium">PostgreSQL 15</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
