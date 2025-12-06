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
import { 
  Settings, 
  Key, 
  Bell, 
  Shield, 
  Database, 
  Loader2, 
  CheckCircle, 
  AlertCircle,
  Plus,
  X,
  Building2,
  Mail,
  Globe,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface ApiConfig {
  id: number;
  service_name: string;
  api_key_masked: string | null;
  api_user: string | null;
  config: Record<string, any>;
  is_active: boolean;
  is_valid: boolean;
  last_used: string | null;
  usage_count: number;
}

const API_SERVICES = [
  { 
    name: 'virustotal', 
    label: 'VirusTotal', 
    description: 'Subdomain discovery via VT database (up to 100 subdomains per domain)',
    free: false,
    hasUser: true,
    link: 'https://www.virustotal.com/gui/join-us'
  },
  { 
    name: 'whoisxml', 
    label: 'WhoisXML API', 
    description: 'Discover IP ranges and CIDRs by organization name',
    free: false,
    hasUser: false,
    needsOrgNames: true,
    link: 'https://whoisxmlapi.com/'
  },
  { 
    name: 'otx', 
    label: 'AlienVault OTX', 
    description: 'Threat intelligence passive DNS and URL data (free API key available)',
    free: true,
    hasUser: false,
    link: 'https://otx.alienvault.com/api'
  },
  { 
    name: 'whoxy', 
    label: 'Whoxy', 
    description: 'Reverse WHOIS lookup by domain registration email',
    free: false,
    hasUser: false,
    needsEmails: true,
    link: 'https://www.whoxy.com/'
  },
];

export default function SettingsPage() {
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('');
  const [apiConfigs, setApiConfigs] = useState<ApiConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<Record<string, string>>({});
  const [apiUsers, setApiUsers] = useState<Record<string, string>>({});
  
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
      
      // Load existing organization names and emails from config
      const whoisxmlConfig = data.configs?.find((c: ApiConfig) => c.service_name === 'whoisxml');
      if (whoisxmlConfig?.config?.organization_names) {
        setOrgNames(whoisxmlConfig.config.organization_names);
      }
      
      const whoxyConfig = data.configs?.find((c: ApiConfig) => c.service_name === 'whoxy');
      if (whoxyConfig?.config?.registration_emails) {
        setRegEmails(whoxyConfig.config.registration_emails);
      }
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
      // Reset form state
      setOrgNames([]);
      setRegEmails([]);
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
      const payload: any = {
        service_name: serviceName,
        api_key: key,
      };
      
      // Add user for VirusTotal
      if (serviceName === 'virustotal' && apiUsers[serviceName]) {
        payload.api_user = apiUsers[serviceName];
      }
      
      // Add organization names for WhoisXML
      if (serviceName === 'whoisxml' && orgNames.length > 0) {
        payload.config = { organization_names: orgNames };
      }
      
      // Add registration emails for Whoxy
      if (serviceName === 'whoxy' && regEmails.length > 0) {
        payload.config = { registration_emails: regEmails };
      }
      
      await api.saveApiConfig(parseInt(selectedOrg), payload);
      
      toast({
        title: 'Success',
        description: `${serviceName} API key saved successfully`,
      });
      
      setApiKeys({ ...apiKeys, [serviceName]: '' });
      setApiUsers({ ...apiUsers, [serviceName]: '' });
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

  return (
    <MainLayout>
      <Header title="Settings" subtitle="Configure API keys and platform settings" />

      <div className="p-6 space-y-6">
        {/* Organization Selector */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5" />
              Organization Settings
            </CardTitle>
            <CardDescription>
              API keys and discovery settings are configured per organization
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

        {/* Discovery Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Building2 className="h-5 w-5" />
              Organization & Email Discovery Settings
            </CardTitle>
            <CardDescription>
              Configure organization names for IP range discovery and registration emails for reverse WHOIS lookups
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Organization Names for WhoisXML */}
            <div className="space-y-3">
              <Label className="flex items-center gap-2">
                <Building2 className="h-4 w-4" />
                Organization Names (for WhoisXML IP Range Discovery)
              </Label>
              <p className="text-sm text-muted-foreground">
                Enter company/organization names to discover IP ranges and CIDRs they own
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., Rockwell Automation"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addOrgName()}
                />
                <Button onClick={addOrgName} variant="outline">
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {orgNames.map((name) => (
                  <Badge key={name} variant="secondary" className="flex items-center gap-1 px-3 py-1">
                    {name}
                    <button onClick={() => removeOrgName(name)} className="ml-1 hover:text-destructive">
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                {orgNames.length === 0 && (
                  <span className="text-sm text-muted-foreground">No organization names configured</span>
                )}
              </div>
            </div>

            {/* Registration Emails for Whoxy */}
            <div className="space-y-3">
              <Label className="flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Registration Emails (for Whoxy Reverse WHOIS)
              </Label>
              <p className="text-sm text-muted-foreground">
                Enter email addresses used to register domains to discover all domains registered with those emails
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g., domains@yourcompany.com"
                  value={newRegEmail}
                  onChange={(e) => setNewRegEmail(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addRegEmail()}
                />
                <Button onClick={addRegEmail} variant="outline">
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {regEmails.map((email) => (
                  <Badge key={email} variant="secondary" className="flex items-center gap-1 px-3 py-1">
                    {email}
                    <button onClick={() => removeRegEmail(email)} className="ml-1 hover:text-destructive">
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                {regEmails.length === 0 && (
                  <span className="text-sm text-muted-foreground">No registration emails configured</span>
                )}
              </div>
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
              Configure API keys to enable additional discovery sources. Keys are encrypted at rest.
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
                          {service.free ? 'Free Tier Available' : 'Paid'}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{service.description}</p>
                      <a 
                        href={service.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-xs text-primary hover:underline"
                      >
                        Get API Key →
                      </a>
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
                  
                  <div className="space-y-2">
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
                    
                    {service.hasUser && (
                      <div className="flex gap-2">
                        <Input
                          placeholder="API Username (optional)"
                          value={apiUsers[service.name] || ''}
                          onChange={(e) => setApiUsers({ ...apiUsers, [service.name]: e.target.value })}
                          className="flex-1"
                        />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Free Sources Info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Free Discovery Sources (No API Key Required)
            </CardTitle>
            <CardDescription>These sources are automatically used during discovery</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🔐 Certificate Transparency</p>
                <p className="text-xs text-muted-foreground">crt.sh - SSL/TLS certificate logs</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">📜 Wayback Machine</p>
                <p className="text-xs text-muted-foreground">Historical URLs and subdomains</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">🌐 RapidDNS</p>
                <p className="text-xs text-muted-foreground">DNS enumeration</p>
              </div>
              <div className="p-3 bg-muted rounded-lg">
                <p className="font-medium">☁️ Microsoft 365</p>
                <p className="text-xs text-muted-foreground">Federated domain discovery</p>
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
