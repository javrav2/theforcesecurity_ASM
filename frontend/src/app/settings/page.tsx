'use client';

import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Settings, Key, Bell, Shield, Database } from 'lucide-react';

export default function SettingsPage() {
  return (
    <MainLayout>
      <Header title="Settings" subtitle="Configure platform settings and integrations" />

      <div className="p-6 space-y-6">
        {/* API Keys */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              API Keys
            </CardTitle>
            <CardDescription>
              Configure API keys for external discovery services
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>VirusTotal API Key</Label>
                <Input type="password" placeholder="Enter API key..." />
              </div>
              <div className="space-y-2">
                <Label>WhoisXML API Key</Label>
                <Input type="password" placeholder="Enter API key..." />
              </div>
              <div className="space-y-2">
                <Label>AlienVault OTX API Key</Label>
                <Input type="password" placeholder="Enter API key..." />
              </div>
              <div className="space-y-2">
                <Label>Whoxy API Key</Label>
                <Input type="password" placeholder="Enter API key..." />
              </div>
            </div>
            <Button>Save API Keys</Button>
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

