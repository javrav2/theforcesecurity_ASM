'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  Globe, 
  Shield, 
  Lock, 
  Unlock,
  Database,
  Server,
  Mail,
  FileText,
  Terminal,
  Wifi,
  Cloud,
  Code,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface PortService {
  id: number;
  port: number;
  protocol: string;
  service?: string;
  product?: string;
  version?: string;
  state: string;
  is_ssl: boolean;
  is_risky: boolean;
  port_string: string;
  verified_state?: string;
}

interface Technology {
  name: string;
  slug: string;
  categories: string[];
  version?: string;
}

interface ApplicationMapProps {
  assetValue: string;
  assetType: string;
  portServices: PortService[];
  technologies: Technology[];
  httpStatus?: number;
  httpTitle?: string;
}

// Map service names to icons and colors
const serviceIcons: Record<string, { icon: any; color: string; category: string }> = {
  http: { icon: Globe, color: 'text-blue-400', category: 'Web' },
  https: { icon: Lock, color: 'text-green-400', category: 'Web' },
  ssh: { icon: Terminal, color: 'text-orange-400', category: 'Remote Access' },
  ftp: { icon: FileText, color: 'text-yellow-400', category: 'File Transfer' },
  ftps: { icon: Lock, color: 'text-green-400', category: 'File Transfer' },
  sftp: { icon: Lock, color: 'text-green-400', category: 'File Transfer' },
  smtp: { icon: Mail, color: 'text-purple-400', category: 'Email' },
  pop3: { icon: Mail, color: 'text-purple-400', category: 'Email' },
  imap: { icon: Mail, color: 'text-purple-400', category: 'Email' },
  mysql: { icon: Database, color: 'text-cyan-400', category: 'Database' },
  postgresql: { icon: Database, color: 'text-blue-400', category: 'Database' },
  postgres: { icon: Database, color: 'text-blue-400', category: 'Database' },
  mssql: { icon: Database, color: 'text-red-400', category: 'Database' },
  oracle: { icon: Database, color: 'text-red-400', category: 'Database' },
  mongodb: { icon: Database, color: 'text-green-400', category: 'Database' },
  redis: { icon: Database, color: 'text-red-400', category: 'Database' },
  rdp: { icon: Terminal, color: 'text-blue-400', category: 'Remote Access' },
  vnc: { icon: Terminal, color: 'text-purple-400', category: 'Remote Access' },
  telnet: { icon: Terminal, color: 'text-yellow-400', category: 'Remote Access' },
  dns: { icon: Cloud, color: 'text-cyan-400', category: 'Infrastructure' },
  ldap: { icon: Server, color: 'text-orange-400', category: 'Directory' },
  smb: { icon: FileText, color: 'text-blue-400', category: 'File Sharing' },
  nfs: { icon: FileText, color: 'text-green-400', category: 'File Sharing' },
};

// Technology category colors
const techCategoryColors: Record<string, string> = {
  'Web servers': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  'Programming languages': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  'JavaScript frameworks': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  'Web frameworks': 'bg-green-500/20 text-green-400 border-green-500/30',
  'Databases': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  'CMS': 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  'Security': 'bg-red-500/20 text-red-400 border-red-500/30',
  'CDN': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  'Caching': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  'Analytics': 'bg-teal-500/20 text-teal-400 border-teal-500/30',
  'default': 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

function getServiceInfo(service: PortService) {
  const serviceName = service.service?.toLowerCase() || '';
  const port = service.port;
  
  // Try to identify by service name first
  if (serviceIcons[serviceName]) {
    return serviceIcons[serviceName];
  }
  
  // Fall back to port number
  const portMappings: Record<number, string> = {
    80: 'http',
    443: 'https',
    8080: 'http',
    8443: 'https',
    22: 'ssh',
    21: 'ftp',
    990: 'ftps',
    25: 'smtp',
    587: 'smtp',
    110: 'pop3',
    143: 'imap',
    993: 'imap',
    995: 'pop3',
    3306: 'mysql',
    5432: 'postgresql',
    1433: 'mssql',
    1521: 'oracle',
    27017: 'mongodb',
    6379: 'redis',
    3389: 'rdp',
    5900: 'vnc',
    23: 'telnet',
    53: 'dns',
    389: 'ldap',
    636: 'ldap',
    445: 'smb',
    2049: 'nfs',
  };
  
  const mappedService = portMappings[port];
  if (mappedService && serviceIcons[mappedService]) {
    return serviceIcons[mappedService];
  }
  
  // Default
  return { icon: Server, color: 'text-gray-400', category: 'Other' };
}

export function ApplicationMap({ 
  assetValue, 
  assetType, 
  portServices, 
  technologies,
  httpStatus,
  httpTitle,
}: ApplicationMapProps) {
  // Group services by category
  const servicesByCategory: Record<string, PortService[]> = {};
  
  portServices.forEach((service) => {
    const { category } = getServiceInfo(service);
    if (!servicesByCategory[category]) {
      servicesByCategory[category] = [];
    }
    servicesByCategory[category].push(service);
  });

  // Group technologies by category
  const techsByCategory: Record<string, Technology[]> = {};
  
  technologies.forEach((tech) => {
    const category = tech.categories?.[0] || 'Other';
    if (!techsByCategory[category]) {
      techsByCategory[category] = [];
    }
    techsByCategory[category].push(tech);
  });

  const hasData = portServices.length > 0 || technologies.length > 0;

  if (!hasData) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Code className="h-5 w-5" />
            Application Stack
          </CardTitle>
          <CardDescription>
            No services or technologies detected yet. Run a port scan or technology detection scan.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <Code className="h-5 w-5" />
          Application Stack
        </CardTitle>
        <CardDescription>
          Visual map of services, ports, and technologies running on this asset
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Central Asset Node */}
        <div className="flex flex-col items-center mb-8">
          <div className="relative">
            <div className="w-24 h-24 rounded-full bg-gradient-to-br from-primary/30 to-primary/10 border-2 border-primary flex items-center justify-center">
              <div className="text-center">
                <Globe className="h-8 w-8 mx-auto text-primary" />
                <span className="text-xs font-mono truncate max-w-[80px] block mt-1">
                  {assetValue.length > 15 ? assetValue.slice(0, 15) + '...' : assetValue}
                </span>
              </div>
            </div>
            {httpStatus && (
              <div className={cn(
                "absolute -top-2 -right-2 px-2 py-1 rounded-full text-xs font-bold",
                httpStatus >= 200 && httpStatus < 300 ? "bg-green-500/20 text-green-400" :
                httpStatus >= 300 && httpStatus < 400 ? "bg-blue-500/20 text-blue-400" :
                httpStatus >= 400 && httpStatus < 500 ? "bg-yellow-500/20 text-yellow-400" :
                "bg-red-500/20 text-red-400"
              )}>
                {httpStatus}
              </div>
            )}
          </div>
          {httpTitle && (
            <span className="text-xs text-muted-foreground mt-2 max-w-[200px] truncate">
              {httpTitle}
            </span>
          )}
        </div>

        {/* Services Section */}
        {Object.keys(servicesByCategory).length > 0 && (
          <div className="mb-6">
            <h4 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
              Network Services
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(servicesByCategory).map(([category, services]) => (
                <div key={category} className="bg-secondary/30 rounded-lg p-4">
                  <h5 className="text-xs font-semibold text-muted-foreground mb-3">{category}</h5>
                  <div className="space-y-2">
                    {services.map((service) => {
                      const { icon: Icon, color } = getServiceInfo(service);
                      return (
                        <div
                          key={service.id || `${service.port}-${service.protocol}`}
                          className={cn(
                            "flex items-center gap-3 p-2 rounded-md transition-colors",
                            // Filtered ports show yellow, risky show red, otherwise neutral
                            (service.state?.toLowerCase() === 'filtered' || service.verified_state?.toLowerCase() === 'filtered')
                              ? "bg-yellow-500/10 border border-yellow-500/30"
                              : service.is_risky 
                                ? "bg-red-500/10 border border-red-500/30" 
                                : "bg-background/50 hover:bg-background"
                          )}
                        >
                          <Icon className={cn("h-5 w-5", color)} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-sm font-bold">
                                {service.port}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                /{service.protocol}
                              </span>
                              {service.is_ssl && (
                                <Lock className="h-3 w-3 text-green-400" />
                              )}
                              {(service.state?.toLowerCase() === 'filtered' || service.verified_state?.toLowerCase() === 'filtered') && (
                                <AlertTriangle className="h-3 w-3 text-yellow-400" />
                              )}
                              {service.is_risky && !(service.state?.toLowerCase() === 'filtered' || service.verified_state?.toLowerCase() === 'filtered') && (
                                <AlertTriangle className="h-3 w-3 text-red-400" />
                              )}
                            </div>
                            {(service.service || service.product) && (
                              <div className="text-xs text-muted-foreground truncate">
                                {service.service}
                                {service.product && ` • ${service.product}`}
                                {service.version && ` ${service.version}`}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Technologies Section */}
        {Object.keys(techsByCategory).length > 0 && (
          <div>
            <h4 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
              Detected Technologies
            </h4>
            <div className="space-y-4">
              {Object.entries(techsByCategory).map(([category, techs]) => (
                <div key={category}>
                  <h5 className="text-xs font-semibold text-muted-foreground mb-2">{category}</h5>
                  <div className="flex flex-wrap gap-2">
                    {techs.map((tech, idx) => (
                      <Badge
                        key={idx}
                        className={cn(
                          "py-1.5 px-3",
                          techCategoryColors[category] || techCategoryColors.default
                        )}
                      >
                        <span className="font-medium">{tech.name}</span>
                        {tech.version && (
                          <span className="ml-1 opacity-75">v{tech.version}</span>
                        )}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Summary Stats */}
        <div className="mt-6 pt-4 border-t border-border flex flex-wrap gap-4 text-sm">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">{portServices.length} ports</span>
          </div>
          <div className="flex items-center gap-2">
            <Code className="h-4 w-4 text-muted-foreground" />
            <span className="text-muted-foreground">{technologies.length} technologies</span>
          </div>
          {portServices.filter(p => p.is_risky).length > 0 && (
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              <span className="text-red-400">
                {portServices.filter(p => p.is_risky).length} risky
              </span>
            </div>
          )}
          {portServices.filter(p => p.is_ssl).length > 0 && (
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-green-400" />
              <span className="text-green-400">
                {portServices.filter(p => p.is_ssl).length} encrypted
              </span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

