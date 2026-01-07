'use client';

import { 
  Globe, 
  Shield, 
  Search, 
  FileText, 
  Link as LinkIcon, 
  Server, 
  Lock,
  Mail,
  Building,
  ArrowRight,
  ChevronRight,
  ExternalLink,
  Database,
  Radar
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

interface DiscoveryStep {
  step: number;
  source: string;
  match_type?: string;
  match_value?: string;
  query_domain?: string;
  timestamp?: string;
  confidence?: number;
}

interface DiscoveryPathProps {
  value: string;  // The asset hostname
  assetType: string;
  rootDomain?: string;
  liveUrl?: string;
  discoverySource?: string;
  discoveryChain?: DiscoveryStep[];
  associationReason?: string;
  associationConfidence?: number;
}

const sourceIcons: Record<string, any> = {
  manual: Globe,
  whoxy: Mail,
  crtsh: Lock,
  virustotal: Shield,
  otx: Database,
  wayback: FileText,
  rapiddns: Search,
  subfinder: Radar,
  m365: Building,
  commoncrawl: Database,
  commoncrawl_comprehensive: Database,
  sni_ip_ranges: Server,
  external_discovery: Search,
  http_probe: LinkIcon,
  nuclei: Shield,
  default: Search,
};

const sourceColors: Record<string, string> = {
  manual: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  whoxy: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
  crtsh: 'bg-green-500/10 text-green-500 border-green-500/20',
  virustotal: 'bg-red-500/10 text-red-500 border-red-500/20',
  otx: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  wayback: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
  rapiddns: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
  subfinder: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
  m365: 'bg-blue-600/10 text-blue-600 border-blue-600/20',
  commoncrawl: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  sni_ip_ranges: 'bg-pink-500/10 text-pink-500 border-pink-500/20',
  external_discovery: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  http_probe: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
  nuclei: 'bg-rose-500/10 text-rose-500 border-rose-500/20',
  default: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
};

const sourceNames: Record<string, string> = {
  manual: 'Manual Entry',
  whoxy: 'Whoxy Reverse WHOIS',
  crtsh: 'Certificate Transparency',
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  wayback: 'Wayback Machine',
  rapiddns: 'RapidDNS',
  subfinder: 'Subfinder',
  m365: 'Microsoft 365 Federation',
  commoncrawl: 'Common Crawl',
  commoncrawl_comprehensive: 'Common Crawl',
  sni_ip_ranges: 'SNI/Cloud Discovery',
  external_discovery: 'External Discovery',
  http_probe: 'HTTP Probe',
  nuclei: 'Nuclei Scan',
};

function DiscoveryNode({ 
  icon: Icon, 
  label, 
  value, 
  colorClass,
  isLast = false,
  detail
}: { 
  icon: any; 
  label: string; 
  value: string; 
  colorClass: string;
  isLast?: boolean;
  detail?: string;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex flex-col items-center">
        <div className={cn(
          "w-10 h-10 rounded-full flex items-center justify-center border",
          colorClass
        )}>
          <Icon className="h-5 w-5" />
        </div>
        {!isLast && (
          <div className="w-0.5 h-8 bg-border mt-2" />
        )}
      </div>
      <div className="pt-1.5">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">{label}</p>
        <p className="font-medium">{value}</p>
        {detail && (
          <p className="text-xs text-muted-foreground mt-0.5">{detail}</p>
        )}
      </div>
    </div>
  );
}

export function DiscoveryPath({
  value,
  assetType,
  rootDomain,
  liveUrl,
  discoverySource,
  discoveryChain,
  associationReason,
  associationConfidence
}: DiscoveryPathProps) {
  const source = discoverySource?.toLowerCase() || 'manual';
  const SourceIcon = sourceIcons[source] || sourceIcons.default;
  const sourceColor = sourceColors[source] || sourceColors.default;
  const sourceName = sourceNames[source] || discoverySource || 'Unknown';
  
  // Build the visual path
  const nodes: Array<{
    icon: any;
    label: string;
    value: string;
    colorClass: string;
    detail?: string;
  }> = [];
  
  // 1. Root domain (if different from asset)
  if (rootDomain && rootDomain !== value) {
    nodes.push({
      icon: Globe,
      label: 'Root Domain',
      value: rootDomain,
      colorClass: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      detail: 'Primary organizational domain'
    });
  }
  
  // 2. Discovery source
  const matchDetail = discoveryChain?.find(s => s.match_value)?.match_value;
  nodes.push({
    icon: SourceIcon,
    label: 'Discovery Method',
    value: sourceName,
    colorClass: sourceColor,
    detail: matchDetail ? `Matched: ${matchDetail}` : undefined
  });
  
  // 3. Asset itself (subdomain/domain)
  const assetIcon = assetType === 'domain' ? Globe : 
                    assetType === 'subdomain' ? Globe :
                    assetType === 'ip_address' ? Server : Globe;
  nodes.push({
    icon: assetIcon,
    label: assetType === 'subdomain' ? 'Subdomain' : assetType === 'domain' ? 'Domain' : 'Asset',
    value: value,
    colorClass: assetType === 'subdomain' 
      ? 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20'
      : 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  });
  
  // 4. Live URL (if available)
  if (liveUrl) {
    nodes.push({
      icon: ExternalLink,
      label: 'Live URL',
      value: liveUrl,
      colorClass: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
      detail: 'Verified accessible'
    });
  }
  
  return (
    <div className="space-y-4">
      {/* Discovery Path Visualization */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center gap-2 mb-4">
          <Radar className="h-4 w-4 text-primary" />
          <h4 className="font-medium">Discovery Path</h4>
          {associationConfidence && (
            <Badge variant="outline" className="ml-auto">
              {associationConfidence}% confidence
            </Badge>
          )}
        </div>
        
        <div className="space-y-0">
          {nodes.map((node, index) => (
            <DiscoveryNode
              key={index}
              icon={node.icon}
              label={node.label}
              value={node.value}
              colorClass={node.colorClass}
              detail={node.detail}
              isLast={index === nodes.length - 1}
            />
          ))}
        </div>
      </div>
      
      {/* Association Reason */}
      {associationReason && (
        <div className="bg-muted/50 rounded-lg p-4">
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-foreground">Why this asset?</span>
            <br />
            {associationReason}
          </p>
        </div>
      )}
      
      {/* Detailed Chain (if available) */}
      {discoveryChain && discoveryChain.length > 0 && (
        <details className="group">
          <summary className="text-sm text-muted-foreground cursor-pointer hover:text-foreground flex items-center gap-1">
            <ChevronRight className="h-4 w-4 group-open:rotate-90 transition-transform" />
            View detailed discovery chain ({discoveryChain.length} steps)
          </summary>
          <div className="mt-2 pl-5 space-y-2">
            {discoveryChain.map((step, index) => (
              <div key={index} className="text-sm bg-muted/30 rounded p-2 font-mono">
                <span className="text-muted-foreground">Step {step.step}:</span>{' '}
                <span className="text-primary">{step.source}</span>
                {step.match_type && (
                  <span className="text-muted-foreground"> ({step.match_type})</span>
                )}
                {step.match_value && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ matched: </span>
                    <span className="text-yellow-500">{step.match_value}</span>
                  </>
                )}
                {step.query_domain && (
                  <>
                    <br />
                    <span className="text-muted-foreground ml-4">→ from: </span>
                    <span>{step.query_domain}</span>
                  </>
                )}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

