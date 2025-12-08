/**
 * ASM Types - Core data types for Attack Surface Management
 */

export interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

export interface Asset {
  id: number;
  value: string;
  hostname?: string;
  ip_address?: string;
  type: AssetType;
  asset_type?: string;
  status: AssetStatus;
  organization_id: number;
  organization_name?: string;
  http_status?: number;
  technologies?: string[];
  tags?: string[];
  labels?: string[];
  findingsCount: number;
  screenshotUrl?: string;
  geoLocation?: GeoLocation;
  lastSeen: Date;
  created_at: string;
  updated_at?: string;
}

export type AssetType = 
  | 'domain'
  | 'subdomain'
  | 'ip'
  | 'cidr'
  | 'port'
  | 'service'
  | 'certificate'
  | 'asn'
  | 'url';

export type AssetStatus = 
  | 'active'
  | 'inactive'
  | 'completed'
  | 'running'
  | 'pending'
  | 'failed'
  | 'unknown';

export interface Vulnerability {
  id: number;
  title: string;
  description?: string;
  severity: SeverityLevel;
  cvss_score?: number;
  cve_id?: string;
  asset_id: number;
  asset_value?: string;
  status: VulnStatus;
  template_id?: string;
  matched_at?: string;
  reference?: string[];
  tags?: string[];
  created_at: string;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type VulnStatus = 'open' | 'confirmed' | 'resolved' | 'false_positive' | 'accepted';

export interface Organization {
  id: number;
  name: string;
  description?: string;
  domains?: string[];
  asset_count?: number;
  vulnerability_count?: number;
  created_at: string;
}

export interface Scan {
  id: number;
  name?: string;
  scan_type: string;
  status: ScanStatus;
  organization_id: number;
  targets?: string[];
  progress?: number;
  findings_count?: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface Screenshot {
  id: number;
  asset_id: number;
  url: string;
  image_path: string;
  image_url?: string;
  http_status?: number;
  page_title?: string;
  captured_at: string;
}

export interface PortInfo {
  id: number;
  asset_id: number;
  port: number;
  protocol: string;
  service?: string;
  banner?: string;
  state: string;
  created_at: string;
}

export interface Column {
  key: string;
  label: string;
  visible: boolean;
  sortable?: boolean;
}

export interface FilterOption {
  key: string;
  label: string;
  options: { label: string; value: string }[];
}



