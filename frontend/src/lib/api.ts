import axios, { AxiosError, AxiosInstance } from 'axios';

/**
 * Extract a user-friendly error message from an API error response.
 * Handles FastAPI's validation error format (detail as array of objects)
 * as well as simple string detail messages.
 */
export function getApiErrorMessage(error: any, fallback: string = 'An error occurred'): string {
  const detail = error?.response?.data?.detail;
  
  if (typeof detail === 'string') {
    return detail;
  }
  
  if (Array.isArray(detail) && detail.length > 0) {
    // FastAPI validation error format: [{type, loc, msg, input, url}, ...]
    return detail.map((e: any) => {
      if (typeof e === 'string') return e;
      return e.msg || e.message || JSON.stringify(e);
    }).join(', ');
  }
  
  if (error?.response?.data?.message) {
    return error.response.data.message;
  }
  
  if (error?.message) {
    return error.message;
  }
  
  return fallback;
}

// Determine API URL based on environment
// In browser: use same host with port 8000 (matching the page protocol)
// In Node.js (SSR): use environment variable or localhost
const getApiUrl = () => {
  if (typeof window !== 'undefined') {
    // Running in browser - use the same hostname and protocol but port 8000
    const { hostname, protocol } = window.location;
    return `${protocol}//${hostname}:8000`;
  }
  // Running on server (SSR) - use env var or default
  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
};

const API_URL = getApiUrl();

class ApiClient {
  private client: AxiosInstance;
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      // FastAPI is mounted at /api/v1 (see backend/app/core/config.py API_PREFIX)
      baseURL: `${API_URL}/api/v1`,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.client.interceptors.request.use((config) => {
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      return config;
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          this.token = null;
          if (typeof window !== 'undefined') {
            localStorage.removeItem('token');
            window.location.href = '/login';
          }
        }
        return Promise.reject(error);
      }
    );

    // Load token from localStorage
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('token');
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem('token', token);
      } else {
        localStorage.removeItem('token');
      }
    }
  }

  getToken() {
    return this.token;
  }

  // Auth
  async login(email: string, password: string) {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);
    
    const response = await this.client.post('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    this.setToken(response.data.access_token);
    return response.data;
  }

  async logout() {
    try {
      await this.client.post('/auth/logout');
    } finally {
      this.setToken(null);
    }
  }

  async getCurrentUser() {
    const response = await this.client.get('/auth/me');
    return response.data;
  }

  // Organizations
  async getOrganizations() {
    const response = await this.client.get('/organizations/');
    return response.data;
  }

  async getOrganization(id: number) {
    const response = await this.client.get(`/organizations/${id}`);
    return response.data;
  }

  async createOrganization(data: { name: string; description?: string; domains: string[] }) {
    const response = await this.client.post('/organizations/', data);
    return response.data;
  }

  async updateOrganization(id: number, data: { name?: string; description?: string; domains?: string[] }) {
    const response = await this.client.put(`/organizations/${id}`, data);
    return response.data;
  }

  async deleteOrganization(id: number) {
    const response = await this.client.delete(`/organizations/${id}`);
    return response.data;
  }

  // Assets
  async getAssets(params?: { 
    organization_id?: number; 
    skip?: number; 
    limit?: number; 
    search?: string;
    asset_type?: string;
    status?: string;
    include_cidr?: boolean;
    has_geo?: boolean;
  }) {
    const response = await this.client.get('/assets/', { params });
    return response.data;
  }

  async getAsset(id: number) {
    const response = await this.client.get(`/assets/${id}`);
    return response.data;
  }

  async updateAsset(id: number, data: { 
    in_scope?: boolean; 
    is_monitored?: boolean;
    criticality?: string;
    tags?: string[];
    description?: string;
  }) {
    const response = await this.client.put(`/assets/${id}`, data);
    return response.data;
  }

  async getAssetsByOrganization(orgId: number) {
    const response = await this.client.get(`/organizations/${orgId}/assets`);
    return response.data;
  }

  // Findings (Vulnerabilities)
  async getFindings(params?: { 
    organization_id?: number; 
    asset_id?: number;
    severity?: string;
    skip?: number; 
    limit?: number;
  }) {
    const response = await this.client.get('/vulnerabilities/', { params });
    return response.data;
  }

  async getFindingsSummary(organizationId?: number) {
    const response = await this.client.get('/vulnerabilities/stats/summary', {
      params: organizationId ? { organization_id: organizationId } : {},
    });
    return response.data;
  }

  // Legacy aliases for backwards compatibility
  async getVulnerabilities(params?: { 
    organization_id?: number; 
    asset_id?: number;
    severity?: string;
    skip?: number; 
    limit?: number;
  }) {
    return this.getFindings(params);
  }

  async getVulnerabilitiesSummary(organizationId?: number) {
    return this.getFindingsSummary(organizationId);
  }

  async getVulnerabilitiesForAsset(assetId: number, params?: { skip?: number; limit?: number }) {
    const response = await this.client.get('/vulnerabilities/', {
      params: { asset_id: assetId, ...params }
    });
    return response.data;
  }

  async getRemediationEfficiency(days: number = 30) {
    const response = await this.client.get('/vulnerabilities/stats/remediation-efficiency', {
      params: { days }
    });
    return response.data;
  }

  async getVulnerabilityExposure() {
    const response = await this.client.get('/vulnerabilities/stats/exposure');
    return response.data;
  }

  async getVulnerability(vulnId: number) {
    const response = await this.client.get(`/vulnerabilities/${vulnId}`);
    return response.data;
  }

  async updateVulnerability(vulnId: number, data: {
    status?: string;
    assigned_to?: string;
    remediation?: string;
    remediation_deadline?: string;
  }) {
    const response = await this.client.put(`/vulnerabilities/${vulnId}`, data);
    return response.data;
  }

  // Scans
  async getScans(params?: { organization_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/scans/', { params });
    return response.data;
  }

  async getScanQueueStatus() {
    const response = await this.client.get('/scans/queue/status');
    return response.data;
  }

  async getScan(id: number) {
    const response = await this.client.get(`/scans/${id}`);
    return response.data;
  }

  async createScan(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    targets?: string[];
    label_ids?: number[];
    match_all_labels?: boolean;
    profile_id?: number;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post('/scans/', data);
    return response.data;
  }

  async createScanByLabel(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    label_ids: number[];
    match_all_labels?: boolean;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post('/scans/by-label', data);
    return response.data;
  }

  async cancelScan(id: number) {
    const response = await this.client.post(`/scans/${id}/cancel`);
    return response.data;
  }

  async rescan(id: number) {
    const response = await this.client.post(`/scans/${id}/rescan`);
    return response.data;
  }

  async previewScanByLabels(labelIds: number[], organizationId: number, matchAll: boolean = false) {
    const response = await this.client.get('/scans/labels/preview', {
      params: { label_ids: labelIds, organization_id: organizationId, match_all: matchAll }
    });
    return response.data;
  }

  // Scan Schedules (Continuous Monitoring)
  async getScanSchedules(params?: { organization_id?: number; scan_type?: string; is_enabled?: boolean }) {
    const response = await this.client.get('/scan-schedules/', { params });
    return response.data;
  }

  async getScanSchedulesSummary(organizationId?: number) {
    const response = await this.client.get('/scan-schedules/summary', {
      params: organizationId ? { organization_id: organizationId } : {}
    });
    return response.data;
  }

  async getScanScheduleTypes() {
    const response = await this.client.get('/scan-schedules/scan-types');
    return response.data;
  }

  async createScanSchedule(data: {
    name: string;
    organization_id: number;
    scan_type: string;
    frequency: string;
    targets?: string[];
    label_ids?: number[];
    match_all_labels?: boolean;
    config?: Record<string, any>;
    run_at_hour?: number;
    run_on_day?: number;
    is_enabled?: boolean;
    notify_on_findings?: boolean;
    notification_emails?: string[];
  }) {
    const response = await this.client.post('/scan-schedules/', data);
    return response.data;
  }

  async updateScanSchedule(scheduleId: number, data: Record<string, any>) {
    const response = await this.client.put(`/scan-schedules/${scheduleId}`, data);
    return response.data;
  }

  async deleteScanSchedule(scheduleId: number) {
    const response = await this.client.delete(`/scan-schedules/${scheduleId}`);
    return response.data;
  }

  async toggleScanSchedule(scheduleId: number) {
    const response = await this.client.post(`/scan-schedules/${scheduleId}/toggle`);
    return response.data;
  }

  async triggerScanSchedule(scheduleId: number, overrides?: { override_targets?: string[]; override_config?: Record<string, any> }) {
    const response = await this.client.post(`/scan-schedules/${scheduleId}/trigger`, overrides || {});
    return response.data;
  }

  async getScanScheduleHistory(scheduleId: number, limit: number = 20) {
    const response = await this.client.get(`/scan-schedules/${scheduleId}/history`, {
      params: { limit }
    });
    return response.data;
  }

  // Tools Status
  async getToolsStatus() {
    const response = await this.client.get('/tools/status');
    return response.data;
  }

  async getToolStatus(toolId: string) {
    const response = await this.client.get(`/tools/${toolId}`);
    return response.data;
  }

  async testTool(toolId: string, target: string = 'example.com') {
    const response = await this.client.post(`/tools/${toolId}/test`, null, {
      params: { target }
    });
    return response.data;
  }

  // Discovery
  async runDiscovery(organizationId: number, domain: string) {
    const response = await this.client.post('/discovery/run', {
      organization_id: organizationId,
      domain,
    });
    return response.data;
  }

  // Geo-location enrichment
  async enrichAssetsGeolocation(options?: {
    organizationId?: number;
    limit?: number;
    provider?: 'ip-api' | 'ipinfo' | 'whoisxml';
    ipinfoToken?: string;
    whoisxmlApiKey?: string;
    force?: boolean;
  }) {
    const params: any = { limit: options?.limit || 50 };
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.provider) params.provider = options.provider;
    if (options?.ipinfoToken) params.ipinfo_token = options.ipinfoToken;
    if (options?.whoisxmlApiKey) params.whoisxml_api_key = options.whoisxmlApiKey;
    if (options?.force) params.force = true;
    const response = await this.client.post('/assets/enrich-geolocation', null, { params });
    return response.data;
  }

  async enrichAssetGeolocation(assetId: number, options?: {
    provider?: 'ip-api' | 'ipinfo' | 'whoisxml';
    ipinfoToken?: string;
    whoisxmlApiKey?: string;
  }) {
    const params: any = {};
    if (options?.provider) params.provider = options.provider;
    if (options?.ipinfoToken) params.ipinfo_token = options.ipinfoToken;
    if (options?.whoisxmlApiKey) params.whoisxml_api_key = options.whoisxmlApiKey;
    const response = await this.client.post(`/assets/${assetId}/enrich-geolocation`, null, { params });
    return response.data;
  }

  async getGeoStats(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/assets/geo-stats', { params });
    return response.data;
  }

  // Screenshots
  async getScreenshots(params?: { organization_id?: number; asset_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/screenshots/', { params });
    return response.data;
  }

  async getAssetScreenshots(assetId: number) {
    const response = await this.client.get(`/screenshots/asset/${assetId}`);
    return response.data;
  }

  getScreenshotImageUrl(screenshotId: number): string {
    const token = this.getToken();
    // Dynamically determine API URL at call time (not module load time)
    // This ensures we use the correct hostname and protocol when called from browser
    let apiUrl = 'http://localhost:8000';
    if (typeof window !== 'undefined') {
      const { hostname, protocol } = window.location;
      apiUrl = `${protocol}//${hostname}:8000`;
    }
    return `${apiUrl}/api/v1/screenshots/image/${screenshotId}?token=${token}`;
  }

  async captureScreenshot(assetId: number) {
    const response = await this.client.post(`/screenshots/capture/asset/${assetId}`);
    return response.data;
  }

  async getScreenshotSchedules() {
    const response = await this.client.get('/screenshots/schedules');
    return response.data;
  }

  // Nuclei
  async getNucleiFindings(params?: { organization_id?: number; severity?: string; skip?: number; limit?: number }) {
    const response = await this.client.get('/nuclei/findings', { params });
    return response.data;
  }

  async runNucleiScan(data: { organization_id: number; targets: string[]; severity?: string[] }) {
    const response = await this.client.post('/nuclei/scan', data);
    return response.data;
  }

  // External Discovery
  async getExternalDiscoveryServices(organizationId: number) {
    const response = await this.client.get('/external-discovery/services', {
      params: { organization_id: organizationId }
    });
    return response.data;
  }

  async runExternalDiscovery(data: { 
    organization_id: number; 
    domain: string; 
    include_paid_sources?: boolean;
    include_free_sources?: boolean;
    organization_names?: string[];
    registration_emails?: string[];
    create_assets?: boolean;
    skip_existing?: boolean;
    enumerate_discovered_domains?: boolean;
    max_domains_to_enumerate?: number;
    // Common Crawl comprehensive search options
    commoncrawl_org_name?: string;
    commoncrawl_keywords?: string[];
    // SNI IP Ranges - Cloud Asset Discovery
    include_sni_discovery?: boolean;
    sni_keywords?: string[];
    // Technology fingerprinting options
    run_technology_scan?: boolean;
    max_technology_scan?: number;
    // Screenshot capture options
    run_screenshots?: boolean;
    max_screenshots?: number;
    screenshot_timeout?: number;
  }) {
    // Discovery can take a long time with multiple sources (Common Crawl, SNI, etc.)
    // Use a 5-minute timeout for this operation
    const response = await this.client.post('/external-discovery/run', data, {
      timeout: 300000  // 5 minutes
    });
    return response.data;
  }

  async runSingleSourceDiscovery(data: {
    organization_id: number;
    domain: string;
    source: string;
    create_assets?: boolean;
  }) {
    const response = await this.client.post('/external-discovery/run/source', data);
    return response.data;
  }

  async getApiConfigs(organizationId: number) {
    const response = await this.client.get(`/external-discovery/configs/${organizationId}`);
    return response.data;
  }

  async saveApiConfig(organizationId: number, data: {
    service_name: string;
    api_key?: string;
    api_user?: string;
    api_secret?: string;
    config?: Record<string, any>;
  }) {
    const response = await this.client.post(`/external-discovery/configs/${organizationId}`, data);
    return response.data;
  }

  async enrichDomainsDns(options?: {
    organizationId?: number;
    domainIds?: number[];
    limit?: number;
  }) {
    const params: any = {};
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.limit) params.limit = options.limit;
    
    const body: any = {};
    if (options?.domainIds) body.domain_ids = options.domainIds;
    
    const response = await this.client.post('/external-discovery/enrich-dns', body, { params });
    return response.data;
  }

  async getAssetDnsRecords(assetId: number, refresh: boolean = false) {
    const response = await this.client.get(`/external-discovery/dns/${assetId}`, {
      params: { refresh }
    });
    return response.data;
  }

  async enrichDomainsWhois(options?: {
    organizationId?: number;
    domainIds?: number[];
    expectedRegistrant?: string;
    limit?: number;
  }) {
    const params: any = {};
    if (options?.organizationId) params.organization_id = options.organizationId;
    if (options?.expectedRegistrant) params.expected_registrant = options.expectedRegistrant;
    if (options?.limit) params.limit = options.limit;
    
    const body: any = {};
    if (options?.domainIds) body.domain_ids = options.domainIds;
    
    const response = await this.client.post('/external-discovery/enrich-whois', body, { params });
    return response.data;
  }

  async getAssetWhois(assetId: number, refresh: boolean = false) {
    const response = await this.client.get(`/external-discovery/whois/${assetId}`, {
      params: { refresh }
    });
    return response.data;
  }

  async deleteAsset(assetId: number) {
    await this.client.delete(`/assets/${assetId}`);
  }

  async bulkDeleteAssets(assetIds: number[]) {
    const results = { deleted: 0, failed: 0, errors: [] as string[] };
    for (const id of assetIds) {
      try {
        await this.client.delete(`/assets/${id}`);
        results.deleted++;
      } catch (error: any) {
        results.failed++;
        results.errors.push(`Asset ${id}: ${error?.response?.data?.detail || error.message}`);
      }
    }
    return results;
  }

  // VirusTotal lookups
  async lookupVirusTotal(assetId: number) {
    const response = await this.client.post(`/assets/${assetId}/virustotal-lookup`);
    return response.data;
  }

  async bulkLookupVirusTotal(assetIds: number[]) {
    const response = await this.client.post('/assets/bulk-virustotal-lookup', assetIds);
    return response.data;
  }

  // Acquisitions / M&A
  async getAcquisitions(params?: { 
    organization_id?: number; 
    status?: string;
    skip?: number; 
    limit?: number 
  }) {
    const response = await this.client.get('/acquisitions/', { params });
    return response.data;
  }

  async getAcquisitionsSummary(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/acquisitions/summary', { params });
    return response.data;
  }

  async getAcquisition(acquisitionId: number) {
    const response = await this.client.get(`/acquisitions/${acquisitionId}`);
    return response.data;
  }

  async createAcquisition(data: {
    organization_id: number;
    target_name: string;
    target_domain?: string;
    target_domains?: string[];
    target_description?: string;
    target_industry?: string;
    target_country?: string;
    acquisition_type?: string;
    status?: string;
    announced_date?: string;
    closed_date?: string;
    deal_value?: number;
    website_url?: string;
    linkedin_url?: string;
  }) {
    const response = await this.client.post('/acquisitions/', data);
    return response.data;
  }

  async updateAcquisition(acquisitionId: number, data: Record<string, any>) {
    const response = await this.client.put(`/acquisitions/${acquisitionId}`, data);
    return response.data;
  }

  async deleteAcquisition(acquisitionId: number) {
    const response = await this.client.delete(`/acquisitions/${acquisitionId}`);
    return response.data;
  }

  async importAcquisitionsFromTracxn(organizationName: string, organizationId: number = 1, limit: number = 20) {
    const response = await this.client.post('/acquisitions/import-from-tracxn', null, {
      params: { organization_id: organizationId, organization_name: organizationName, limit }
    });
    return response.data;
  }

  async discoverDomainsForAcquisition(acquisitionId: number) {
    const response = await this.client.post(`/acquisitions/${acquisitionId}/discover-domains`);
    return response.data;
  }

  async getAcquisitionAssets(acquisitionId: number) {
    const response = await this.client.get(`/acquisitions/${acquisitionId}/assets`);
    return response.data;
  }

  async addDomainToAcquisition(acquisitionId: number, domain: string) {
    const response = await this.client.post(`/acquisitions/${acquisitionId}/add-domain`, null, {
      params: { domain }
    });
    return response.data;
  }

  // Ports
  async getPorts(params?: { organization_id?: number; asset_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/ports/', { params });
    return response.data;
  }

  async runPortScan(data: { organization_id: number; targets: string[]; ports?: string }) {
    const response = await this.client.post('/ports/scan', data);
    return response.data;
  }

  // Users (Admin)
  async getUsers() {
    const response = await this.client.get('/users');
    return response.data;
  }

  async createUser(data: { email: string; password: string; full_name: string; role?: string }) {
    const response = await this.client.post('/users', data);
    return response.data;
  }

  // Wayback URLs
  async getWaybackStatus() {
    const response = await this.client.get('/waybackurls/status');
    return response.data;
  }

  async fetchWaybackUrls(data: {
    domain: string;
    no_subs?: boolean;
    timeout?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch', data);
    return response.data;
  }

  async fetchWaybackUrlsBatch(data: {
    domains: string[];
    no_subs?: boolean;
    timeout?: number;
    max_concurrent?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch/batch', data);
    return response.data;
  }

  async fetchWaybackUrlsForOrganization(data: {
    organization_id: number;
    include_subdomains?: boolean;
    timeout_per_domain?: number;
    max_concurrent?: number;
  }) {
    const response = await this.client.post('/waybackurls/fetch/organization', data);
    return response.data;
  }

  // Netblocks / CIDR ranges
  async getNetblocks(params?: { 
    organization_id?: number; 
    is_owned?: boolean; 
    in_scope?: boolean;
    ip_version?: string;
    skip?: number; 
    limit?: number 
  }) {
    const response = await this.client.get('/netblocks/', { params });
    return response.data;
  }

  async getNetblockSummary(organizationId?: number) {
    const params: any = {};
    if (organizationId) params.organization_id = organizationId;
    const response = await this.client.get('/netblocks/summary', { params });
    return response.data;
  }

  async getNetblock(netblockId: number) {
    const response = await this.client.get(`/netblocks/${netblockId}`);
    return response.data;
  }

  async discoverNetblocks(data: {
    organization_id: number;
    search_terms: string[];
    include_variations?: boolean;
  }) {
    const response = await this.client.post('/netblocks/discover', data);
    return response.data;
  }

  async updateNetblock(netblockId: number, data: {
    is_owned?: boolean;
    in_scope?: boolean;
    description?: string;
    tags?: string[];
  }) {
    const response = await this.client.put(`/netblocks/${netblockId}`, data);
    return response.data;
  }

  async toggleNetblockScope(netblockId: number) {
    const response = await this.client.put(`/netblocks/${netblockId}/toggle-scope`);
    return response.data;
  }

  async toggleNetblockOwnership(netblockId: number) {
    const response = await this.client.put(`/netblocks/${netblockId}/toggle-ownership`);
    return response.data;
  }

  async bulkUpdateNetblockScope(netblockIds: number[], inScope: boolean) {
    const response = await this.client.post('/netblocks/bulk-scope', null, {
      params: { netblock_ids: netblockIds, in_scope: inScope }
    });
    return response.data;
  }

  // Label API methods
  async getLabels(params?: { organization_id?: number; search?: string }) {
    const response = await this.client.get('/labels/', { params });
    return response.data;
  }

  async getLabelColors() {
    const response = await this.client.get('/labels/colors');
    return response.data;
  }

  async getLabel(labelId: number) {
    const response = await this.client.get(`/labels/${labelId}`);
    return response.data;
  }

  async createLabel(data: { name: string; color?: string; description?: string; organization_id: number }) {
    const response = await this.client.post('/labels/', data);
    return response.data;
  }

  async quickCreateLabel(name: string, organizationId: number, color?: string) {
    const response = await this.client.post('/labels/quick-create', null, {
      params: { name, organization_id: organizationId, color }
    });
    return response.data;
  }

  async updateLabel(labelId: number, data: { name?: string; color?: string; description?: string }) {
    const response = await this.client.put(`/labels/${labelId}`, data);
    return response.data;
  }

  async deleteLabel(labelId: number) {
    const response = await this.client.delete(`/labels/${labelId}`);
    return response.data;
  }

  async assignAssetsToLabel(labelId: number, assetIds: number[]) {
    const response = await this.client.post(`/labels/${labelId}/assets`, assetIds);
    return response.data;
  }

  async removeAssetsFromLabel(labelId: number, assetIds: number[]) {
    const response = await this.client.delete(`/labels/${labelId}/assets`, {
      params: { asset_ids: assetIds }
    });
    return response.data;
  }

  async bulkAssignLabels(data: { asset_ids: number[]; add_labels: number[]; remove_labels: number[] }) {
    const response = await this.client.post('/labels/bulk-assign', data);
    return response.data;
  }

  async getLabelsForAsset(assetId: number) {
    const response = await this.client.get(`/labels/by-asset/${assetId}`);
    return response.data;
  }

  async searchAssetsByLabels(labelIds: number[], matchAll: boolean = false, organizationId?: number) {
    const response = await this.client.get('/labels/search-assets', {
      params: { label_ids: labelIds, match_all: matchAll, organization_id: organizationId }
    });
    return response.data;
  }

  // Generic methods for direct API calls
  async get(url: string, params?: any) {
    return this.client.get(url, { params });
  }

  async post(url: string, data?: any) {
    return this.client.post(url, data);
  }

  // Generic request method for flexible API calls
  async request(url: string, options?: { 
    method?: string; 
    body?: string; 
    params?: any;
    headers?: Record<string, string>;
  }) {
    const method = options?.method?.toUpperCase() || 'GET';
    const config: any = {
      headers: options?.headers || {},
    };
    
    if (options?.params) {
      config.params = options.params;
    }

    let data: any = undefined;
    if (options?.body) {
      try {
        data = JSON.parse(options.body);
      } catch {
        data = options.body;
      }
    }

    switch (method) {
      case 'POST':
        const postRes = await this.client.post(url, data, config);
        return postRes.data;
      case 'PUT':
        const putRes = await this.client.put(url, data, config);
        return putRes.data;
      case 'DELETE':
        const delRes = await this.client.delete(url, config);
        return delRes.data;
      case 'PATCH':
        const patchRes = await this.client.patch(url, data, config);
        return patchRes.data;
      default:
        const getRes = await this.client.get(url, config);
        return getRes.data;
    }
  }

  // Health check
  async healthCheck() {
    const response = await axios.get(`${API_URL}/health`);
    return response.data;
  }
}

export const api = new ApiClient();
export default api;

