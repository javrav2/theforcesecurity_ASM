import axios, { AxiosError, AxiosInstance } from 'axios';

// Determine API URL based on environment
// In browser: use same host with port 8000
// In Node.js (SSR): use environment variable or localhost
const getApiUrl = () => {
  if (typeof window !== 'undefined') {
    // Running in browser - use the same hostname but port 8000
    const hostname = window.location.hostname;
    return `http://${hostname}:8000`;
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
    const response = await this.client.get('/organizations');
    return response.data;
  }

  async getOrganization(id: number) {
    const response = await this.client.get(`/organizations/${id}`);
    return response.data;
  }

  async createOrganization(data: { name: string; description?: string; domains: string[] }) {
    const response = await this.client.post('/organizations', data);
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
  async getAssets(params?: { organization_id?: number; skip?: number; limit?: number; search?: string }) {
    const response = await this.client.get('/assets', { params });
    return response.data;
  }

  async getAsset(id: number) {
    const response = await this.client.get(`/assets/${id}`);
    return response.data;
  }

  async getAssetsByOrganization(orgId: number) {
    const response = await this.client.get(`/organizations/${orgId}/assets`);
    return response.data;
  }

  // Vulnerabilities
  async getVulnerabilities(params?: { 
    organization_id?: number; 
    asset_id?: number;
    severity?: string;
    skip?: number; 
    limit?: number;
  }) {
    const response = await this.client.get('/vulnerabilities', { params });
    return response.data;
  }

  async getVulnerabilitiesSummary(organizationId?: number) {
    const response = await this.client.get('/vulnerabilities/summary', {
      params: organizationId ? { organization_id: organizationId } : {},
    });
    return response.data;
  }

  // Scans
  async getScans(params?: { organization_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/scans', { params });
    return response.data;
  }

  async getScan(id: number) {
    const response = await this.client.get(`/scans/${id}`);
    return response.data;
  }

  async createScan(data: { 
    organization_id: number; 
    scan_type: string;
    targets?: string[];
    profile_id?: number;
  }) {
    const response = await this.client.post('/scans', data);
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

  // Screenshots
  async getScreenshots(params?: { organization_id?: number; asset_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/screenshots', { params });
    return response.data;
  }

  async captureScreenshot(assetId: number) {
    const response = await this.client.post(`/screenshots/capture/${assetId}`);
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
  }) {
    const response = await this.client.post('/external-discovery/run', data);
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
    api_key: string;
    api_user?: string;
    api_secret?: string;
  }) {
    const response = await this.client.post(`/external-discovery/configs/${organizationId}`, data);
    return response.data;
  }

  // Ports
  async getPorts(params?: { organization_id?: number; asset_id?: number; skip?: number; limit?: number }) {
    const response = await this.client.get('/ports', { params });
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

  // Generic methods for direct API calls
  async get(url: string, params?: any) {
    return this.client.get(url, { params });
  }

  async post(url: string, data?: any) {
    return this.client.post(url, data);
  }

  // Health check
  async healthCheck() {
    const response = await axios.get(`${API_URL}/health`);
    return response.data;
  }
}

export const api = new ApiClient();
export default api;

