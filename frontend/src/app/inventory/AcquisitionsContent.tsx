'use client';

import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Building2,
  Search,
  RefreshCw,
  Plus,
  Globe,
  Loader2,
  ExternalLink,
  Download,
  ChevronRight,
  CheckCircle,
  Clock,
  AlertCircle,
  Briefcase,
  MapPin,
  Calendar,
  DollarSign,
  Users,
  Link as LinkIcon,
  Trash2,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Acquisition {
  id: number;
  organization_id: number;
  target_name: string;
  target_domain: string | null;
  target_domains: string[];
  target_description: string | null;
  target_industry: string | null;
  target_country: string | null;
  target_city: string | null;
  target_founded_year: number | null;
  target_employees: number | null;
  acquisition_type: string;
  status: string;
  announced_date: string | null;
  closed_date: string | null;
  deal_value: number | null;
  deal_currency: string;
  is_integrated: boolean;
  integration_notes: string | null;
  domains_discovered: number;
  domains_in_scope: number;
  tracxn_id: string | null;
  website_url: string | null;
  linkedin_url: string | null;
  source: string;
  created_at: string;
  updated_at: string;
}

interface Summary {
  total_acquisitions: number;
  completed: number;
  pending: number;
  integrated: number;
  total_domains_discovered: number;
  total_domains_in_scope: number;
}

export default function AcquisitionsContent() {
  const [acquisitions, setAcquisitions] = useState<Acquisition[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState(false);
  const [discovering, setDiscovering] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedAcquisition, setSelectedAcquisition] = useState<Acquisition | null>(null);
  const [formData, setFormData] = useState({
    target_name: '',
    target_domain: '',
    target_description: '',
    target_industry: '',
    target_country: '',
    announced_date: '',
    deal_value: '',
    website_url: '',
  });
  const [importOrgName, setImportOrgName] = useState('Rockwell Automation');
  const { toast } = useToast();

  const fetchData = async () => {
    try {
      setLoading(true);
      const [acqData, summaryData] = await Promise.all([
        api.getAcquisitions({ organization_id: 1, limit: 100 }),
        api.getAcquisitionsSummary(1),
      ]);
      
      setAcquisitions(acqData || []);
      setSummary(summaryData);
    } catch (error) {
      console.error('Error fetching acquisitions:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch acquisitions',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreate = async () => {
    if (!formData.target_name) {
      toast({
        title: 'Error',
        description: 'Target company name is required',
        variant: 'destructive',
      });
      return;
    }

    try {
      await api.createAcquisition({
        organization_id: 1,
        target_name: formData.target_name,
        target_domain: formData.target_domain || undefined,
        target_domains: formData.target_domain ? [formData.target_domain] : [],
        target_description: formData.target_description || undefined,
        target_industry: formData.target_industry || undefined,
        target_country: formData.target_country || undefined,
        announced_date: formData.announced_date || undefined,
        deal_value: formData.deal_value ? parseFloat(formData.deal_value) : undefined,
        website_url: formData.website_url || undefined,
      });

      toast({
        title: 'Success',
        description: `Added acquisition: ${formData.target_name}`,
      });

      setCreateDialogOpen(false);
      setFormData({
        target_name: '',
        target_domain: '',
        target_description: '',
        target_industry: '',
        target_country: '',
        announced_date: '',
        deal_value: '',
        website_url: '',
      });
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create acquisition',
        variant: 'destructive',
      });
    }
  };

  const handleImportFromTracxn = async () => {
    if (!importOrgName) {
      toast({
        title: 'Error',
        description: 'Organization name is required',
        variant: 'destructive',
      });
      return;
    }

    try {
      setImporting(true);
      const result = await api.importAcquisitionsFromTracxn(importOrgName, 1, 50);

      toast({
        title: 'Import Complete',
        description: `Imported ${result.imported} acquisitions, ${result.skipped} skipped`,
      });

      setImportDialogOpen(false);
      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to import from Tracxn',
        variant: 'destructive',
      });
    } finally {
      setImporting(false);
    }
  };

  const handleDiscoverDomains = async (acquisition: Acquisition) => {
    if (!acquisition.target_domain) {
      toast({
        title: 'Error',
        description: 'Acquisition has no target domain. Add a domain first.',
        variant: 'destructive',
      });
      return;
    }

    try {
      setDiscovering(acquisition.id);
      const result = await api.discoverDomainsForAcquisition(acquisition.id);

      toast({
        title: 'Domain Discovery Complete',
        description: `Found ${result.domains_found} domains, created ${result.assets_created} assets`,
      });

      fetchData();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to discover domains',
        variant: 'destructive',
      });
    } finally {
      setDiscovering(null);
    }
  };

  const handleDelete = async (acquisition: Acquisition) => {
    if (!confirm(`Delete acquisition "${acquisition.target_name}"?`)) return;

    try {
      await api.deleteAcquisition(acquisition.id);
      toast({
        title: 'Deleted',
        description: `Removed ${acquisition.target_name}`,
      });
      fetchData();
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to delete acquisition',
        variant: 'destructive',
      });
    }
  };

  const filteredAcquisitions = acquisitions.filter((acq: Acquisition) =>
    acq.target_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (acq.target_domain || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (acq.target_industry || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge className="bg-green-500/20 text-green-600"><CheckCircle className="h-3 w-3 mr-1" />Completed</Badge>;
      case 'pending':
        return <Badge className="bg-yellow-500/20 text-yellow-600"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case 'announced':
        return <Badge className="bg-blue-500/20 text-blue-600"><AlertCircle className="h-3 w-3 mr-1" />Announced</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <>
      <div className="p-6 space-y-6">
        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold">{summary.total_acquisitions}</div>
                <div className="text-xs text-muted-foreground">Total M&A</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-green-600">{summary.completed}</div>
                <div className="text-xs text-muted-foreground">Completed</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-yellow-600">{summary.pending}</div>
                <div className="text-xs text-muted-foreground">Pending</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-blue-600">{summary.integrated}</div>
                <div className="text-xs text-muted-foreground">Integrated</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-purple-600">{summary.total_domains_discovered}</div>
                <div className="text-xs text-muted-foreground">Domains Found</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-cyan-600">{summary.total_domains_in_scope}</div>
                <div className="text-xs text-muted-foreground">In Scope</div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Actions and Filters */}
        <Card>
          <CardHeader>
            <div className="flex flex-col md:flex-row gap-4 justify-between">
              <div className="flex gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search acquisitions..."
                    value={searchTerm}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchTerm(e.target.value)}
                    className="pl-9 w-64"
                  />
                </div>
              </div>
              
              <div className="flex gap-2">
                <Button variant="outline" onClick={() => setImportDialogOpen(true)}>
                  <Download className="h-4 w-4 mr-2" />
                  Import from Tracxn
                </Button>
                <Button onClick={() => setCreateDialogOpen(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Acquisition
                </Button>
                <Button variant="outline" onClick={fetchData} disabled={loading}>
                  <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
              </div>
            </div>
          </CardHeader>

          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : filteredAcquisitions.length === 0 ? (
              <div className="text-center py-12">
                <Building2 className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No acquisitions found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Add an acquisition manually or import from Tracxn
                </p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Company</TableHead>
                      <TableHead>Domain</TableHead>
                      <TableHead>Industry</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead>Domains</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAcquisitions.map((acq: Acquisition) => (
                      <TableRow key={acq.id}>
                        <TableCell>
                          <div className="flex flex-col">
                            <span className="font-medium">{acq.target_name}</span>
                            {acq.target_country && (
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <MapPin className="h-3 w-3" />
                                {acq.target_city ? `${acq.target_city}, ` : ''}{acq.target_country}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          {acq.target_domain ? (
                            <a
                              href={`https://${acq.target_domain}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm text-primary hover:underline flex items-center gap-1"
                            >
                              {acq.target_domain}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {acq.target_industry ? (
                            <Badge variant="outline">{acq.target_industry}</Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {getStatusBadge(acq.status)}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {acq.announced_date ? formatDate(acq.announced_date) : '—'}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Badge variant="secondary">{acq.domains_discovered} found</Badge>
                            {acq.domains_in_scope > 0 && (
                              <Badge className="bg-green-500/20 text-green-600">{acq.domains_in_scope} in scope</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleDiscoverDomains(acq)}
                              disabled={discovering === acq.id || !acq.target_domain}
                              title={!acq.target_domain ? 'Add a domain first' : 'Discover related domains via Whoxy'}
                            >
                              {discovering === acq.id ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Globe className="h-4 w-4" />
                              )}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setSelectedAcquisition(acq)}
                            >
                              <ChevronRight className="h-4 w-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleDelete(acq)}
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Acquisition</DialogTitle>
            <DialogDescription>
              Manually add an M&A event to track domains from acquired companies.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div>
              <Label htmlFor="target_name">Target Company Name *</Label>
              <Input
                id="target_name"
                value={formData.target_name}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, target_name: e.target.value }))}
                placeholder="e.g., OTTO Motors"
              />
            </div>
            <div>
              <Label htmlFor="target_domain">Primary Domain</Label>
              <Input
                id="target_domain"
                value={formData.target_domain}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, target_domain: e.target.value }))}
                placeholder="e.g., ottomotors.com"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="target_industry">Industry</Label>
                <Input
                  id="target_industry"
                  value={formData.target_industry}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, target_industry: e.target.value }))}
                  placeholder="e.g., Robotics"
                />
              </div>
              <div>
                <Label htmlFor="target_country">Country</Label>
                <Input
                  id="target_country"
                  value={formData.target_country}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, target_country: e.target.value }))}
                  placeholder="e.g., Canada"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="announced_date">Announced Date</Label>
                <Input
                  id="announced_date"
                  type="date"
                  value={formData.announced_date}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, announced_date: e.target.value }))}
                />
              </div>
              <div>
                <Label htmlFor="deal_value">Deal Value (M USD)</Label>
                <Input
                  id="deal_value"
                  type="number"
                  value={formData.deal_value}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, deal_value: e.target.value }))}
                  placeholder="e.g., 150"
                />
              </div>
            </div>
            <div>
              <Label htmlFor="website_url">Website URL</Label>
              <Input
                id="website_url"
                value={formData.website_url}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, website_url: e.target.value }))}
                placeholder="https://www.ottomotors.com"
              />
            </div>
            <div>
              <Label htmlFor="target_description">Description</Label>
              <Input
                id="target_description"
                value={formData.target_description}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData(prev => ({ ...prev, target_description: e.target.value }))}
                placeholder="Brief description of the acquired company"
              />
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate}>
              Add Acquisition
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Import from Tracxn Dialog */}
      <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Import from Tracxn</DialogTitle>
            <DialogDescription>
              Import acquisition history from Tracxn API. Requires a Tracxn API key configured in Settings.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4">
            <Label htmlFor="org_name">Acquirer Organization Name</Label>
            <Input
              id="org_name"
              value={importOrgName}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setImportOrgName(e.target.value)}
              placeholder="e.g., Rockwell Automation"
            />
            <p className="text-xs text-muted-foreground mt-2">
              Enter the name of the acquiring company to search for their acquisition history.
            </p>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleImportFromTracxn} disabled={importing}>
              {importing ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Importing...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Import
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Acquisition Detail Dialog */}
      <Dialog open={!!selectedAcquisition} onOpenChange={() => setSelectedAcquisition(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Building2 className="h-5 w-5" />
              {selectedAcquisition?.target_name}
            </DialogTitle>
            <DialogDescription>
              Acquisition details and associated domains
            </DialogDescription>
          </DialogHeader>
          
          {selectedAcquisition && (
            <div className="space-y-6 py-4">
              {/* Quick Stats */}
              <div className="grid grid-cols-4 gap-4">
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-lg font-bold">{selectedAcquisition.domains_discovered}</div>
                  <div className="text-xs text-muted-foreground">Domains Found</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-lg font-bold text-green-600">{selectedAcquisition.domains_in_scope}</div>
                  <div className="text-xs text-muted-foreground">In Scope</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-lg font-bold">{selectedAcquisition.target_employees || '—'}</div>
                  <div className="text-xs text-muted-foreground">Employees</div>
                </div>
                <div className="text-center p-3 bg-muted/50 rounded-lg">
                  <div className="text-lg font-bold">
                    {selectedAcquisition.deal_value ? `$${selectedAcquisition.deal_value}M` : '—'}
                  </div>
                  <div className="text-xs text-muted-foreground">Deal Value</div>
                </div>
              </div>

              {/* Details */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Industry:</span>
                  <span className="ml-2 font-medium">{selectedAcquisition.target_industry || '—'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Country:</span>
                  <span className="ml-2 font-medium">{selectedAcquisition.target_country || '—'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Founded:</span>
                  <span className="ml-2 font-medium">{selectedAcquisition.target_founded_year || '—'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>
                  <span className="ml-2">{getStatusBadge(selectedAcquisition.status)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Announced:</span>
                  <span className="ml-2 font-medium">
                    {selectedAcquisition.announced_date ? formatDate(selectedAcquisition.announced_date) : '—'}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Closed:</span>
                  <span className="ml-2 font-medium">
                    {selectedAcquisition.closed_date ? formatDate(selectedAcquisition.closed_date) : '—'}
                  </span>
                </div>
              </div>

              {/* Domains */}
              {selectedAcquisition.target_domains && selectedAcquisition.target_domains.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2">Associated Domains ({selectedAcquisition.target_domains.length})</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedAcquisition.target_domains.map((domain: string, idx: number) => (
                      <Badge key={idx} variant="outline" className="font-mono">
                        <Globe className="h-3 w-3 mr-1" />
                        {domain}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Links */}
              <div className="flex gap-4">
                {selectedAcquisition.website_url && (
                  <a
                    href={selectedAcquisition.website_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline flex items-center gap-1"
                  >
                    <Globe className="h-4 w-4" />
                    Website
                  </a>
                )}
                {selectedAcquisition.linkedin_url && (
                  <a
                    href={selectedAcquisition.linkedin_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline flex items-center gap-1"
                  >
                    <LinkIcon className="h-4 w-4" />
                    LinkedIn
                  </a>
                )}
              </div>
            </div>
          )}
          
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => selectedAcquisition && handleDiscoverDomains(selectedAcquisition)}
              disabled={!selectedAcquisition?.target_domain || discovering === selectedAcquisition?.id}
            >
              {discovering === selectedAcquisition?.id ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Globe className="h-4 w-4 mr-2" />
              )}
              Discover Domains
            </Button>
            <Button onClick={() => setSelectedAcquisition(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
