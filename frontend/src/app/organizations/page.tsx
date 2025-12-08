'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Plus, Building2, Globe, Trash2, Edit, MoreHorizontal, Loader2 } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import Link from 'next/link';

interface Organization {
  id: number;
  name: string;
  description?: string;
  domains: string[];
  created_at: string;
  asset_count?: number;
}

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [formData, setFormData] = useState({ name: '', description: '', domains: '' });
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  const fetchOrganizations = async () => {
    try {
      const data = await api.getOrganizations();
      setOrganizations(data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch organizations',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const handleCreate = async () => {
    if (!formData.name) return;

    setSubmitting(true);
    try {
      const domains = formData.domains
        .split(',')
        .map((d) => d.trim())
        .filter((d) => d);

      await api.createOrganization({
        name: formData.name,
        description: formData.description || undefined,
        domains,
      });

      toast({
        title: 'Success',
        description: 'Organization created successfully',
      });

      setCreateDialogOpen(false);
      setFormData({ name: '', description: '', domains: '' });
      fetchOrganizations();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create organization',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this organization?')) return;

    try {
      await api.deleteOrganization(id);
      toast({
        title: 'Success',
        description: 'Organization deleted successfully',
      });
      fetchOrganizations();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to delete organization',
        variant: 'destructive',
      });
    }
  };

  return (
    <MainLayout>
      <Header title="Organizations" subtitle="Manage your organizations and their domains" />

      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Building2 className="h-5 w-5 text-muted-foreground" />
            <span className="text-muted-foreground">
              {organizations.length} organization{organizations.length !== 1 ? 's' : ''}
            </span>
          </div>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Add Organization
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create Organization</DialogTitle>
                <DialogDescription>
                  Add a new organization to track and manage its attack surface.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Organization Name</Label>
                  <Input
                    id="name"
                    placeholder="Acme Corporation"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Description (optional)</Label>
                  <Input
                    id="description"
                    placeholder="Brief description of the organization"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="domains">Domains (comma-separated)</Label>
                  <Input
                    id="domains"
                    placeholder="example.com, sub.example.com"
                    value={formData.domains}
                    onChange={(e) => setFormData({ ...formData, domains: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">
                    Enter root domains to discover subdomains and assets
                  </p>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreate} disabled={submitting || !formData.name}>
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    'Create Organization'
                  )}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Domains</TableHead>
                <TableHead>Assets</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : organizations.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                    No organizations yet. Create one to get started.
                  </TableCell>
                </TableRow>
              ) : (
                organizations.map((org) => (
                  <TableRow key={org.id}>
                    <TableCell>
                      <Link
                        href={`/organizations/${org.id}`}
                        className="font-medium hover:text-primary"
                      >
                        {org.name}
                      </Link>
                      {org.description && (
                        <p className="text-xs text-muted-foreground">{org.description}</p>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {org.domains?.slice(0, 3).map((domain) => (
                          <Badge key={domain} variant="outline" className="text-xs">
                            <Globe className="h-3 w-3 mr-1" />
                            {domain}
                          </Badge>
                        ))}
                        {org.domains?.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{org.domains.length - 3} more
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{org.asset_count || 0}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(org.created_at)}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem asChild>
                            <Link href={`/organizations/${org.id}`}>
                              <Edit className="h-4 w-4 mr-2" />
                              View Details
                            </Link>
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="text-destructive"
                            onClick={() => handleDelete(org.id)}
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>
      </div>
    </MainLayout>
  );
}



