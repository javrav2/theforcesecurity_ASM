'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card } from '@/components/ui/card';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Plus, Users, Loader2, KeyRound } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';
import { useAuth } from '@/store/auth';
import { useRouter } from 'next/navigation';

interface User {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  organization_id: number | null;
  created_at: string;
  must_change_password?: boolean;
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [organizations, setOrganizations] = useState<{ id: number; name: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [resettingId, setResettingId] = useState<number | null>(null);
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    full_name: '',
    role: 'analyst',
    organization_id: '' as string,
    must_change_password: true,
  });
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (currentUser && currentUser.role !== 'admin') {
      router.push('/dashboard');
      return;
    }
    fetchUsers();
    fetchOrganizations();
  }, [currentUser, router]);

  const fetchOrganizations = async () => {
    try {
      const data = await api.getOrganizations();
      setOrganizations(Array.isArray(data) ? data : []);
    } catch {
      setOrganizations([]);
    }
  };

  const fetchUsers = async () => {
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch users',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!formData.email || !formData.username || !formData.password || !formData.full_name) {
      toast({
        title: 'Error',
        description: 'Please fill in all required fields',
        variant: 'destructive',
      });
      return;
    }

    setSubmitting(true);
    try {
      const payload: Parameters<typeof api.createUser>[0] = {
        email: formData.email,
        username: formData.username,
        password: formData.password,
        full_name: formData.full_name,
        role: formData.role,
        must_change_password: formData.must_change_password,
      };
      if (formData.organization_id) {
        payload.organization_id = parseInt(formData.organization_id, 10);
      } else {
        payload.organization_id = null;
      }
      await api.createUser(payload);
      toast({
        title: 'Success',
        description: formData.must_change_password
          ? 'User created. They will be required to set a new password at first login.'
          : 'User created successfully',
      });
      setCreateDialogOpen(false);
      setFormData({ email: '', username: '', password: '', full_name: '', role: 'analyst', organization_id: '', must_change_password: true });
      fetchUsers();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to create user',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleForceReset = async (user: User) => {
    setResettingId(user.id);
    try {
      await api.forcePasswordReset(user.id);
      toast({
        title: 'Password reset required',
        description: `${user.full_name || user.email} must set a new password on their next request.`,
      });
      fetchUsers();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.detail || 'Failed to force password reset',
        variant: 'destructive',
      });
    } finally {
      setResettingId(null);
    }
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-red-500/20 text-red-400';
      case 'analyst':
        return 'bg-blue-500/20 text-blue-400';
      case 'viewer':
        return 'bg-green-500/20 text-green-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <MainLayout>
      <Header title="Users" subtitle="Manage user accounts and permissions" />

      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-muted-foreground" />
            <span className="text-muted-foreground">
              {users.length} user{users.length !== 1 ? 's' : ''}
            </span>
          </div>

          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Add User
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create User</DialogTitle>
                <DialogDescription>Add a new user to the platform.</DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="full_name">Full Name</Label>
                  <Input
                    id="full_name"
                    placeholder="John Doe"
                    value={formData.full_name}
                    onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    placeholder="johndoe"
                    value={formData.username}
                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="john@example.com"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Initial Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  />
                </div>

                <div className="flex items-start gap-2">
                  <Checkbox
                    id="must_change_password"
                    checked={formData.must_change_password}
                    onCheckedChange={(checked) =>
                      setFormData({ ...formData, must_change_password: checked === true })
                    }
                  />
                  <div className="grid gap-1 leading-none">
                    <Label htmlFor="must_change_password" className="cursor-pointer">
                      Require password change at first login
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      The password above is temporary; the user must set their own before accessing the platform.
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Role</Label>
                  <Select
                    value={formData.role}
                    onValueChange={(value) => setFormData({ ...formData, role: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="analyst">Analyst</SelectItem>
                      <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Organization</Label>
                  <Select
                    value={formData.organization_id || 'none'}
                    onValueChange={(value) => setFormData({ ...formData, organization_id: value === 'none' ? '' : value })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="No organization (no data access)" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">No organization</SelectItem>
                      {organizations.map((org) => (
                        <SelectItem key={org.id} value={String(org.id)}>
                          {org.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    User will only see assets and scans for this organization. Leave unset for no access.
                  </p>
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreate} disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    'Create User'
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
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  </TableCell>
                </TableRow>
              ) : users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No users found.
                  </TableCell>
                </TableRow>
              ) : (
                users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.full_name}</TableCell>
                    <TableCell>{user.email}</TableCell>
                    <TableCell>
                      <Badge className={getRoleColor(user.role)}>{user.role}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {user.organization_id
                        ? organizations.find((o) => o.id === user.organization_id)?.name ?? `Org #${user.organization_id}`
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Badge variant={user.is_active ? 'default' : 'secondary'}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                        {user.must_change_password && (
                          <Badge className="bg-amber-500/20 text-amber-400">Reset pending</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(user.created_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleForceReset(user)}
                        disabled={resettingId === user.id || user.must_change_password}
                        title={user.must_change_password ? 'User already has a pending password reset' : 'Force this user to set a new password'}
                      >
                        {resettingId === user.id ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <KeyRound className="h-3.5 w-3.5 mr-1.5" />
                        )}
                        Force reset
                      </Button>
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














