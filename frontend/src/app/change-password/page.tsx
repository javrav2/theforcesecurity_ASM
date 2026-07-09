'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2, KeyRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/store/auth';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';

export default function ChangePasswordPage() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const { isAuthenticated, isLoading: authLoading, checkAuth, user } = useAuth();
  const { toast } = useToast();

  const forced = !!user?.must_change_password;

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [authLoading, isAuthenticated, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 8) {
      toast({ title: 'Password too short', description: 'Use at least 8 characters.', variant: 'destructive' });
      return;
    }
    if (newPassword !== confirmPassword) {
      toast({ title: 'Passwords do not match', description: 'Re-enter the new password.', variant: 'destructive' });
      return;
    }
    setIsLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      // Refresh user so must_change_password clears, then continue into the app.
      await checkAuth();
      toast({ title: 'Password updated', description: 'Your password has been changed.' });
      router.push('/dashboard');
    } catch (error: any) {
      const { getApiErrorMessage } = await import('@/lib/api');
      toast({
        title: 'Could not change password',
        description: getApiErrorMessage(error, 'Please check your current password and try again.'),
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-8">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-full border border-primary/20 bg-primary/10">
            <KeyRound className="h-5 w-5 text-primary" />
          </div>
          <div className="space-y-1 text-center">
            <h1 className="text-2xl font-bold tracking-tight">Set a new password</h1>
            <p className="text-sm text-muted-foreground">
              {forced
                ? 'Your account uses a temporary password. Choose a new one to continue.'
                : 'Update your account password.'}
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="current">Current password</Label>
            <Input
              id="current"
              type="password"
              placeholder="••••••••"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="h-11"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="new">New password</Label>
            <Input
              id="new"
              type="password"
              placeholder="At least 8 characters"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              autoComplete="new-password"
              className="h-11"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm">Confirm new password</Label>
            <Input
              id="confirm"
              type="password"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              autoComplete="new-password"
              className="h-11"
            />
          </div>

          <Button type="submit" className="w-full h-11 text-sm font-semibold tracking-wide" disabled={isLoading}>
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Updating...
              </>
            ) : (
              'Update Password'
            )}
          </Button>
        </form>
      </div>
    </div>
  );
}
