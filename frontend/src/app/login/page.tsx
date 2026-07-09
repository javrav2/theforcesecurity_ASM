'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Loader2, Shield, Scan, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/store/auth';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import { Turnstile } from '@/components/auth/Turnstile';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [captcha, setCaptcha] = useState<{ enabled: boolean; siteKey: string | null }>({
    enabled: false,
    siteKey: null,
  });
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const router = useRouter();
  const { login } = useAuth();
  const { toast } = useToast();

  useEffect(() => {
    api
      .getAuthConfig()
      .then((cfg) => {
        if (cfg.captcha.enabled && cfg.captcha.provider === 'turnstile' && cfg.captcha.site_key) {
          setCaptcha({ enabled: true, siteKey: cfg.captcha.site_key });
        }
      })
      .catch(() => {
        /* config unreachable — proceed without captcha (backend still enforces if required) */
      });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (captcha.enabled && !captchaToken) {
      toast({
        title: 'Verification required',
        description: 'Please complete the CAPTCHA challenge.',
        variant: 'destructive',
      });
      return;
    }
    setIsLoading(true);
    try {
      await login(email, password, captchaToken ?? undefined);
      const currentUser = useAuth.getState().user;
      if (currentUser?.must_change_password) {
        toast({ title: 'Password change required', description: 'Please set a new password to continue.' });
        router.push('/change-password');
        return;
      }
      toast({ title: 'Welcome back!', description: 'Successfully logged in.' });
      router.push('/dashboard');
    } catch (error: any) {
      const { getApiErrorMessage } = await import('@/lib/api');
      // A CAPTCHA token is single-use; force a fresh challenge after any failure.
      setCaptchaToken(null);
      toast({
        title: 'Login failed',
        description: getApiErrorMessage(error, 'Invalid credentials'),
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row">

      {/* ── Left panel: brand showcase ── */}
      <div className="relative hidden lg:flex lg:w-1/2 flex-col items-center justify-center overflow-hidden bg-[hsl(222,70%,4%)]">

        {/* Dot grid overlay */}
        <div className="absolute inset-0 dot-grid opacity-30" />

        {/* Ambient glow rings */}
        <div className="absolute w-[560px] h-[560px] rounded-full border border-primary/10" />
        <div className="absolute w-[420px] h-[420px] rounded-full border border-primary/15" />
        <div className="absolute w-[280px] h-[280px] rounded-full border border-primary/20" />

        {/* Core radial glow behind logo */}
        <div className="absolute w-[500px] h-[500px] rounded-full bg-primary/8 blur-3xl" />
        <div className="absolute w-[300px] h-[300px] rounded-full bg-primary/12 blur-2xl" />

        {/* Logo */}
        <div className="relative z-10 flex flex-col items-center gap-8 px-16">
          <img
            src="/logo.png"
            alt="Judah Security"
            className="w-[360px] drop-shadow-[0_0_60px_hsl(213,100%,62%,0.35)]"
          />

          {/* Divider */}
          <div className="flex items-center gap-4 w-full max-w-xs">
            <div className="flex-1 h-px bg-primary/20" />
            <span className="text-[10px] tracking-[0.35em] text-primary/50 uppercase">Platform</span>
            <div className="flex-1 h-px bg-primary/20" />
          </div>

          {/* Feature pills */}
          <div className="flex flex-col gap-3 w-full max-w-xs">
            {[
              { icon: Globe,  label: 'Attack Surface Discovery' },
              { icon: Scan,   label: 'Continuous Vulnerability Scanning' },
              { icon: Shield, label: 'Threat Exposure Scoring' },
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-primary/15 bg-primary/5">
                <Icon className="h-4 w-4 text-primary shrink-0" />
                <span className="text-sm text-foreground/70">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="absolute bottom-8 text-[10px] tracking-[0.3em] text-muted-foreground/40 uppercase">
          Judah Security &mdash; Cyber Security Advisory &amp; Services
        </div>
      </div>

      {/* ── Right panel: login form ── */}
      <div className="w-full lg:w-1/2 flex items-center justify-center bg-background p-8 relative">

        {/* Subtle corner glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none" />

        <div className="w-full max-w-sm relative z-10 space-y-8">

          {/* Mobile logo (shown only below lg breakpoint) */}
          <div className="flex justify-center lg:hidden">
            <img src="/logo.png" alt="Judah Security" className="w-52 rounded-2xl" />
          </div>

          {/* Heading */}
          <div className="space-y-1">
            <h1 className="text-3xl font-bold tracking-tight">Welcome back</h1>
            <p className="text-sm text-muted-foreground">
              Sign in to your Attack Surface Management account
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="email">Username</Label>
              <Input
                id="email"
                type="text"
                placeholder="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="username"
                className="h-11 bg-card/60 border-border focus:border-primary"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                  className="h-11 bg-card/60 border-border focus:border-primary pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {captcha.enabled && captcha.siteKey && (
              <div className="flex justify-center">
                <Turnstile
                  siteKey={captcha.siteKey}
                  onVerify={(token) => setCaptchaToken(token)}
                  onExpire={() => setCaptchaToken(null)}
                />
              </div>
            )}

            <Button
              type="submit"
              className="w-full h-11 text-sm font-semibold tracking-wide"
              disabled={isLoading || (captcha.enabled && !captchaToken)}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </Button>
          </form>

          {/* Footer */}
          <p className="text-center text-[11px] text-muted-foreground/50 tracking-wider uppercase">
            Judah Security &mdash; ASM Platform
          </p>
        </div>
      </div>
    </div>
  );
}
