'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  Building2,
  Globe,
  Shield,
  Camera,
  ScanLine,
  Network,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Search,
  Users,
  History,
  ServerCrash,
  CalendarClock,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/store/auth';
import { useState } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Organizations', href: '/organizations', icon: Building2 },
  { name: 'Assets', href: '/assets', icon: Globe },
  { name: 'CIDR Blocks', href: '/netblocks', icon: ServerCrash },
  { name: 'Findings', href: '/findings', icon: Shield },
  { name: 'Screenshots', href: '/screenshots', icon: Camera },
  { name: 'Scans', href: '/scans', icon: ScanLine },
  { name: 'Schedules', href: '/schedules', icon: CalendarClock },
  { name: 'Ports', href: '/ports', icon: Network },
  { name: 'Discovery', href: '/discovery', icon: Search },
  { name: 'Wayback URLs', href: '/wayback', icon: History },
];

const adminNavigation = [
  { name: 'Users', href: '/users', icon: Users },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      className={cn(
        'flex flex-col h-screen bg-card border-r border-border transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between h-16 px-4 border-b border-blue-900/50">
        {!collapsed && (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 flex items-center justify-center">
              <img src="/logo.svg" alt="Logo" className="w-full h-full" style={{ filter: 'invert(1)' }} />
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-sm tracking-wide">THE FORCE</span>
              <span className="text-[10px] text-blue-400 tracking-widest">SECURITY</span>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="ml-auto"
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              )}
            >
              <item.icon className={cn('h-5 w-5 shrink-0', isActive && 'text-primary')} />
              {!collapsed && <span>{item.name}</span>}
            </Link>
          );
        })}

        {user?.role === 'admin' && (
          <>
            <div className={cn('pt-4 pb-2', !collapsed && 'px-3')}>
              {!collapsed && (
                <span className="text-xs font-semibold uppercase text-muted-foreground">
                  Admin
                </span>
              )}
              {collapsed && <div className="border-t border-border" />}
            </div>
            {adminNavigation.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <item.icon className={cn('h-5 w-5 shrink-0', isActive && 'text-primary')} />
                  {!collapsed && <span>{item.name}</span>}
                </Link>
              );
            })}
          </>
        )}
      </nav>

      {/* User section */}
      <div className="border-t border-border p-4">
        {!collapsed ? (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center">
              <span className="text-sm font-medium">
                {user?.full_name?.charAt(0) || user?.email?.charAt(0) || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user?.full_name || user?.email}</p>
              <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
            </div>
            <Button variant="ghost" size="icon" onClick={() => logout()}>
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        ) : (
          <Button variant="ghost" size="icon" onClick={() => logout()} className="w-full">
            <LogOut className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}

