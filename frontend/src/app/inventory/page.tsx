'use client';

import { useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Network, Globe, Loader2, Building2, FolderTree } from 'lucide-react';
import dynamic from 'next/dynamic';

// Dynamically import content components
const NetblocksContent = dynamic(() => import('./NetblocksContent'), {
  loading: () => <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>,
});

const DomainsContent = dynamic(() => import('./DomainsContent'), {
  loading: () => <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>,
});

const AcquisitionsContent = dynamic(() => import('./AcquisitionsContent'), {
  loading: () => <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>,
});

const AppStructureContent = dynamic(() => import('./AppStructureContent'), {
  loading: () => <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>,
});

function InventoryPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialTab = searchParams.get('tab') || 'netblocks';
  const [activeTab, setActiveTab] = useState(initialTab);

  const handleTabChange = (value: string) => {
    setActiveTab(value);
    router.push(`/inventory?tab=${value}`, { scroll: false });
  };

  return (
    <MainLayout>
      <Header 
        title="Asset Inventory" 
        subtitle="Manage CIDR blocks, domains, and M&A acquisitions"
      />

      <div className="p-6">
        <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
          <TabsList className="grid w-full max-w-2xl grid-cols-4">
            <TabsTrigger value="netblocks" className="flex items-center gap-2">
              <Network className="h-4 w-4" />
              CIDR Blocks
            </TabsTrigger>
            <TabsTrigger value="domains" className="flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Domains
            </TabsTrigger>
            <TabsTrigger value="acquisitions" className="flex items-center gap-2">
              <Building2 className="h-4 w-4" />
              M&A
            </TabsTrigger>
            <TabsTrigger value="app-structure" className="flex items-center gap-2">
              <FolderTree className="h-4 w-4" />
              App Structure
            </TabsTrigger>
          </TabsList>

          <TabsContent value="netblocks" className="space-y-6">
            <NetblocksContent />
          </TabsContent>

          <TabsContent value="domains" className="space-y-6">
            <DomainsContent />
          </TabsContent>

          <TabsContent value="acquisitions" className="space-y-6">
            <AcquisitionsContent />
          </TabsContent>

          <TabsContent value="app-structure" className="space-y-6">
            <AppStructureContent />
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
}

export default function InventoryPage() {
  return (
    <Suspense fallback={<div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin" /></div>}>
      <InventoryPageContent />
    </Suspense>
  );
}
