'use client';

import { useEffect, useState } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Camera,
  Search,
  Grid,
  List,
  Loader2,
  ExternalLink,
  RefreshCw,
  Calendar,
  Globe,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { formatDate } from '@/lib/utils';

interface Screenshot {
  id: number;
  asset_id: number;
  url: string;
  file_path: string;
  thumbnail_path?: string;
  http_status?: number;
  page_title?: string;
  status: string;
  captured_at: string;
  asset?: {
    hostname: string;
  };
}

export default function ScreenshotsPage() {
  const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [selectedScreenshot, setSelectedScreenshot] = useState<Screenshot | null>(null);
  const [organizations, setOrganizations] = useState<any[]>([]);
  const [orgFilter, setOrgFilter] = useState<string>('all');
  const { toast } = useToast();

  const fetchData = async () => {
    setLoading(true);
    try {
      const [screenshotsData, orgsData] = await Promise.all([
        api.getScreenshots({
          organization_id: orgFilter !== 'all' ? parseInt(orgFilter) : undefined,
          limit: 100,
        }),
        api.getOrganizations(),
      ]);

      setScreenshots(screenshotsData.items || screenshotsData || []);
      setOrganizations(orgsData);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch screenshots',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [orgFilter]);

  const filteredScreenshots = screenshots.filter(
    (s) =>
      s.url?.toLowerCase().includes(search.toLowerCase()) ||
      s.page_title?.toLowerCase().includes(search.toLowerCase()) ||
      s.asset?.hostname?.toLowerCase().includes(search.toLowerCase())
  );

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'success':
        return 'bg-green-500/20 text-green-400';
      case 'failed':
        return 'bg-red-500/20 text-red-400';
      case 'pending':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <MainLayout>
      <Header title="Screenshots" subtitle="Visual snapshots of discovered assets" />

      <div className="p-6 space-y-6">
        {/* Toolbar */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="relative flex-1 min-w-[250px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search screenshots..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>

          <div className="flex items-center gap-2">
            <Select value={orgFilter} onValueChange={setOrgFilter}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Organization" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Organizations</SelectItem>
                {organizations.map((org) => (
                  <SelectItem key={org.id} value={org.id.toString()}>
                    {org.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="flex border rounded-md">
              <Button
                variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
                size="icon"
                onClick={() => setViewMode('grid')}
              >
                <Grid className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                size="icon"
                onClick={() => setViewMode('list')}
              >
                <List className="h-4 w-4" />
              </Button>
            </div>

            <Button variant="outline" size="sm" onClick={fetchData}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Screenshots Display */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin" />
          </div>
        ) : filteredScreenshots.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Camera className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-muted-foreground text-center">
                No screenshots found. Screenshots will appear here after running EyeWitness scans.
              </p>
            </CardContent>
          </Card>
        ) : viewMode === 'grid' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredScreenshots.map((screenshot) => (
              <Card
                key={screenshot.id}
                className="overflow-hidden cursor-pointer hover:ring-2 ring-primary transition-all"
                onClick={() => setSelectedScreenshot(screenshot)}
              >
                <div className="aspect-video bg-muted relative">
                  {screenshot.thumbnail_path || screenshot.file_path ? (
                    <img
                      src={api.getScreenshotImageUrl(screenshot.id)}
                      alt={screenshot.page_title || screenshot.url}
                      className="w-full h-full object-cover"
                      onError={(e) => {
                        (e.target as HTMLImageElement).src = '/placeholder-screenshot.png';
                      }}
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center">
                      <Camera className="h-8 w-8 text-muted-foreground" />
                    </div>
                  )}
                  <Badge className={`absolute top-2 right-2 ${getStatusColor(screenshot.status)}`}>
                    {screenshot.status}
                  </Badge>
                </div>
                <CardContent className="p-3">
                  <p className="font-medium text-sm truncate">
                    {screenshot.page_title || screenshot.url}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">
                    {screenshot.asset?.hostname || screenshot.url}
                  </p>
                  <div className="flex items-center justify-between mt-2">
                    {screenshot.http_status && (
                      <Badge variant="outline" className="text-xs">
                        HTTP {screenshot.http_status}
                      </Badge>
                    )}
                    <span className="text-xs text-muted-foreground">
                      {formatDate(screenshot.captured_at)}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <Card>
            <div className="divide-y">
              {filteredScreenshots.map((screenshot) => (
                <div
                  key={screenshot.id}
                  className="flex items-center gap-4 p-4 hover:bg-muted/50 cursor-pointer"
                  onClick={() => setSelectedScreenshot(screenshot)}
                >
                  <div className="w-32 h-20 bg-muted rounded overflow-hidden flex-shrink-0">
                    {screenshot.thumbnail_path || screenshot.file_path ? (
                      <img
                        src={api.getScreenshotImageUrl(screenshot.id)}
                        alt={screenshot.page_title || screenshot.url}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center">
                        <Camera className="h-6 w-6 text-muted-foreground" />
                      </div>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">
                      {screenshot.page_title || screenshot.url}
                    </p>
                    <p className="text-sm text-muted-foreground truncate">
                      {screenshot.asset?.hostname || screenshot.url}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge className={getStatusColor(screenshot.status)}>
                        {screenshot.status}
                      </Badge>
                      {screenshot.http_status && (
                        <Badge variant="outline">HTTP {screenshot.http_status}</Badge>
                      )}
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {formatDate(screenshot.captured_at)}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Screenshot Detail Dialog */}
        <Dialog open={!!selectedScreenshot} onOpenChange={() => setSelectedScreenshot(null)}>
          <DialogContent className="max-w-4xl">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                {selectedScreenshot?.page_title || selectedScreenshot?.url}
              </DialogTitle>
            </DialogHeader>

            <div className="space-y-4">
              <div className="aspect-video bg-muted rounded-lg overflow-hidden">
                {selectedScreenshot?.file_path ? (
                  <img
                    src={api.getScreenshotImageUrl(selectedScreenshot.id)}
                    alt={selectedScreenshot.page_title || selectedScreenshot.url}
                    className="w-full h-full object-contain"
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center">
                    <Camera className="h-12 w-12 text-muted-foreground" />
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">URL</p>
                  <a
                    href={selectedScreenshot?.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline flex items-center gap-1 text-sm"
                  >
                    {selectedScreenshot?.url}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">HTTP Status</p>
                  <p className="font-medium">{selectedScreenshot?.http_status || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  <Badge className={getStatusColor(selectedScreenshot?.status || '')}>
                    {selectedScreenshot?.status}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Captured</p>
                  <p className="text-sm flex items-center gap-1">
                    <Calendar className="h-3 w-3" />
                    {selectedScreenshot && formatDate(selectedScreenshot.captured_at)}
                  </p>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </MainLayout>
  );
}











