'use client';

import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ExternalLink, Activity } from 'lucide-react';
import Link from 'next/link';

const DETECTFLOW_UI_URL = process.env.NEXT_PUBLIC_DETECTFLOW_UI_URL || '';
const DETECTFLOW_README = 'https://github.com/socprime/detectflow-ui';

export default function DetectFlowPage() {
  const embedUrl = DETECTFLOW_UI_URL.trim();

  return (
    <MainLayout>
      <Header
        title="DetectFlow Dashboard"
        subtitle="Real-time pipeline topology and runtime state (SOC Prime DetectFlow OSS)"
      />
      <div className="p-6 flex flex-col gap-4">
        {embedUrl ? (
          <>
            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" asChild>
                <Link href={embedUrl} target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open in new tab
                </Link>
              </Button>
            </div>
            <Card className="flex-1 min-h-[calc(100vh-12rem)] overflow-hidden">
              <div className="h-full w-full min-h-[600px]">
                <iframe
                  src={embedUrl}
                  title="DetectFlow real-time dashboard"
                  className="w-full h-full min-h-[600px] border-0 rounded-lg"
                  allow="fullscreen"
                  sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
                />
              </div>
            </Card>
          </>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                DetectFlow dashboard not configured
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                The real-time dashboard is provided by the{' '}
                <a
                  href={DETECTFLOW_README}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary underline"
                >
                  DetectFlow UI
                </a>{' '}
                (separate repo). To embed it here:
              </p>
              <ol className="list-decimal list-inside space-y-2 text-sm text-muted-foreground">
                <li>
                  Clone and run DetectFlow UI (e.g. <code className="bg-muted px-1 rounded">yarn watch</code> or
                  deploy it). By default it runs on <code className="bg-muted px-1 rounded">http://localhost:5173</code>.
                </li>
                <li>
                  Set <code className="bg-muted px-1 rounded">NEXT_PUBLIC_DETECTFLOW_UI_URL</code> in your
                  frontend environment to the DetectFlow UI origin (e.g.{' '}
                  <code className="bg-muted px-1 rounded">http://localhost:5173</code> or your deployed URL).
                </li>
                <li>
                  Rebuild the ASM frontend and reload this page. The dashboard will appear in the frame above.
                </li>
              </ol>
              <Button variant="outline" asChild>
                <Link href={DETECTFLOW_README} target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  DetectFlow UI repo
                </Link>
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
