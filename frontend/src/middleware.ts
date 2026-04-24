import { NextRequest, NextResponse } from 'next/server';

// CSP is currently provided by the nginx layer in front of the app.
// We previously also emitted a strict nonce-based CSP from middleware, but
// because the App Router never wired the nonce through to layout/<Script>,
// browsers intersected the two CSP headers and blocked Next.js's own
// hydration scripts — which broke the login form (and every interactive
// element on the page). Until the nonce is plumbed through layout.tsx,
// keep this middleware as a passthrough so the nginx CSP is the single
// source of truth.
export function middleware(_request: NextRequest) {
  return NextResponse.next();
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
