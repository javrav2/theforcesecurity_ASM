'use client';

import { useEffect, useRef } from 'react';

const SCRIPT_SRC =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const SCRIPT_ID = 'cf-turnstile-script';

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      remove: (id?: string) => void;
    };
  }
}

function loadScript(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window === 'undefined') return resolve();
    if (window.turnstile) return resolve();
    const existing = document.getElementById(SCRIPT_ID) as HTMLScriptElement | null;
    if (existing) {
      existing.addEventListener('load', () => resolve());
      existing.addEventListener('error', () => reject(new Error('Turnstile failed to load')));
      return;
    }
    const script = document.createElement('script');
    script.id = SCRIPT_ID;
    script.src = SCRIPT_SRC;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Turnstile failed to load'));
    document.head.appendChild(script);
  });
}

interface TurnstileProps {
  siteKey: string;
  /** Fires with the verification token once the challenge is solved. */
  onVerify: (token: string) => void;
  /** Fires when the token expires or errors, so the caller can clear it. */
  onExpire?: () => void;
}

/**
 * Cloudflare Turnstile widget. Renders the challenge and reports the token via
 * onVerify. The token is single-use and short-lived, so it is passed to the
 * backend immediately on form submit.
 */
export function Turnstile({ siteKey, onVerify, onExpire }: TurnstileProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    loadScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.turnstile) return;
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: siteKey,
          callback: (token: string) => onVerify(token),
          'expired-callback': () => onExpire?.(),
          'error-callback': () => onExpire?.(),
        });
      })
      .catch(() => onExpire?.());

    return () => {
      cancelled = true;
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current);
        } catch {
          /* widget already gone */
        }
      }
    };
  }, [siteKey, onVerify, onExpire]);

  return <div ref={containerRef} />;
}
