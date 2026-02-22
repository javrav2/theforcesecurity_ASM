'use client';

import { useMemo } from 'react';

export interface ThreatExposureCardProps {
  /** Central value (e.g. 12799 or "12,799") */
  value: number | string;
  /** Label below the value (e.g. "Global trending exploits") */
  label: string;
  /** Visual variant for ring color */
  variant?: 'neutral' | 'success' | 'danger' | 'warning' | 'info';
  /** Whether to animate the outer rings (slow rotation) */
  animate?: boolean;
  /** Optional className for the wrapper */
  className?: string;
}

const VARIANT_STROKE: Record<string, string> = {
  neutral: 'hsl(var(--muted-foreground))',
  success: 'hsl(142 76% 36%)',   // green
  danger: 'hsl(0 84% 60%)',      // red
  warning: 'hsl(38 92% 50%)',    // amber
  info: '#00d4ff',               // cyan
};

export function ThreatExposureCard({
  value,
  label,
  variant = 'info',
  animate = true,
  className = '',
}: ThreatExposureCardProps) {
  const strokeColor = VARIANT_STROKE[variant] ?? VARIANT_STROKE.info;

  const displayValue = useMemo(() => {
    if (typeof value === 'number') return value.toLocaleString();
    return String(value);
  }, [value]);

  const cx = 260.5;
  const cy = 200;
  const rings = [110, 100, 90, 80];
  const innerR = 77.5;

  return (
    <div className={`w-full relative z-10 ${className}`}>
      <svg
        viewBox="0 0 521 320"
        className="w-full h-auto"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <filter id="glow-threat" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g className="threat-exposure-card__centralGlow">
          {/* Outer rings (glow, optional rotation) */}
          {rings.map((r, i) => (
            <circle
              key={r}
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke="#00d4ff"
              strokeWidth="0.5"
              opacity={0.1 - i * 0.02}
              filter="url(#glow-threat)"
              className={animate ? 'threat-exposure-rotate' : ''}
            />
          ))}
          {/* Inner ring (accent color) */}
          <circle
            cx={cx}
            cy={cy}
            r={innerR}
            fill="none"
            stroke={strokeColor}
            strokeWidth="2"
            opacity={0.79}
            filter="url(#glow-threat)"
          />
          {/* Center value */}
          <text
            x={cx}
            y={cy}
            textAnchor="middle"
            dominantBaseline="middle"
            fill="hsl(var(--foreground))"
            style={{
              fontSize: 28,
              fontWeight: 'normal',
              fontFamily: 'var(--font-sans), system-ui, sans-serif',
            }}
          >
            {displayValue}
          </text>
          {/* Label below */}
          <text
            x={cx}
            y={cy + 100}
            textAnchor="middle"
            fill={strokeColor}
            style={{
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: '0.5px',
            }}
          >
            {label}
          </text>
        </g>
      </svg>
    </div>
  );
}
