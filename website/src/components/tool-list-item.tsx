import Link from 'next/link'
import { ExternalLink, Star } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Tool, PricingModel } from '@/lib/tools'

const PRICING_COLORS: Record<PricingModel, string> = {
  Free: 'text-success border-success/30 bg-success/5',
  'Open Source': 'text-primary border-primary/30 bg-primary/5',
  Freemium: 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  Commercial: 'text-warning border-warning/30 bg-warning/5',
  Enterprise: 'text-purple-400 border-purple-400/30 bg-purple-400/5',
}

interface ToolListItemProps {
  tool: Tool
  isLast?: boolean
}

export function ToolListItem({ tool, isLast = false }: ToolListItemProps) {
  return (
    <div
      className={cn(
        'grid grid-cols-12 items-center px-4 py-3.5 hover:bg-accent/30 transition-colors',
        !isLast && 'border-b border-border'
      )}
    >
      {/* Name + tagline */}
      <div className="col-span-4 flex items-center gap-3 min-w-0">
        <div className="w-7 h-7 rounded bg-accent border border-border flex items-center justify-center flex-shrink-0">
          <span className="text-xs font-bold text-primary font-mono">{tool.name.charAt(0)}</span>
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground truncate">{tool.name}</p>
          <p className="text-xs text-muted-foreground truncate hidden sm:block">{tool.tagline}</p>
        </div>
      </div>

      {/* Category */}
      <div className="col-span-3 hidden md:block">
        <span className="text-xs text-muted-foreground">{tool.category}</span>
      </div>

      {/* Pricing */}
      <div className="col-span-2 hidden md:block">
        <span className={cn('tag text-xs', PRICING_COLORS[tool.pricing])}>
          {tool.pricing}
        </span>
      </div>

      {/* Rating */}
      <div className="col-span-2 hidden md:flex items-center gap-0.5">
        {tool.rating
          ? Array.from({ length: 5 }).map((_, i) => (
              <Star
                key={i}
                className={cn(
                  'w-3 h-3',
                  i < tool.rating! ? 'text-warning fill-warning' : 'text-border'
                )}
              />
            ))
          : <span className="text-xs text-muted-foreground/40">—</span>
        }
      </div>

      {/* Actions */}
      <div className="col-span-8 md:col-span-1 flex items-center justify-end gap-3">
        <a
          href={tool.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-muted-foreground hover:text-foreground transition-colors"
          aria-label={`Visit ${tool.name}`}
        >
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
        <Link
          href={`/tools/${tool.id}`}
          className="text-xs text-primary hover:text-primary/80 transition-colors font-medium whitespace-nowrap"
        >
          Review
        </Link>
      </div>
    </div>
  )
}
