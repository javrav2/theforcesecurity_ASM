import Link from 'next/link'
import { ExternalLink, Github, Star } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Tool, PricingModel } from '@/lib/tools'

const PRICING_COLORS: Record<PricingModel, string> = {
  Free: 'text-success border-success/30 bg-success/5',
  'Open Source': 'text-primary border-primary/30 bg-primary/5',
  Freemium: 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  Commercial: 'text-warning border-warning/30 bg-warning/5',
  Enterprise: 'text-purple-400 border-purple-400/30 bg-purple-400/5',
}

interface ToolCardProps {
  tool: Tool
  compact?: boolean
}

export function ToolCard({ tool, compact = false }: ToolCardProps) {
  return (
    <div
      className={cn(
        'group relative flex flex-col rounded-xl border border-border bg-card p-5 transition-all duration-200',
        'hover:border-primary/25 hover:bg-card/80',
        compact && 'p-4'
      )}
    >
      {tool.featured && (
        <div className="absolute top-3 right-3">
          <span className="tag text-primary border-primary/30 bg-primary/5">Featured</span>
        </div>
      )}

      <div className="flex items-start gap-3 mb-3">
        <div className="w-10 h-10 rounded-lg bg-accent border border-border flex items-center justify-center flex-shrink-0">
          <span className="text-lg font-bold text-primary font-mono">
            {tool.name.charAt(0)}
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold text-foreground text-sm leading-tight">{tool.name}</h3>
          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{tool.tagline}</p>
        </div>
      </div>

      {!compact && (
        <p className="text-xs text-muted-foreground leading-relaxed mb-4 line-clamp-3 flex-1">
          {tool.description}
        </p>
      )}

      <div className="flex flex-wrap gap-1.5 mb-4">
        <span className={cn('tag', PRICING_COLORS[tool.pricing])}>
          {tool.pricing}
        </span>
        <span className="tag text-muted-foreground border-border bg-accent/50">
          {tool.category}
        </span>
      </div>

      {tool.rating && (
        <div className="flex items-center gap-0.5 mb-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Star
              key={i}
              className={cn(
                'w-3 h-3',
                i < tool.rating! ? 'text-warning fill-warning' : 'text-border'
              )}
            />
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 mt-auto pt-2 border-t border-border">
        <a
          href={tool.url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ExternalLink className="w-3 h-3" />
          Visit
        </a>
        {tool.github && (
          <a
            href={tool.github}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <Github className="w-3 h-3" />
            GitHub
          </a>
        )}
        <Link
          href={`/tools/${tool.id}`}
          className="ml-auto text-xs text-primary hover:text-primary/80 transition-colors font-medium"
        >
          Review →
        </Link>
      </div>
    </div>
  )
}
