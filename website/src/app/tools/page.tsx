'use client'

import { useState, useMemo } from 'react'
import { Search, SlidersHorizontal, X, ExternalLink, Star, Github } from 'lucide-react'
import { TOOLS, CATEGORIES, PRICING_MODELS, type ToolCategory, type PricingModel } from '@/lib/tools'
import { cn } from '@/lib/utils'

const PRICING_COLORS: Record<PricingModel, string> = {
  Free: 'text-success border-success/30 bg-success/5',
  'Open Source': 'text-primary border-primary/30 bg-primary/5',
  Freemium: 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  Commercial: 'text-warning border-warning/30 bg-warning/5',
  Enterprise: 'text-purple-400 border-purple-400/30 bg-purple-400/5',
}

export default function ToolsPage() {
  const [query, setQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState<ToolCategory | null>(null)
  const [activePricing, setActivePricing] = useState<PricingModel | null>(null)
  const [showFilters, setShowFilters] = useState(false)

  const filtered = useMemo(() => {
    let results = TOOLS
    if (query.trim()) {
      const q = query.toLowerCase()
      results = results.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.tagline.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          t.tags.some((tag) => tag.toLowerCase().includes(q))
      )
    }
    if (activeCategory) results = results.filter((t) => t.category === activeCategory)
    if (activePricing) results = results.filter((t) => t.pricing === activePricing)
    return results
  }, [query, activeCategory, activePricing])

  const clearFilters = () => {
    setQuery('')
    setActiveCategory(null)
    setActivePricing(null)
  }

  const hasFilters = query || activeCategory || activePricing
  const activeFilterCount = [activeCategory, activePricing, query.trim()].filter(Boolean).length

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-8 max-w-2xl">
        <h1 className="text-2xl font-bold text-foreground mb-2">Tool Reference</h1>
        <p className="text-sm text-muted-foreground leading-relaxed">
          {TOOLS.length} security tools evaluated by practitioners. Every entry here
          has been used in real engagements — no affiliate links, no sponsored placements.
        </p>
      </div>

      {/* Search + Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        <div className="relative flex-1 max-w-lg">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search tools..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-border bg-card text-foreground placeholder:text-muted-foreground text-sm focus:outline-none focus:border-primary/50 transition-colors"
          />
          {query && (
            <button onClick={() => setQuery('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <button
          onClick={() => setShowFilters(!showFilters)}
          className={cn(
            'flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium transition-colors',
            showFilters ? 'border-primary/50 bg-primary/10 text-primary' : 'border-border bg-card text-muted-foreground hover:text-foreground'
          )}
        >
          <SlidersHorizontal className="w-4 h-4" />
          Filter
          {activeFilterCount > 0 && (
            <span className="w-4 h-4 rounded-full bg-primary text-primary-foreground text-xs flex items-center justify-center font-mono">
              {activeFilterCount}
            </span>
          )}
        </button>

        {hasFilters && (
          <button onClick={clearFilters} className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-card text-sm text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" /> Clear
          </button>
        )}
      </div>

      {/* Filter panel */}
      {showFilters && (
        <div className="mb-5 p-5 rounded-xl border border-border bg-card/50">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Category</p>
              <div className="flex flex-wrap gap-2">
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                    className={cn(
                      'px-3 py-1.5 rounded border text-xs font-medium transition-colors',
                      activeCategory === cat
                        ? 'border-primary/50 bg-primary/10 text-primary'
                        : 'border-border bg-accent/30 text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Pricing</p>
              <div className="flex flex-wrap gap-2">
                {PRICING_MODELS.map((p) => (
                  <button
                    key={p}
                    onClick={() => setActivePricing(activePricing === p ? null : p)}
                    className={cn(
                      'px-3 py-1.5 rounded border text-xs font-medium transition-colors',
                      activePricing === p
                        ? 'border-primary/50 bg-primary/10 text-primary'
                        : 'border-border bg-accent/30 text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results count */}
      <div className="text-xs text-muted-foreground mb-3">
        {filtered.length === TOOLS.length
          ? `${TOOLS.length} tools`
          : `${filtered.length} of ${TOOLS.length} tools`}
        {activeCategory && <span className="ml-1">in <span className="text-foreground">{activeCategory}</span></span>}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="text-center py-20 border border-border rounded-xl">
          <p className="text-sm text-muted-foreground">No tools match your filters.</p>
          <button onClick={clearFilters} className="mt-3 text-xs text-primary hover:underline">Clear filters</button>
        </div>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-12 px-4 py-3 bg-accent/40 border-b border-border text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            <div className="col-span-4">Tool</div>
            <div className="col-span-3 hidden md:block">Category</div>
            <div className="col-span-2 hidden md:block">Pricing</div>
            <div className="col-span-2 hidden md:block">Rating</div>
            <div className="col-span-1 hidden md:block"></div>
          </div>

          {filtered.map((tool, i) => (
            <div
              key={tool.id}
              className={cn(
                'grid grid-cols-12 items-center px-4 py-3.5 hover:bg-accent/20 transition-colors group',
                i < filtered.length - 1 && 'border-b border-border'
              )}
            >
              {/* Name */}
              <div className="col-span-8 md:col-span-4 flex items-center gap-3 min-w-0">
                <div className="w-7 h-7 rounded bg-accent border border-border flex items-center justify-center flex-shrink-0">
                  <span className="text-xs font-bold text-primary font-mono">{tool.name.charAt(0)}</span>
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-foreground truncate">{tool.name}</p>
                    {tool.featured && (
                      <span className="hidden lg:inline text-[10px] px-1.5 py-0.5 rounded border border-primary/30 text-primary bg-primary/5 font-mono">
                        featured
                      </span>
                    )}
                  </div>
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
                  ? Array.from({ length: 5 }).map((_, j) => (
                      <Star key={j} className={cn('w-3 h-3', j < tool.rating! ? 'text-warning fill-warning' : 'text-border')} />
                    ))
                  : <span className="text-xs text-muted-foreground/40">—</span>
                }
              </div>

              {/* Actions */}
              <div className="col-span-4 md:col-span-1 flex items-center justify-end gap-3">
                {tool.github && (
                  <a href={tool.github} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors hidden lg:block" aria-label="GitHub">
                    <Github className="w-3.5 h-3.5" />
                  </a>
                )}
                <a href={tool.url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors" aria-label="Visit">
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
                <a href={`/tools/${tool.id}`} className="text-xs text-primary hover:text-primary/80 transition-colors font-medium whitespace-nowrap">
                  Review
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
