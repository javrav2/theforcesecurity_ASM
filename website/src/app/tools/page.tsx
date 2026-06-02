'use client'

import { useState, useMemo } from 'react'
import { Search, SlidersHorizontal, X } from 'lucide-react'
import { TOOLS, CATEGORIES, PRICING_MODELS, type ToolCategory, type PricingModel } from '@/lib/tools'
import { ToolCard } from '@/components/tool-card'
import { cn } from '@/lib/utils'

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

    if (activeCategory) {
      results = results.filter((t) => t.category === activeCategory)
    }

    if (activePricing) {
      results = results.filter((t) => t.pricing === activePricing)
    }

    return results
  }, [query, activeCategory, activePricing])

  const clearFilters = () => {
    setQuery('')
    setActiveCategory(null)
    setActivePricing(null)
  }

  const hasFilters = query || activeCategory || activePricing

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-foreground mb-2">Security Tools Directory</h1>
        <p className="text-muted-foreground">
          {TOOLS.length} tools across {CATEGORIES.length} categories — reviewed by security practitioners
        </p>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search tools, categories, tags..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-border bg-card text-foreground placeholder:text-muted-foreground text-sm focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/20 transition-colors"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <button
          onClick={() => setShowFilters(!showFilters)}
          className={cn(
            'flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium transition-colors',
            showFilters
              ? 'border-primary/50 bg-primary/10 text-primary'
              : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-border/80'
          )}
        >
          <SlidersHorizontal className="w-4 h-4" />
          Filters
          {hasFilters && (
            <span className="w-4 h-4 rounded-full bg-primary text-primary-foreground text-xs flex items-center justify-center font-mono">
              {[activeCategory, activePricing, query].filter(Boolean).length}
            </span>
          )}
        </button>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-card text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="w-4 h-4" />
            Clear
          </button>
        )}
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="mb-6 p-5 rounded-xl border border-border bg-card/50">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-3">
                Category
              </h3>
              <div className="flex flex-wrap gap-2">
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                    className={cn(
                      'px-3 py-1.5 rounded-md text-xs font-medium border transition-colors',
                      activeCategory === cat
                        ? 'border-primary/50 bg-primary/10 text-primary'
                        : 'border-border bg-accent/30 text-muted-foreground hover:text-foreground hover:border-border/80'
                    )}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-3">
                Pricing
              </h3>
              <div className="flex flex-wrap gap-2">
                {PRICING_MODELS.map((pricing) => (
                  <button
                    key={pricing}
                    onClick={() => setActivePricing(activePricing === pricing ? null : pricing)}
                    className={cn(
                      'px-3 py-1.5 rounded-md text-xs font-medium border transition-colors',
                      activePricing === pricing
                        ? 'border-primary/50 bg-primary/10 text-primary'
                        : 'border-border bg-accent/30 text-muted-foreground hover:text-foreground hover:border-border/80'
                    )}
                  >
                    {pricing}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Active Filters Display */}
      {(activeCategory || activePricing) && (
        <div className="flex items-center gap-2 mb-5 text-sm">
          <span className="text-muted-foreground text-xs">Filtered by:</span>
          {activeCategory && (
            <button
              onClick={() => setActiveCategory(null)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/30 text-primary text-xs hover:bg-primary/20 transition-colors"
            >
              {activeCategory}
              <X className="w-3 h-3" />
            </button>
          )}
          {activePricing && (
            <button
              onClick={() => setActivePricing(null)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/30 text-primary text-xs hover:bg-primary/20 transition-colors"
            >
              {activePricing}
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      )}

      {/* Results */}
      {filtered.length === 0 ? (
        <div className="text-center py-20">
          <Search className="w-10 h-10 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-foreground font-medium mb-1">No tools found</p>
          <p className="text-sm text-muted-foreground">Try adjusting your search or filters</p>
          <button onClick={clearFilters} className="mt-4 text-sm text-primary hover:underline">
            Clear all filters
          </button>
        </div>
      ) : (
        <>
          <div className="text-xs text-muted-foreground mb-5">
            Showing <span className="text-foreground font-medium">{filtered.length}</span> of {TOOLS.length} tools
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map((tool) => (
              <ToolCard key={tool.id} tool={tool} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}
