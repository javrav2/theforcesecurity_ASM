import Link from 'next/link'
import { Download, Clock, ArrowRight, FileText, BookOpen, AlertTriangle, Wrench } from 'lucide-react'
import { getAllResearch, type ResearchType } from '@/lib/research'
import { formatDate, cn } from '@/lib/utils'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Research & Whitepapers',
  description: 'Security whitepapers, technical reports, and field guides from the Judah Security team.',
}

import type { LucideIcon } from 'lucide-react'

const TYPE_META: Record<ResearchType, { color: string; icon: LucideIcon }> = {
  Whitepaper: { color: 'text-primary border-primary/30 bg-primary/5', icon: FileText },
  'Technical Report': { color: 'text-blue-400 border-blue-400/30 bg-blue-400/5', icon: BookOpen },
  'Tool Evaluation': { color: 'text-warning border-warning/30 bg-warning/5', icon: Wrench },
  'Field Guide': { color: 'text-green-400 border-green-400/30 bg-green-400/5', icon: BookOpen },
  Advisory: { color: 'text-destructive border-destructive/30 bg-destructive/5', icon: AlertTriangle },
}

export default function ResearchPage() {
  const all = getAllResearch()
  const featured = all.filter((r) => r.featured)
  const rest = all.filter((r) => !r.featured)

  return (
    <div>
      {/* Header */}
      <section className="border-b border-border bg-card/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <p className="text-xs font-mono text-primary uppercase tracking-widest mb-4">Research</p>
          <h1 className="text-4xl font-bold text-foreground mb-4">
            Whitepapers & Technical Reports
          </h1>
          <p className="text-muted-foreground text-base max-w-2xl leading-relaxed">
            Long-form security research from Judah Security — operational findings, technical
            deep-dives, and field guides. Written by practitioners, for practitioners and
            security leaders.
          </p>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">

        {/* Featured */}
        {featured.length > 0 && (
          <section className="mb-16">
            <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-6">Featured Research</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {featured.map((item) => {
                const meta = TYPE_META[item.type] ?? { color: 'text-muted-foreground border-border', icon: FileText }
                const Icon = meta.icon
                return (
                  <div key={item.slug} className="flex flex-col rounded-xl border border-border bg-card p-7 hover:border-primary/30 transition-colors group">
                    <div className="flex items-start justify-between gap-4 mb-5">
                      <div className="flex items-center gap-2">
                        <div className={cn('w-7 h-7 rounded flex items-center justify-center border', meta.color)}>
                          <Icon className="w-3.5 h-3.5" />
                        </div>
                        <span className={cn('tag text-xs', meta.color)}>{item.type}</span>
                      </div>
                      {item.downloadable && (
                        <span className="flex items-center gap-1 text-xs text-muted-foreground/60 border border-border px-2 py-1 rounded">
                          <Download className="w-3 h-3" />PDF
                        </span>
                      )}
                    </div>

                    <h2 className="font-bold text-foreground text-lg leading-snug mb-3 group-hover:text-primary transition-colors flex-1">
                      {item.title}
                    </h2>
                    <p className="text-sm text-muted-foreground leading-relaxed line-clamp-3 mb-6">
                      {item.excerpt}
                    </p>

                    <div className="flex items-center justify-between pt-4 border-t border-border mt-auto">
                      <div className="flex items-center gap-3">
                        <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center">
                          <span className="text-[10px] font-bold text-primary">{item.author.charAt(0)}</span>
                        </div>
                        <div>
                          <p className="text-xs font-medium text-foreground">{item.author}</p>
                          <p className="text-xs text-muted-foreground/60">{formatDate(item.date)}</p>
                        </div>
                      </div>
                      <Link href={`/research/${item.slug}`} className="flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 font-medium transition-colors">
                        Read <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </div>
                )
              })}
            </div>
          </section>
        )}

        {/* All research */}
        {rest.length > 0 && (
          <section>
            <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-6">All Research</p>
            <div className="rounded-xl border border-border overflow-hidden divide-y divide-border">
              {rest.map((item) => {
                const meta = TYPE_META[item.type] ?? { color: 'text-muted-foreground border-border', icon: FileText }
                return (
                  <Link
                    key={item.slug}
                    href={`/research/${item.slug}`}
                    className="flex items-start gap-5 px-6 py-5 hover:bg-accent/20 transition-colors group bg-card"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <span className={cn('tag text-xs', meta.color)}>{item.type}</span>
                        <span className="text-xs text-muted-foreground/60 font-mono">{formatDate(item.date)}</span>
                        {item.downloadable && (
                          <span className="flex items-center gap-1 text-xs text-muted-foreground/50">
                            <Download className="w-2.5 h-2.5" />PDF
                          </span>
                        )}
                      </div>
                      <h3 className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors leading-snug mb-1">
                        {item.title}
                      </h3>
                      <p className="text-xs text-muted-foreground line-clamp-1">{item.excerpt}</p>
                    </div>
                    <div className="flex items-center gap-1 text-xs text-muted-foreground/50 flex-shrink-0 mt-1">
                      <Clock className="w-3 h-3" />{item.readTime}m
                      <ArrowRight className="w-3 h-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </Link>
                )
              })}
            </div>
          </section>
        )}

        {all.length === 0 && (
          <div className="text-center py-24">
            <FileText className="w-10 h-10 text-muted-foreground/20 mx-auto mb-4" />
            <p className="text-muted-foreground text-sm">Research coming soon.</p>
          </div>
        )}

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-primary/20 bg-primary/5 px-8 py-10 text-center">
          <h3 className="text-xl font-bold text-foreground mb-3">Have a research question?</h3>
          <p className="text-sm text-muted-foreground max-w-lg mx-auto mb-6">
            If there's a topic you'd like us to cover or a security challenge you're working through,
            get in touch. We're always looking for the next real problem to dig into.
          </p>
          <Link
            href="mailto:hello@judahsecurity.com"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors"
          >
            Reach Out <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </div>
  )
}
