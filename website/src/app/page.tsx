import Link from 'next/link'
import { ArrowRight, Search, Shield, Zap, BookOpen, ChevronRight } from 'lucide-react'
import { getFeaturedTools, CATEGORIES, TOOLS } from '@/lib/tools'
import { getFeaturedPosts, getRecentPosts } from '@/lib/blog'
import { ToolCard } from '@/components/tool-card'
import { BlogCard } from '@/components/blog-card'

export default function HomePage() {
  const featuredTools = getFeaturedTools()
  const featuredPosts = getFeaturedPosts()
  const recentPosts = getRecentPosts(5)

  return (
    <div>
      {/* Hero */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="absolute inset-0 grid-lines opacity-30 pointer-events-none" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-background pointer-events-none" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 md:py-36">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/30 bg-primary/5 text-primary text-xs font-medium mb-6">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              Security Intelligence for Modern Teams
            </div>

            <h1 className="text-4xl md:text-6xl font-bold text-foreground tracking-tight leading-tight mb-6">
              Find the right{' '}
              <span className="text-primary glow-green">security tool</span>
              {' '}for every threat
            </h1>

            <p className="text-lg text-muted-foreground leading-relaxed mb-10 max-w-2xl">
              We research, test, and review the best cybersecurity tools on the market.
              From open-source scanners to enterprise platforms — cut through the noise and
              find what actually works.
            </p>

            <div className="flex flex-col sm:flex-row gap-4">
              <Link
                href="/tools"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors"
              >
                <Search className="w-4 h-4" />
                Browse Tools
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/blog"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg border border-border text-foreground font-medium text-sm hover:bg-accent transition-colors"
              >
                <BookOpen className="w-4 h-4" />
                Read Research
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-b border-border bg-card/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-3 divide-x divide-border">
            {[
              { value: `${TOOLS.length}+`, label: 'Tools Reviewed' },
              { value: `${CATEGORIES.length}`, label: 'Categories' },
              { value: '100%', label: 'Practitioner-Tested' },
            ].map((stat) => (
              <div key={stat.label} className="py-8 px-8 text-center">
                <div className="text-2xl font-bold text-primary font-mono">{stat.value}</div>
                <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Featured Tools */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-2xl font-bold text-foreground">Featured Tools</h2>
            <p className="text-sm text-muted-foreground mt-1">Hand-picked by our security team</p>
          </div>
          <Link
            href="/tools"
            className="flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 transition-colors font-medium"
          >
            View all <ChevronRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {featuredTools.map((tool) => (
            <ToolCard key={tool.id} tool={tool} />
          ))}
        </div>
      </section>

      {/* Categories */}
      <section className="border-y border-border bg-card/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-foreground">Browse by Category</h2>
            <p className="text-sm text-muted-foreground mt-1">
              {CATEGORIES.length} security disciplines covered
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            {CATEGORIES.map((cat) => (
              <Link
                key={cat}
                href={`/tools?category=${encodeURIComponent(cat)}`}
                className="px-4 py-2 rounded-lg border border-border bg-card text-sm text-muted-foreground hover:text-foreground hover:border-primary/30 hover:bg-primary/5 transition-all duration-150"
              >
                {cat}
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Blog + Recent Posts */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-12">
          {/* Featured posts */}
          <div className="lg:col-span-3">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h2 className="text-2xl font-bold text-foreground">Latest Research</h2>
                <p className="text-sm text-muted-foreground mt-1">In-depth security insights</p>
              </div>
              <Link
                href="/blog"
                className="flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 transition-colors font-medium"
              >
                All posts <ChevronRight className="w-4 h-4" />
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {featuredPosts.slice(0, 2).map((post) => (
                <BlogCard key={post.slug} post={post} featured />
              ))}
            </div>
          </div>

          {/* Recent posts list */}
          <div className="lg:col-span-2">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-xl font-bold text-foreground">Recent Posts</h2>
            </div>
            <div>
              {recentPosts.map((post) => (
                <BlogCard key={post.slug} post={post} />
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* About / CTA */}
      <section id="about" className="border-t border-border bg-card/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="max-w-3xl">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary" />
              </div>
              <h2 className="text-2xl font-bold text-foreground">About The Force Security</h2>
            </div>
            <p className="text-muted-foreground leading-relaxed mb-4">
              We&apos;re a team of offensive security practitioners building tools and research at
              the intersection of attack surface management, vulnerability intelligence, and
              AI-assisted security operations.
            </p>
            <p className="text-muted-foreground leading-relaxed mb-8">
              This site is where we share what we learn — honest tool reviews from practitioners
              who use this software daily, deep dives into security research, and practical guides
              for security teams navigating an increasingly complex threat landscape.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { icon: Shield, title: 'Practitioner-Led', desc: 'Written by security professionals, not marketers' },
                { icon: Zap, title: 'Hands-On Testing', desc: 'Every tool tested in real environments' },
                { icon: BookOpen, title: 'No Vendor Bias', desc: 'Independent reviews, no sponsored content' },
              ].map(({ icon: Icon, title, desc }) => (
                <div key={title} className="p-4 rounded-lg border border-border bg-card">
                  <Icon className="w-5 h-5 text-primary mb-3" />
                  <h3 className="font-semibold text-foreground text-sm mb-1">{title}</h3>
                  <p className="text-xs text-muted-foreground">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
