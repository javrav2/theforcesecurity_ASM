import Link from 'next/link'
import { Clock, ArrowRight } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import type { BlogPostMeta } from '@/lib/blog'

const CATEGORY_COLORS: Record<string, string> = {
  'Tool Review': 'text-primary border-primary/30 bg-primary/5',
  'Research': 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  'Tutorials': 'text-warning border-warning/30 bg-warning/5',
  'News': 'text-purple-400 border-purple-400/30 bg-purple-400/5',
}

interface BlogCardProps {
  post: BlogPostMeta
  featured?: boolean
}

export function BlogCard({ post, featured = false }: BlogCardProps) {
  const categoryColor = CATEGORY_COLORS[post.category] ?? 'text-muted-foreground border-border bg-accent/50'

  if (featured) {
    return (
      <Link href={`/blog/${post.slug}`} className="group block">
        <article className="rounded-xl border border-border bg-card p-6 transition-all duration-200 hover:border-primary/25 hover:bg-card/80 h-full">
          <div className="flex items-center gap-2 mb-4">
            <span className={cn('tag', categoryColor)}>{post.category}</span>
            <span className="tag text-muted-foreground border-border bg-transparent">
              Featured
            </span>
          </div>

          <h2 className="font-semibold text-foreground text-lg leading-snug mb-3 group-hover:text-primary transition-colors line-clamp-2">
            {post.title}
          </h2>

          <p className="text-sm text-muted-foreground leading-relaxed mb-4 line-clamp-3">
            {post.excerpt}
          </p>

          <div className="flex items-center justify-between mt-auto pt-4 border-t border-border">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center flex-shrink-0">
                <span className="text-xs font-bold text-primary">
                  {post.author.charAt(0)}
                </span>
              </div>
              <div>
                <p className="text-xs font-medium text-foreground">{post.author}</p>
                <p className="text-xs text-muted-foreground">{formatDate(post.date)}</p>
              </div>
            </div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock className="w-3 h-3" />
              {post.readTime}m
            </div>
          </div>
        </article>
      </Link>
    )
  }

  return (
    <Link href={`/blog/${post.slug}`} className="group block">
      <article className="flex gap-4 py-5 border-b border-border last:border-0 hover:bg-accent/20 -mx-3 px-3 rounded-lg transition-colors">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span className={cn('tag', categoryColor)}>{post.category}</span>
            <span className="text-xs text-muted-foreground">{formatDate(post.date)}</span>
          </div>
          <h3 className="font-medium text-foreground text-sm leading-snug mb-1 group-hover:text-primary transition-colors line-clamp-2">
            {post.title}
          </h3>
          <p className="text-xs text-muted-foreground line-clamp-1">{post.excerpt}</p>
        </div>
        <div className="flex items-center gap-1 text-xs text-muted-foreground flex-shrink-0">
          <Clock className="w-3 h-3" />
          {post.readTime}m
          <ArrowRight className="w-3 h-3 ml-1 opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </article>
    </Link>
  )
}
