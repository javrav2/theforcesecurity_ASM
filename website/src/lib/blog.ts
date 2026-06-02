import fs from 'fs'
import path from 'path'
import matter from 'gray-matter'

const BLOG_DIR = path.join(process.cwd(), 'src/content/blog')

export interface BlogPost {
  slug: string
  title: string
  excerpt: string
  date: string
  author: string
  authorRole: string
  category: string
  tags: string[]
  readTime: number
  featured?: boolean
  coverImage?: string
  content: string
}

export interface BlogPostMeta extends Omit<BlogPost, 'content'> {}

function computeReadTime(content: string): number {
  const words = content.split(/\s+/).length
  return Math.max(1, Math.ceil(words / 200))
}

export function getAllPosts(): BlogPostMeta[] {
  if (!fs.existsSync(BLOG_DIR)) return []

  const files = fs.readdirSync(BLOG_DIR).filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))

  const posts = files.map((file) => {
    const slug = file.replace(/\.(mdx|md)$/, '')
    const raw = fs.readFileSync(path.join(BLOG_DIR, file), 'utf-8')
    const { data, content } = matter(raw)

    return {
      slug,
      title: data.title ?? 'Untitled',
      excerpt: data.excerpt ?? '',
      date: data.date ?? new Date().toISOString().split('T')[0],
      author: data.author ?? 'The Force Security',
      authorRole: data.authorRole ?? 'Security Researcher',
      category: data.category ?? 'Research',
      tags: data.tags ?? [],
      readTime: data.readTime ?? computeReadTime(content),
      featured: data.featured ?? false,
      coverImage: data.coverImage,
    } satisfies BlogPostMeta
  })

  return posts.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
}

export function getPostBySlug(slug: string): BlogPost | null {
  const candidates = [
    path.join(BLOG_DIR, `${slug}.mdx`),
    path.join(BLOG_DIR, `${slug}.md`),
  ]
  const filePath = candidates.find((p) => fs.existsSync(p))
  if (!filePath) return null

  const raw = fs.readFileSync(filePath, 'utf-8')
  const { data, content } = matter(raw)

  return {
    slug,
    title: data.title ?? 'Untitled',
    excerpt: data.excerpt ?? '',
    date: data.date ?? new Date().toISOString().split('T')[0],
    author: data.author ?? 'The Force Security',
    authorRole: data.authorRole ?? 'Security Researcher',
    category: data.category ?? 'Research',
    tags: data.tags ?? [],
    readTime: data.readTime ?? computeReadTime(content),
    featured: data.featured ?? false,
    coverImage: data.coverImage,
    content,
  }
}

export function getFeaturedPosts(): BlogPostMeta[] {
  return getAllPosts().filter((p) => p.featured).slice(0, 3)
}

export function getRecentPosts(count = 6): BlogPostMeta[] {
  return getAllPosts().slice(0, count)
}

export function getPostsByCategory(category: string): BlogPostMeta[] {
  return getAllPosts().filter((p) => p.category === category)
}
