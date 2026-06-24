import fs from 'fs'
import path from 'path'
import matter from 'gray-matter'

const RESEARCH_DIR = path.join(process.cwd(), 'src/content/research')

export type ResearchType = 'Whitepaper' | 'Technical Report' | 'Tool Evaluation' | 'Field Guide' | 'Advisory'

export interface ResearchItem {
  slug: string
  title: string
  excerpt: string
  date: string
  author: string
  authorRole: string
  type: ResearchType
  tags: string[]
  readTime: number
  featured?: boolean
  downloadable?: boolean
  content: string
}

export type ResearchMeta = Omit<ResearchItem, 'content'>

function computeReadTime(content: string): number {
  return Math.max(1, Math.ceil(content.split(/\s+/).length / 200))
}

export function getAllResearch(): ResearchMeta[] {
  if (!fs.existsSync(RESEARCH_DIR)) return []

  const files = fs.readdirSync(RESEARCH_DIR).filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))

  const items = files.map((file) => {
    const slug = file.replace(/\.(mdx|md)$/, '')
    const raw = fs.readFileSync(path.join(RESEARCH_DIR, file), 'utf-8')
    const { data, content } = matter(raw)

    return {
      slug,
      title: data.title ?? 'Untitled',
      excerpt: data.excerpt ?? '',
      date: data.date ?? new Date().toISOString().split('T')[0],
      author: data.author ?? 'Judah Security',
      authorRole: data.authorRole ?? 'Security Researcher',
      type: (data.type ?? 'Technical Report') as ResearchType,
      tags: data.tags ?? [],
      readTime: data.readTime ?? computeReadTime(content),
      featured: data.featured ?? false,
      downloadable: data.downloadable ?? false,
    } satisfies ResearchMeta
  })

  return items.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
}

export function getResearchBySlug(slug: string): ResearchItem | null {
  const candidates = [
    path.join(RESEARCH_DIR, `${slug}.mdx`),
    path.join(RESEARCH_DIR, `${slug}.md`),
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
      author: data.author ?? 'Judah Security',
    authorRole: data.authorRole ?? 'Security Researcher',
    type: (data.type ?? 'Technical Report') as ResearchType,
    tags: data.tags ?? [],
    readTime: data.readTime ?? computeReadTime(content),
    featured: data.featured ?? false,
    downloadable: data.downloadable ?? false,
    content,
  }
}

export function getRecentResearch(count = 6): ResearchMeta[] {
  return getAllResearch().slice(0, count)
}

export function getFeaturedResearch(): ResearchMeta[] {
  return getAllResearch().filter((r) => r.featured)
}
