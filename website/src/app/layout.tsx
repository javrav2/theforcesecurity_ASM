import type { Metadata } from 'next'
import './globals.css'
import { Nav } from '@/components/nav'
import { Footer } from '@/components/footer'

export const metadata: Metadata = {
  title: {
    default: 'The Force Security — Security Tools & Research',
    template: '%s | The Force Security',
  },
  description:
    'Discover, compare, and learn about the best cybersecurity tools. Expert reviews, guides, and research from The Force Security team.',
  keywords: ['cybersecurity', 'security tools', 'penetration testing', 'vulnerability management', 'ASM', 'attack surface management'],
  authors: [{ name: 'The Force Security' }],
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://theforcesecurity.io',
    siteName: 'The Force Security',
    title: 'The Force Security — Security Tools & Research',
    description: 'Discover, compare, and learn about the best cybersecurity tools.',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'The Force Security',
    description: 'Discover, compare, and learn about the best cybersecurity tools.',
  },
  icons: {
    icon: '/favicon.ico',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col">
        <Nav />
        <main className="flex-1">{children}</main>
        <Footer />
      </body>
    </html>
  )
}
