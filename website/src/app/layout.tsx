import type { Metadata } from 'next'
import './globals.css'
import { Nav } from '@/components/nav'
import { Footer } from '@/components/footer'

export const metadata: Metadata = {
  title: {
    default: 'Judah Security — Cyber Security Advisory, Consulting & Services',
    template: '%s | Judah Security',
  },
  description:
    'Practitioner-led cyber security research, tool evaluations, and whitepapers. Advisory, consulting and services from the Judah Security team.',
  keywords: ['cybersecurity', 'security consulting', 'penetration testing', 'vulnerability management', 'ASM', 'attack surface management', 'security advisory'],
  authors: [{ name: 'Judah Security' }],
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://judahsecurity.com',
    siteName: 'Judah Security',
    title: 'Judah Security — Cyber Security Advisory, Consulting & Services',
    description: 'Practitioner-led cyber security research, tool evaluations, and whitepapers.',
    images: [{ url: '/logo.png' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Judah Security',
    description: 'Practitioner-led cyber security research, tool evaluations, and whitepapers.',
  },
  icons: {
    icon: '/logo.png',
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
