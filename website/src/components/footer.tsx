import Link from 'next/link'
import Image from 'next/image'
import { Github, Twitter, Linkedin } from 'lucide-react'

const FOOTER_LINKS = {
  Tools: [
    { href: '/tools?category=Attack+Surface+Management', label: 'ASM Tools' },
    { href: '/tools?category=Penetration+Testing', label: 'Pen Testing' },
    { href: '/tools?category=SAST+%2F+DAST', label: 'SAST / DAST' },
    { href: '/tools?category=Threat+Intelligence', label: 'Threat Intel' },
    { href: '/tools?category=OSINT', label: 'OSINT' },
  ],
  Content: [
    { href: '/blog', label: 'Blog' },
    { href: '/research', label: 'Research' },
    { href: '/blog?category=Tool+Review', label: 'Tool Reviews' },
    { href: '/blog?category=Tutorials', label: 'Tutorials' },
  ],
  Company: [
    { href: '/#about', label: 'About' },
    { href: 'mailto:hello@judahsecurity.com', label: 'Contact' },
  ],
}

export function Footer() {
  return (
    <footer className="border-t border-border bg-card/30 mt-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
          <div className="col-span-2 md:col-span-1">
            <Link href="/" className="flex items-center gap-2.5 mb-4">
              <Image
                src="/logo.png"
                alt="Judah Security"
                width={32}
                height={32}
                className="rounded object-contain"
              />
              <div className="flex flex-col leading-none">
                <span className="text-xs font-bold text-foreground tracking-widest uppercase">
                  Judah Security
                </span>
                <span className="text-[9px] text-muted-foreground tracking-wider uppercase font-mono">
                  Cyber Security
                </span>
              </div>
            </Link>
            <p className="text-xs text-muted-foreground leading-relaxed mb-4">
              Cyber security advisory, consulting & services. Practitioner-led research and tool evaluations.
            </p>
            <div className="flex items-center gap-3">
              <a href="https://github.com/judahsecurity" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors" aria-label="GitHub">
                <Github className="w-4 h-4" />
              </a>
              <a href="https://twitter.com/judahsecurity" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors" aria-label="Twitter">
                <Twitter className="w-4 h-4" />
              </a>
              <a href="https://linkedin.com/company/judahsecurity" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors" aria-label="LinkedIn">
                <Linkedin className="w-4 h-4" />
              </a>
            </div>
          </div>

          {Object.entries(FOOTER_LINKS).map(([section, links]) => (
            <div key={section}>
              <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-4">
                {section}
              </h3>
              <ul className="space-y-2.5">
                {links.map((link) => (
                  <li key={link.href}>
                    <Link href={link.href} className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="pt-6 border-t border-border flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-muted-foreground">
            &copy; {new Date().getFullYear()} Judah Security. All rights reserved.
          </p>
          <p className="text-xs text-muted-foreground font-mono">
            judahsecurity.com
          </p>
        </div>
      </div>
    </footer>
  )
}
