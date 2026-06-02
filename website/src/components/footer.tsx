import Link from 'next/link'
import { Shield, Github, Twitter, Linkedin } from 'lucide-react'

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
    { href: '/blog?category=Tool+Review', label: 'Tool Reviews' },
    { href: '/blog?category=Research', label: 'Research' },
    { href: '/blog?category=Tutorials', label: 'Tutorials' },
  ],
  Company: [
    { href: '/#about', label: 'About' },
    { href: 'mailto:hello@theforcesecurity.io', label: 'Contact' },
  ],
}

export function Footer() {
  return (
    <footer className="border-t border-border bg-card/30 mt-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
          <div className="col-span-2 md:col-span-1">
            <Link href="/" className="flex items-center gap-2 mb-4">
              <div className="w-7 h-7 rounded-md bg-primary/10 border border-primary/30 flex items-center justify-center">
                <Shield className="w-3.5 h-3.5 text-primary" />
              </div>
              <span className="font-semibold text-sm">
                The Force<span className="text-primary">Security</span>
              </span>
            </Link>
            <p className="text-xs text-muted-foreground leading-relaxed mb-4">
              Expert security research and tool reviews for the modern security practitioner.
            </p>
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/theforcesecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
                aria-label="GitHub"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="https://twitter.com/theforcesec"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
                aria-label="Twitter"
              >
                <Twitter className="w-4 h-4" />
              </a>
              <a
                href="https://linkedin.com/company/theforcesecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
                aria-label="LinkedIn"
              >
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
                    <Link
                      href={link.href}
                      className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
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
            &copy; {new Date().getFullYear()} The Force Security. All rights reserved.
          </p>
          <p className="text-xs text-muted-foreground font-mono">
            theforcesecurity.io
          </p>
        </div>
      </div>
    </footer>
  )
}
