import Link from 'next/link'
import Image from 'next/image'
import { ArrowRight, Download, ChevronRight, Shield, Eye, Target, FileText, Users, BookOpen } from 'lucide-react'
import { getAllResearch } from '@/lib/research'
import { getRecentPosts } from '@/lib/blog'
import { formatDate } from '@/lib/utils'

const SERVICES = [
  {
    icon: Eye,
    name: 'Attack Surface Management',
    description: 'Continuous discovery of every internet-facing asset you own -- including the ones you forgot about. We see your organization the way attackers do.',
  },
  {
    icon: Target,
    name: 'Penetration Testing',
    description: 'Adversary-minded assessments that prove exploitability, not just exposure. Red team engagements, web application testing, and infrastructure assessments.',
  },
  {
    icon: Shield,
    name: 'Security Advisory',
    description: 'Executive and technical guidance for teams that need clear priorities and decisive action. We translate security risk into business language.',
  },
  {
    icon: FileText,
    name: 'Vulnerability Management',
    description: 'Program design and operational support to help your team identify, prioritize, and remediate vulnerabilities at the pace your business demands.',
  },
  {
    icon: Users,
    name: 'Incident Response',
    description: 'When something goes wrong, time is the variable that matters most. We help organizations prepare, respond, and recover from security incidents.',
  },
  {
    icon: BookOpen,
    name: 'Security Awareness',
    description: 'Your people are both your greatest risk and your greatest defense. We build programs that turn awareness into measurable behavior change.',
  },
]

export default function HomePage() {
  const research = getAllResearch().slice(0, 3)
  const posts = getRecentPosts(3)

  return (
    <div>

      {/* HERO */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="absolute inset-0 dot-grid opacity-40 pointer-events-none" />
        <div className="absolute inset-0 bg-gradient-to-b from-background/0 via-background/0 to-background pointer-events-none" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 md:py-36">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">

            <div>
              <p className="text-xs font-mono text-primary uppercase tracking-widest mb-6">
                Cyber Security Advisory &middot; Consulting &middot; Services
              </p>

              <h1 className="text-5xl md:text-6xl font-bold text-foreground leading-tight tracking-tight mb-6">
                We don&apos;t wait<br />
                <span className="text-primary glow-blue">for the attack.</span>
              </h1>

              <div className="rule" />

              <p className="text-lg text-muted-foreground leading-relaxed mb-10 max-w-lg">
                Judah Security helps organizations identify, understand, and eliminate
                risk before attackers exploit it. Continuous visibility, offensive
                validation, and clear advisory built for decisive security teams.
              </p>

              <div className="flex flex-wrap gap-4">
                <Link
                  href="mailto:hello@judahsecurity.com"
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 transition-colors"
                >
                  Talk to Our Team
                  <ArrowRight className="w-4 h-4" />
                </Link>
                <Link
                  href="/research"
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-border text-foreground text-sm font-medium hover:bg-accent transition-colors"
                >
                  Read Research
                </Link>
              </div>
            </div>

            <div className="flex items-center justify-center lg:justify-end">
              <div className="relative">
                <div className="absolute inset-0 rounded-full bg-primary/10 blur-3xl scale-110" />
                <Image
                  src="/logo.png"
                  alt="Judah Security"
                  width={340}
                  height={340}
                  className="relative object-contain drop-shadow-2xl"
                  priority
                />
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* MISSION */}
      <section className="border-b border-border bg-card/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="max-w-3xl">
            <p className="text-xs font-mono text-primary uppercase tracking-widest mb-4">Why Judah Security</p>
            <h2 className="text-3xl font-bold text-foreground leading-tight mb-5">
              Strength. Vigilance. Leadership. Triumph.
            </h2>
            <p className="text-muted-foreground leading-relaxed text-base mb-5">
              The lion is the symbol of vigilance and decisive action -- the posture every
              security program needs. Most organizations find out about their exposures when
              an attacker tells them. We find them first.
            </p>
            <p className="text-muted-foreground leading-relaxed text-base">
              Our team combines offensive security expertise with operational advisory to give
              you both the intelligence to understand your risk and the roadmap to eliminate it.
              No vendor bias. No checkbox security. Clear findings, validated risk, decisive next steps.
            </p>
          </div>
        </div>
      </section>

      {/* SERVICES */}
      <section id="services" className="border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="flex items-end justify-between mb-12">
            <div>
              <p className="text-xs font-mono text-primary uppercase tracking-widest mb-3">Services</p>
              <h2 className="text-3xl font-bold text-foreground">
                Your single point of contact<br className="hidden sm:block" /> for cyber security expertise.
              </h2>
            </div>
            <Link
              href="mailto:hello@judahsecurity.com"
              className="hidden md:flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 font-medium transition-colors"
            >
              Engage Judah <ChevronRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-border rounded-xl overflow-hidden">
            {SERVICES.map((service) => {
              const Icon = service.icon
              return (
                <div key={service.name} className="bg-background p-7 hover:bg-card/60 transition-colors group">
                  <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center mb-5 group-hover:bg-primary/20 transition-colors">
                    <Icon className="w-4 h-4 text-primary" />
                  </div>
                  <h3 className="font-semibold text-foreground text-sm mb-2 leading-snug">{service.name}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{service.description}</p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* RESEARCH */}
      <section className="border-b border-border bg-card/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="flex items-end justify-between mb-12">
            <div>
              <p className="text-xs font-mono text-primary uppercase tracking-widest mb-3">Research</p>
              <h2 className="text-3xl font-bold text-foreground">
                Whitepapers &amp; technical reports<br className="hidden sm:block" /> written by practitioners.
              </h2>
            </div>
            <Link href="/research" className="hidden md:flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 font-medium transition-colors">
              All research <ChevronRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {research.map((item) => (
              <div key={item.slug} className="flex flex-col rounded-xl border border-border bg-card p-6 hover:border-primary/30 transition-colors group">
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-mono text-primary uppercase tracking-wider">{item.type}</span>
                  {item.downloadable && (
                    <span className="flex items-center gap-1 text-xs text-muted-foreground/60">
                      <Download className="w-3 h-3" />PDF
                    </span>
                  )}
                </div>
                <h3 className="font-semibold text-foreground text-sm leading-snug mb-3 group-hover:text-primary transition-colors flex-1">
                  {item.title}
                </h3>
                <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 mb-5">
                  {item.excerpt}
                </p>
                <div className="flex items-center justify-between pt-4 border-t border-border mt-auto">
                  <span className="text-xs text-muted-foreground/60 font-mono">{formatDate(item.date)}</span>
                  <Link href={`/research/${item.slug}`} className="text-xs text-primary hover:text-primary/80 font-medium transition-colors flex items-center gap-1">
                    Read <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-8 text-center">
            <Link href="/research" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
              View all research &amp; whitepapers <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      {/* BLOG */}
      <section className="border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="flex items-end justify-between mb-10">
            <div>
              <p className="text-xs font-mono text-primary uppercase tracking-widest mb-3">Blog</p>
              <h2 className="text-3xl font-bold text-foreground">Latest from the field.</h2>
            </div>
            <Link href="/blog" className="hidden md:flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 font-medium transition-colors">
              All posts <ChevronRight className="w-4 h-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {posts.map((post) => (
              <Link key={post.slug} href={`/blog/${post.slug}`} className="group block rounded-xl border border-border bg-card p-6 hover:border-primary/30 transition-colors">
                <p className="text-xs font-mono text-muted-foreground/60 mb-3">{formatDate(post.date)}</p>
                <h3 className="font-semibold text-foreground text-sm leading-snug mb-3 group-hover:text-primary transition-colors line-clamp-2">
                  {post.title}
                </h3>
                <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 mb-4">
                  {post.excerpt}
                </p>
                <span className="text-xs text-primary font-medium flex items-center gap-1">
                  Read more <ArrowRight className="w-3 h-3" />
                </span>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ABOUT */}
      <section id="about" className="border-b border-border bg-card/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-start">
            <div>
              <p className="text-xs font-mono text-primary uppercase tracking-widest mb-4">About</p>
              <h2 className="text-3xl font-bold text-foreground mb-6">
                Practitioner-led.<br />Operationally grounded.
              </h2>
              <p className="text-muted-foreground leading-relaxed mb-4 text-base">
                Judah Security is an offensive security and advisory firm. We build and operate
                security infrastructure, conduct penetration tests, and publish what we learn.
                Our public research is practitioner-written and operationally grounded.
              </p>
              <p className="text-muted-foreground leading-relaxed mb-8 text-base">
                When we say a tool works or a technique is effective, it is because we have
                validated it against real environments -- not because a vendor paid us to say so.
              </p>
              <Link
                href="mailto:hello@judahsecurity.com"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors"
              >
                Start a Conversation <ArrowRight className="w-4 h-4" />
              </Link>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {[
                { label: 'Vigilant by default', desc: 'We continuously look for the exposures attackers can reach before your team knows they exist.' },
                { label: 'Offensive by design', desc: 'We validate risk through exploitation-minded testing -- not theoretical analysis alone.' },
                { label: 'Decisive in delivery', desc: 'We turn findings into clear priorities that both security leaders and engineers can act on immediately.' },
                { label: 'No vendor bias', desc: 'We do not accept payment for tool placements or sponsored content. Our recommendations are earned, not bought.' },
              ].map((item) => (
                <div key={item.label} className="flex gap-4 p-5 rounded-xl border border-border bg-card hover:border-primary/20 transition-colors">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary mt-2 flex-shrink-0" />
                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-1">{item.label}</h3>
                    <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="rounded-2xl border border-primary/20 bg-primary/5 px-8 md:px-16 py-14 text-center">
            <p className="text-xs font-mono text-primary uppercase tracking-widest mb-4">Ready to work together?</p>
            <h2 className="text-3xl md:text-4xl font-bold text-foreground mb-5">
              Let&apos;s find your exposures<br className="hidden sm:block" /> before attackers do.
            </h2>
            <p className="text-muted-foreground text-base max-w-xl mx-auto mb-8">
              Whether you need a one-time assessment or an ongoing security partner,
              we are ready to help. Reach out and let us talk about what you are defending.
            </p>
            <Link
              href="mailto:hello@judahsecurity.com"
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-lg bg-primary text-primary-foreground font-semibold text-sm hover:bg-primary/90 transition-colors"
            >
              Talk to Our Team <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

    </div>
  )
}
