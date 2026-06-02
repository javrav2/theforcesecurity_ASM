export type ToolCategory =
  | 'Attack Surface Management'
  | 'Vulnerability Management'
  | 'Penetration Testing'
  | 'SAST / DAST'
  | 'Threat Intelligence'
  | 'Identity & Access'
  | 'Cloud Security'
  | 'Network Security'
  | 'Endpoint Security'
  | 'Incident Response'
  | 'Red Teaming'
  | 'OSINT'

export type PricingModel = 'Free' | 'Freemium' | 'Open Source' | 'Commercial' | 'Enterprise'

export interface Tool {
  id: string
  name: string
  tagline: string
  description: string
  category: ToolCategory
  tags: string[]
  pricing: PricingModel
  url: string
  github?: string
  logo?: string
  featured?: boolean
  rating?: number
  lastReviewed?: string
}

export const TOOLS: Tool[] = [
  {
    id: 'projectdiscovery-nuclei',
    name: 'Nuclei',
    tagline: 'Fast, template-based vulnerability scanner',
    description:
      'Nuclei is used to send requests across targets based on a template, leading to zero false positives and providing fast scanning on a large number of hosts. It offers scanning for a variety of protocols including TCP, DNS, HTTP, SSL, and more.',
    category: 'Penetration Testing',
    tags: ['scanner', 'templates', 'open-source', 'cli'],
    pricing: 'Open Source',
    url: 'https://projectdiscovery.io/nuclei',
    github: 'https://github.com/projectdiscovery/nuclei',
    featured: true,
    rating: 5,
    lastReviewed: '2026-05-15',
  },
  {
    id: 'projectdiscovery-subfinder',
    name: 'Subfinder',
    tagline: 'Passive subdomain discovery at scale',
    description:
      'Subfinder is a subdomain discovery tool that discovers valid subdomains for websites using passive online sources. It has a simple modular architecture and is optimized for speed.',
    category: 'Attack Surface Management',
    tags: ['subdomain', 'recon', 'passive', 'open-source'],
    pricing: 'Open Source',
    url: 'https://projectdiscovery.io/subfinder',
    github: 'https://github.com/projectdiscovery/subfinder',
    featured: true,
    rating: 5,
    lastReviewed: '2026-05-10',
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    tagline: 'Static analysis at ludicrous speed',
    description:
      'Semgrep is a fast, open-source, static analysis tool for finding bugs and enforcing code standards. It supports 30+ languages and integrates with CI/CD pipelines.',
    category: 'SAST / DAST',
    tags: ['sast', 'static-analysis', 'ci-cd', 'code-security'],
    pricing: 'Freemium',
    url: 'https://semgrep.dev',
    github: 'https://github.com/semgrep/semgrep',
    featured: true,
    rating: 4,
    lastReviewed: '2026-04-22',
  },
  {
    id: 'burp-suite',
    name: 'Burp Suite',
    tagline: 'The leading web application security testing platform',
    description:
      'Burp Suite is a leading cybersecurity testing platform for web application security. It includes a manual testing toolkit, automated vulnerability scanner, and a catalog of web security research.',
    category: 'Penetration Testing',
    tags: ['web-app', 'proxy', 'scanner', 'manual-testing'],
    pricing: 'Freemium',
    url: 'https://portswigger.net/burp',
    featured: false,
    rating: 5,
    lastReviewed: '2026-03-18',
  },
  {
    id: 'shodan',
    name: 'Shodan',
    tagline: 'Search engine for internet-connected devices',
    description:
      'Shodan is the world\'s first search engine for internet-connected devices. Use it to discover open ports, services, and vulnerabilities across your attack surface.',
    category: 'Attack Surface Management',
    tags: ['search-engine', 'iot', 'exposure', 'passive-recon'],
    pricing: 'Freemium',
    url: 'https://shodan.io',
    featured: false,
    rating: 5,
    lastReviewed: '2026-04-01',
  },
  {
    id: 'metasploit',
    name: 'Metasploit Framework',
    tagline: 'The world\'s most used penetration testing framework',
    description:
      'Metasploit is the most widely used penetration testing framework in the world. It enables security teams to verify vulnerabilities, test security controls, and demonstrate actual business risk.',
    category: 'Penetration Testing',
    tags: ['exploitation', 'payloads', 'open-source', 'post-exploitation'],
    pricing: 'Open Source',
    url: 'https://metasploit.com',
    github: 'https://github.com/rapid7/metasploit-framework',
    featured: false,
    rating: 5,
    lastReviewed: '2026-02-28',
  },
  {
    id: 'nmap',
    name: 'Nmap',
    tagline: 'Network discovery and security auditing',
    description:
      'Nmap is a free and open source utility for network discovery and security auditing. It uses raw IP packets to determine what hosts are available, what services they are offering, and what OS they are running.',
    category: 'Network Security',
    tags: ['port-scanner', 'network-discovery', 'open-source', 'cli'],
    pricing: 'Open Source',
    url: 'https://nmap.org',
    github: 'https://github.com/nmap/nmap',
    featured: false,
    rating: 5,
    lastReviewed: '2026-01-15',
  },
  {
    id: 'wiz',
    name: 'Wiz',
    tagline: 'Cloud security platform for enterprises',
    description:
      'Wiz is a cloud security platform that provides full-stack visibility, enabling teams to identify and prioritize critical risks across multi-cloud environments without agents.',
    category: 'Cloud Security',
    tags: ['cloud', 'agentless', 'cspm', 'enterprise'],
    pricing: 'Enterprise',
    url: 'https://wiz.io',
    featured: false,
    rating: 4,
    lastReviewed: '2026-05-01',
  },
  {
    id: 'crowdstrike-falcon',
    name: 'CrowdStrike Falcon',
    tagline: 'AI-native cybersecurity platform',
    description:
      'CrowdStrike Falcon is a cloud-native endpoint protection platform that uses AI and machine learning to detect, prevent, and respond to threats in real time.',
    category: 'Endpoint Security',
    tags: ['edr', 'endpoint', 'ai', 'enterprise'],
    pricing: 'Enterprise',
    url: 'https://crowdstrike.com',
    featured: false,
    rating: 5,
    lastReviewed: '2026-04-10',
  },
  {
    id: 'maltego',
    name: 'Maltego',
    tagline: 'OSINT and graphical link analysis',
    description:
      'Maltego is an OSINT and graphical link analysis tool for gathering and connecting information for investigative tasks. It visualizes complex data relationships.',
    category: 'OSINT',
    tags: ['osint', 'graph', 'link-analysis', 'investigation'],
    pricing: 'Freemium',
    url: 'https://maltego.com',
    featured: false,
    rating: 4,
    lastReviewed: '2026-03-22',
  },
  {
    id: 'snyk',
    name: 'Snyk',
    tagline: 'Developer-first security for code, dependencies, and containers',
    description:
      'Snyk finds and automatically fixes vulnerabilities in your code, dependencies, containers, and infrastructure as code. Built for developers and integrated into DevSecOps pipelines.',
    category: 'SAST / DAST',
    tags: ['devsecops', 'sca', 'container-security', 'iac'],
    pricing: 'Freemium',
    url: 'https://snyk.io',
    featured: true,
    rating: 4,
    lastReviewed: '2026-04-18',
  },
  {
    id: 'recorded-future',
    name: 'Recorded Future',
    tagline: 'Intelligence-led cybersecurity',
    description:
      'Recorded Future is the world\'s largest intelligence company, providing real-time threat intelligence powered by machine learning and human analysts.',
    category: 'Threat Intelligence',
    tags: ['threat-intel', 'dark-web', 'ioc', 'enterprise'],
    pricing: 'Enterprise',
    url: 'https://recordedfuture.com',
    featured: false,
    rating: 5,
    lastReviewed: '2026-03-05',
  },
]

export const CATEGORIES: ToolCategory[] = [
  'Attack Surface Management',
  'Vulnerability Management',
  'Penetration Testing',
  'SAST / DAST',
  'Threat Intelligence',
  'Identity & Access',
  'Cloud Security',
  'Network Security',
  'Endpoint Security',
  'Incident Response',
  'Red Teaming',
  'OSINT',
]

export const PRICING_MODELS: PricingModel[] = [
  'Free',
  'Open Source',
  'Freemium',
  'Commercial',
  'Enterprise',
]

export function getToolById(id: string): Tool | undefined {
  return TOOLS.find((t) => t.id === id)
}

export function getFeaturedTools(): Tool[] {
  return TOOLS.filter((t) => t.featured)
}

export function getToolsByCategory(category: ToolCategory): Tool[] {
  return TOOLS.filter((t) => t.category === category)
}
