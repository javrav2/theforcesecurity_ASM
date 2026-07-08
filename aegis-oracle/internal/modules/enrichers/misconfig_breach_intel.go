package enrichers

import "strings"

// ── Misconfig Breach Intelligence ─────────────────────────────────────────────
//
// Many high-impact breaches are caused by misconfigurations and exposed
// services that have no CVE. This file maps non-CVE finding patterns
// (Nuclei template IDs, tags, port-finding titles) to breach risk scores
// for the OPES X component, grounded in historical breach data.
//
// Data sources:
//   - VCDB (Verizon VERIS Community Database) — breach action patterns
//     including "Misuse", "Hacking", "Use of stolen credentials"
//   - Mandiant M-Trends — initial access vectors from breach investigations
//   - CrowdStrike Global Threat Report — adversary-tracked initial access
//   - CISA Alerts — specific advisories for exposed services
//   - HackerOne public disclosures — web-facing misconfiguration impact
//
// Scoring aligns with the OPES X component hierarchy:
//
//	9.0 — breach-confirmed, mass-exploitation (matches VCDB/M-Trends evidence)
//	8.5 — strong exploitation evidence (CISA-alerted, documented attacker TTPs)
//	8.0 — known breach pattern (admin panels, cloud metadata)
//	7.5 — data exposure (directory listing, file disclosure)
//	7.0 — credential chain risk (debug endpoints, diagnostic APIs)
//	6.5 — generic misconfiguration (misconfig tag, no specific class)
//
// Note on KEV floor: X ≥ 9.0 triggers the OPES KEV floor override, placing
// the finding at Critical regardless of other components. This is intentional
// for exposed_remote_access, exposed_database_no_auth, and
// exposed_container_mgmt — their VCDB frequency justifies equivalent urgency.

// MisconfigBreachResult holds breach risk classification for a non-CVE finding.
type MisconfigBreachResult struct {
	Found     bool     `json:"found"`
	Class     string   `json:"class,omitempty"`
	Score     float64  `json:"score,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Rationale string   `json:"rationale,omitempty"`
}

// breachClassEntry describes one breach-cause category with its evidence
// backing and multi-signal match criteria.
type breachClassEntry struct {
	class     string
	score     float64
	sources   []string
	rationale string

	// Match criteria — any single satisfied criterion fires this class.
	// templatePrefixes: substring match on normalized templateID.
	// tagSets: any one tagSet fully satisfied (all tags in the set present).
	// textKeywords: any keyword present in the combined lower-case text.
	templatePrefixes []string
	tagSets          [][]string
	textKeywords     []string
}

// breachClasses is the priority-ordered list of breach class entries.
// The lookup walks this list and returns the first match. Higher-scoring
// (more specific) entries must come first to prevent a generic match
// from shadowing a specific one.
var breachClasses = []breachClassEntry{

	// ── 9.0: breach-confirmed, mass-exploitation (KEV floor triggers) ─────────

	{
		class:  "exposed_remote_access",
		score:  9.0,
		sources: []string{"vcdb_pattern", "cisa_alert_aa22_279a", "mandiant_mtrends_pattern"},
		rationale: "Exposed remote access services (RDP, VNC, Telnet, WinRM) are the #1 confirmed " +
			"ransomware initial access vector in VCDB across multiple DBIR years. CISA AA22-279A " +
			"specifically covers exposed RDP. Mandiant M-Trends consistently tracks these as a top " +
			"initial access vector for eCrime and ransomware operators.",
		templatePrefixes: []string{
			"rdp-", "xrdp", "vnc-", "telnet-", "winrm-",
			"citrix-gateway", "citrix-xenapp", "teamviewer", "anydesk",
		},
		tagSets: [][]string{
			{"rdp"}, {"vnc"}, {"telnet"}, {"winrm"},
		},
		textKeywords: []string{
			"rdp exposed", "rdp open", "rdp service",
			"port 3389", "3389/tcp",
			"vnc exposed", "vnc open", "port 5900", "5900/tcp",
			"telnet open", "port 23", "23/tcp",
			"winrm exposed", "port 5985", "port 5986",
		},
	},

	{
		class:  "exposed_database_no_auth",
		score:  9.0,
		sources: []string{"vcdb_pattern", "mandiant_mtrends_pattern"},
		rationale: "Unauthenticated databases (MongoDB, Redis, Elasticsearch, CouchDB) appear in " +
			"VCDB breach records as the root cause of mass data theft and extortion campaigns. " +
			"NoSQL databases exposed without authentication were the top data exposure root cause " +
			"in multiple DBIR editions. Redis without auth is a documented ransomware delivery path " +
			"via SLAVEOF/CONFIG SET attacks.",
		templatePrefixes: []string{
			"mongodb-", "redis-", "elasticsearch-", "couchdb-",
			"cassandra-", "memcached-", "influxdb-", "rethinkdb-",
			"aerospike-", "mssql-", "mysql-detect", "postgres-detect",
		},
		tagSets: [][]string{
			{"database", "exposure"},
			{"nosql", "exposure"},
			{"nosql", "misconfig"},
			{"database", "detect"},
		},
		textKeywords: []string{
			"mongodb exposed", "mongodb open", "unauthenticated mongodb",
			"redis exposed", "unauthenticated redis", "redis open",
			"elasticsearch open", "elasticsearch exposed",
			"port 27017", "27017/tcp",
			"port 6379", "6379/tcp",
			"port 9200", "9200/tcp",
			"port 5984", "5984/tcp",
			"port 11211", "11211/tcp",
			"mysql exposed", "postgres exposed", "mssql exposed",
			"port 3306", "3306/tcp", "port 5432", "5432/tcp", "port 1433", "1433/tcp",
		},
	},

	{
		class:  "exposed_container_mgmt",
		score:  9.0,
		sources: []string{"crowdstrike_gtr_pattern", "cisa_alert_aa22_154a", "vcdb_pattern"},
		rationale: "Exposed Kubernetes API servers, Docker daemons, and etcd endpoints are tracked " +
			"in CrowdStrike GTR as top initial access vectors for cryptomining, data theft, and " +
			"ransomware. CISA AA22-154A addresses exposed k8s APIs. An exposed Docker socket grants " +
			"root-equivalent access to the host via container escape.",
		templatePrefixes: []string{
			"kubernetes-", "k8s-", "docker-api", "docker-daemon",
			"etcd-", "kubelet-", "helm-", "rancher-", "portainer-",
		},
		tagSets: [][]string{
			{"kubernetes", "exposure"},
			{"docker", "exposure"},
			{"kubernetes", "misconfig"},
			{"k8s"},
			{"container", "exposure"},
		},
		textKeywords: []string{
			"kubernetes api", "k8s api", "kube-apiserver",
			"docker api exposed", "docker socket", "docker daemon",
			"etcd exposed", "kubelet api",
			"port 2375", "2375/tcp", "port 2376", "2376/tcp",
			"port 6443", "6443/tcp", "port 8443", "8443/tcp",
			"port 2379", "2379/tcp", "port 10250", "10250/tcp",
		},
	},

	// ── 8.5: strong exploitation evidence (CISA-alerted, documented TTPs) ─────

	{
		class:  "exposed_management_interface",
		score:  8.5,
		sources: []string{"mandiant_mtrends_pattern", "hacker_one_disclosures"},
		rationale: "Spring Boot Actuator /env, /heapdump, and /jolokia endpoints enable credential " +
			"extraction and RCE in documented breach chains. Mandiant M-Trends 2024 documents " +
			"management interface exposure as a top initial access facilitator. /heapdump produces " +
			"JVM heap dumps containing plaintext credentials. /jolokia enables JMX-based RCE via " +
			"MLET MBean loading. Server-status and phpinfo leak infrastructure details used for " +
			"targeted follow-on attacks.",
		templatePrefixes: []string{
			"spring-actuator", "spring-boot-actuator", "actuator-",
			"jolokia-", "heapdump", "laravel-debug-enabled",
			"django-debug-enabled", "rails-info-disclosure",
			"phpinfo-", "apache-server-status", "apache-server-info",
			"iis-debug",
		},
		tagSets: [][]string{
			{"spring", "exposure"},
			{"actuator"},
			{"java", "exposure", "misconfig"},
		},
		textKeywords: []string{
			"spring actuator", "actuator/env", "actuator/heapdump",
			"actuator/jolokia", "jolokia", "/env endpoint",
			"laravel debug", "django debug mode", "rails info",
			"phpinfo", "server-status", "apache server info",
		},
	},

	{
		class:  "default_credentials",
		score:  8.5,
		sources: []string{"vcdb_pattern", "cisa_alert_aa23_025a"},
		rationale: "Default or weak credentials on internet-accessible services are documented in " +
			"VCDB as 'Use of weak or default credentials' — a consistent DBIR action variety. " +
			"CISA AA23-025A specifically warns about default credentials on internet-exposed devices " +
			"and services. Automated credential-stuffing scanners continuously probe for default " +
			"logins, making any default credential surface rapidly exploitable.",
		templatePrefixes: []string{
			"default-login", "default-credentials", "default-password",
		},
		tagSets: [][]string{
			{"default-login"},
			{"default-credentials"},
			{"misconfig", "default-login"},
		},
		textKeywords: []string{
			"default credentials", "default password", "default login",
			"default admin", "weak credentials", "weak password",
			"admin/admin", "admin/password", "root/root",
		},
	},

	{
		class:  "exposed_vpn_gateway",
		score:  8.5,
		sources: []string{"mandiant_mtrends_pattern", "crowdstrike_gtr_pattern"},
		rationale: "VPN and remote gateway login panels (Citrix NetScaler, Fortinet, Pulse Secure, " +
			"Ivanti, Palo Alto, SonicWall) consistently rank as top initial access vectors in " +
			"Mandiant M-Trends and CrowdStrike GTR. Even without a specific CVE, an exposed login " +
			"panel is a high-value target for credential stuffing, password spraying, and exploit " +
			"chains. These gateways are the perimeter entry point for most ransomware operations.",
		templatePrefixes: []string{
			"citrix-netscaler", "citrix-gateway-detect",
			"pulse-secure-", "fortinet-", "palo-alto-globalprotect",
			"sonicwall-", "ivanti-", "checkpoint-vpn",
			"barracuda-vpn", "cisco-asa-", "juniper-sslvpn",
			"f5-big-ip-login",
		},
		tagSets: [][]string{
			{"vpn", "panel"},
			{"vpn", "misconfig"},
			{"gateway", "panel"},
		},
		textKeywords: []string{
			"citrix gateway", "fortinet login", "pulse secure login",
			"sonicwall vpn", "ivanti gateway", "vpn login panel",
			"globalprotect portal", "f5 bigip login",
		},
	},

	// ── 8.0: known breach patterns (panels, cloud metadata) ──────────────────

	{
		class:  "admin_panel_exposed",
		score:  8.0,
		sources: []string{"vcdb_pattern", "hacker_one_disclosures"},
		rationale: "Admin panels (phpMyAdmin, Webmin, Grafana, Jenkins, GitLab, SonarQube, Kibana, " +
			"Jupyter Notebook) without authentication or with weak auth are frequent breach " +
			"precursors in VCDB. Once an attacker reaches an admin panel, privilege escalation " +
			"and data access are straightforward. Jenkins can execute arbitrary code via pipelines; " +
			"Grafana exposes data sources and credentials.",
		templatePrefixes: []string{
			"phpmyadmin-", "webmin-", "grafana-", "jenkins-",
			"gitlab-", "sonarqube-", "kibana-", "jupyter-",
			"adminer-", "cockpit-", "traefik-dashboard",
			"openmediavault-", "plesk-", "cpanel-",
			"zabbix-", "nagios-", "icinga-",
		},
		tagSets: [][]string{
			{"panel", "exposure"},
			{"panel", "misconfig"},
		},
		textKeywords: []string{
			"phpmyadmin", "webmin panel", "grafana dashboard",
			"jenkins dashboard", "admin panel", "admin interface",
			"management console", "control panel",
		},
	},

	{
		class:  "cloud_metadata_exposed",
		score:  8.0,
		sources: []string{"mandiant_mtrends_pattern", "hacker_one_disclosures"},
		rationale: "IMDS (Instance Metadata Service) access and cloud credential exposure via SSRF " +
			"chains are documented breach paths in Mandiant M-Trends and numerous HackerOne " +
			"disclosures. AWS/GCP/Azure IMDS endpoints return IAM role credentials, service account " +
			"tokens, and user data scripts — all enabling lateral movement into cloud services. " +
			"Exposed metadata endpoints without IMDSv2 enforcement are a known SSRF escalation path.",
		templatePrefixes: []string{
			"aws-metadata-", "gcp-metadata-", "azure-metadata",
			"imds-", "cloud-metadata-",
		},
		tagSets: [][]string{
			{"cloud", "exposure"},
			{"aws", "exposure"},
			{"gcp", "exposure"},
			{"azure", "exposure"},
		},
		textKeywords: []string{
			"aws metadata", "ec2 metadata", "169.254.169.254",
			"imds exposed", "cloud metadata", "gcp metadata",
			"azure metadata", "instance metadata",
		},
	},

	// ── 7.5: data exposure breach patterns ────────────────────────────────────

	{
		class:  "directory_file_disclosure",
		score:  7.5,
		sources: []string{"vcdb_pattern"},
		rationale: "Directory listings, exposed .git repositories, .env files, backup archives, " +
			"and application logs are documented in VCDB data exposure events. While not direct " +
			"RCE, they expose credentials, API keys, database connection strings, and internal " +
			"infrastructure details routinely used in follow-on attacks. Exposed .git repositories " +
			"frequently contain secrets committed by developers.",
		templatePrefixes: []string{
			"directory-listing", "git-config", "git-exposure",
			"env-file-", "exposed-env", "backup-file",
			"log-exposure", "htpasswd-", "web-config-disclosure",
			"ds-store", "dwsync", "phpinfo",
		},
		tagSets: [][]string{
			{"listing", "exposure"},
			{"git", "exposure"},
			{"exposure", "file"},
			{"exposure", "config"},
		},
		textKeywords: []string{
			"directory listing", "index of /",
			".git exposed", ".git/config",
			".env exposed", ".env file",
			"backup file exposed", "log file exposed",
			"htpasswd exposed",
		},
	},

	// ── 7.0: credential chain risk (debug/diagnostic APIs) ───────────────────

	{
		class:  "debug_endpoint_exposed",
		score:  7.0,
		sources: []string{"mandiant_mtrends_pattern"},
		rationale: "Debug and diagnostic endpoints (Swagger UI, GraphQL introspection, Prometheus " +
			"metrics, unauthenticated health checks with verbose output) are documented in Mandiant " +
			"M-Trends as intermediate steps in credential harvesting chains. They disclose API " +
			"structure, internal service endpoints, environment details, and occasionally embedded " +
			"credentials in configuration objects.",
		templatePrefixes: []string{
			"swagger-", "graphql-", "prometheus-metrics",
			"openapi-", "api-docs-", "graphql-introspection",
		},
		tagSets: [][]string{
			{"exposure", "api"},
			{"swagger"},
			{"graphql", "exposure"},
			{"prometheus", "exposure"},
		},
		textKeywords: []string{
			"swagger ui", "graphql introspection", "prometheus metrics",
			"api documentation exposed", "openapi exposed",
		},
	},

	// ── 6.5: generic misconfiguration (any misconfig tag) ────────────────────

	{
		class:  "generic_misconfiguration",
		score:  6.5,
		sources: []string{"vcdb_pattern"},
		rationale: "Misconfiguration findings correlate with breach events in VCDB across multiple " +
			"categories. While a specific breach pattern cannot be determined from available " +
			"signals, misconfigurations on internet-facing assets represent meaningful exploitation " +
			"risk and should be investigated promptly.",
		templatePrefixes: []string{},
		tagSets: [][]string{
			{"misconfig"},
			{"misconfiguration"},
		},
		textKeywords: []string{},
	},
}

// LookupMisconfigBreachRisk classifies a non-CVE finding against historical
// breach data to produce a breach risk score for the OPES X component.
//
// Parameters:
//   - tags:       Nuclei/scanner tags (e.g. ["exposure", "spring", "misconfig"])
//   - templateID: Nuclei template identifier (e.g. "spring-actuator-env")
//   - title:      Finding title (e.g. "[Port 3389/tcp] RDP Service Exposed")
//   - description: Finding description or evidence text
//
// Returns Found=false (Score=0) when no breach class pattern matches.
// When multiple patterns match, the highest-scoring class is returned.
func LookupMisconfigBreachRisk(tags []string, templateID, title, description string) MisconfigBreachResult {
	// Normalize inputs for case-insensitive matching.
	normTemplate := strings.ToLower(strings.TrimSpace(templateID))
	normText := strings.ToLower(title + " " + description)

	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[strings.ToLower(strings.TrimSpace(t))] = true
	}

	best := MisconfigBreachResult{}

	for _, entry := range breachClasses {
		if !matchesEntry(entry, normTemplate, normText, tagSet) {
			continue
		}
		if !best.Found || entry.score > best.Score {
			best = MisconfigBreachResult{
				Found:     true,
				Class:     entry.class,
				Score:     entry.score,
				Sources:   entry.sources,
				Rationale: entry.rationale,
			}
		}
		// Since breachClasses is ordered from highest to lowest score,
		// the first match at the current tier wins. Keep scanning to
		// allow a higher-scored entry later in the list to take precedence
		// if it also matches (though list ordering already handles this).
	}
	return best
}

// matchesEntry returns true when any of the entry's match criteria is satisfied.
func matchesEntry(e breachClassEntry, normTemplate, normText string, tags map[string]bool) bool {
	// Check template ID prefixes.
	if normTemplate != "" {
		for _, prefix := range e.templatePrefixes {
			if strings.Contains(normTemplate, prefix) {
				return true
			}
		}
	}
	// Check tag sets (all tags in any one set must be present).
	for _, tagSet := range e.tagSets {
		allPresent := true
		for _, required := range tagSet {
			if !tags[required] {
				allPresent = false
				break
			}
		}
		if allPresent && len(tagSet) > 0 {
			return true
		}
	}
	// Check text keywords.
	for _, kw := range e.textKeywords {
		if strings.Contains(normText, kw) {
			return true
		}
	}
	return false
}
