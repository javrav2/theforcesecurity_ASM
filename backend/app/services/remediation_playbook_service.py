"""
Remediation Playbook Service

Provides structured remediation guidance for security findings including:
- Step-by-step remediation instructions
- Priority levels based on risk
- Estimated effort for remediation
- Verification steps to confirm fix
- Required access/permissions
- Related resources and references
"""

import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RemediationPriority(str, Enum):
    """Priority level for remediation."""
    CRITICAL = "critical"  # Fix immediately - active exploitation risk
    HIGH = "high"          # Fix within 24-48 hours
    MEDIUM = "medium"      # Fix within 1-2 weeks
    LOW = "low"            # Fix when convenient
    INFORMATIONAL = "informational"  # No action required, awareness only


class RemediationEffort(str, Enum):
    """Estimated effort to remediate."""
    MINIMAL = "minimal"      # < 30 minutes, simple config change
    LOW = "low"              # 1-2 hours, straightforward fix
    MEDIUM = "medium"        # Half day to full day
    HIGH = "high"            # Multiple days, may need change window
    SIGNIFICANT = "significant"  # Week+, architectural changes needed


class RequiredAccess(str, Enum):
    """Access level required for remediation."""
    READ_ONLY = "read_only"           # View configs
    OPERATOR = "operator"             # Basic operational changes
    ADMIN = "admin"                   # Administrative access
    INFRASTRUCTURE = "infrastructure"  # Cloud/infra access
    SECURITY_TEAM = "security_team"    # Security-specific tools


@dataclass
class RemediationStep:
    """A single remediation step."""
    order: int
    title: str
    description: str
    command: Optional[str] = None  # CLI command if applicable
    code_snippet: Optional[str] = None  # Code example if applicable
    notes: Optional[str] = None  # Additional notes/warnings


@dataclass
class VerificationStep:
    """A step to verify remediation was successful."""
    order: int
    description: str
    expected_result: str
    command: Optional[str] = None  # Command to run for verification
    automated: bool = False  # Can be automated via re-scan


@dataclass
class RemediationPlaybook:
    """Complete remediation playbook for a finding type."""
    id: str  # Unique playbook identifier
    title: str
    summary: str  # Brief summary of what needs to be done
    priority: RemediationPriority
    effort: RemediationEffort
    estimated_time: str  # Human-readable estimate (e.g., "30 minutes", "2-4 hours")
    required_access: List[RequiredAccess]
    
    # Detailed remediation steps
    steps: List[RemediationStep]
    
    # Verification steps
    verification: List[VerificationStep]
    
    # Additional context
    impact_if_not_fixed: str
    common_mistakes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    related_cwe: Optional[str] = None
    related_cve: List[str] = field(default_factory=list)
    
    # Tags for categorization
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert playbook to dictionary for API response."""
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "priority": self.priority.value,
            "effort": self.effort.value,
            "estimated_time": self.estimated_time,
            "required_access": [a.value for a in self.required_access],
            "steps": [
                {
                    "order": s.order,
                    "title": s.title,
                    "description": s.description,
                    "command": s.command,
                    "code_snippet": s.code_snippet,
                    "notes": s.notes,
                }
                for s in self.steps
            ],
            "verification": [
                {
                    "order": v.order,
                    "description": v.description,
                    "expected_result": v.expected_result,
                    "command": v.command,
                    "automated": v.automated,
                }
                for v in self.verification
            ],
            "impact_if_not_fixed": self.impact_if_not_fixed,
            "common_mistakes": self.common_mistakes,
            "references": self.references,
            "related_cwe": self.related_cwe,
            "related_cve": self.related_cve,
            "tags": self.tags,
        }


# =============================================================================
# REMEDIATION PLAYBOOKS DATABASE
# =============================================================================

REMEDIATION_PLAYBOOKS: Dict[str, RemediationPlaybook] = {}


def _register_playbook(playbook: RemediationPlaybook):
    """Register a playbook in the database."""
    REMEDIATION_PLAYBOOKS[playbook.id] = playbook


# -----------------------------------------------------------------------------
# REMOTE ACCESS PLAYBOOKS
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="exposed-ssh",
    title="Secure Exposed SSH Service",
    summary="Restrict SSH access and implement security hardening to prevent brute-force attacks.",
    priority=RemediationPriority.MEDIUM,
    effort=RemediationEffort.LOW,
    estimated_time="1-2 hours",
    required_access=[RequiredAccess.ADMIN, RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="Implement IP-based access restrictions",
            description="Configure firewall rules to allow SSH only from trusted IP ranges (office, VPN).",
            command="# AWS Security Group example:\naws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 10.0.0.0/8",
            notes="Document all allowed IP ranges for future reference."
        ),
        RemediationStep(
            order=2,
            title="Disable password authentication",
            description="Configure SSH to only allow key-based authentication.",
            command="# Edit /etc/ssh/sshd_config:\nPasswordAuthentication no\nPubkeyAuthentication yes\n\n# Then restart SSH:\nsudo systemctl restart sshd",
            notes="Ensure you have key-based access configured before disabling passwords!"
        ),
        RemediationStep(
            order=3,
            title="Install fail2ban for brute-force protection",
            description="Install and configure fail2ban to automatically block repeated failed login attempts.",
            command="sudo apt install fail2ban\nsudo systemctl enable fail2ban\nsudo systemctl start fail2ban"
        ),
        RemediationStep(
            order=4,
            title="Consider using a bastion host or VPN",
            description="For production environments, route all SSH through a dedicated bastion host or require VPN connection first.",
            notes="This adds defense-in-depth and centralizes access logging."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify SSH is not accessible from unauthorized IPs",
            expected_result="Connection refused or timeout from non-allowed IPs",
            command="ssh -o ConnectTimeout=5 user@target-ip",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm password authentication is disabled",
            expected_result="Permission denied (publickey) when trying password auth",
            command="ssh -o PreferredAuthentications=password user@target-ip"
        ),
        VerificationStep(
            order=3,
            description="Verify fail2ban is active",
            expected_result="fail2ban service running with SSH jail active",
            command="sudo fail2ban-client status sshd"
        ),
    ],
    impact_if_not_fixed="Exposed SSH services are primary targets for automated brute-force attacks and credential stuffing. Successful compromise leads to full server access.",
    common_mistakes=[
        "Forgetting to add your own IP before restricting access (locking yourself out)",
        "Not testing key-based auth before disabling passwords",
        "Using weak SSH keys (use ED25519 or RSA 4096-bit)"
    ],
    references=[
        "https://www.ssh.com/academy/ssh/sshd_config",
        "https://www.fail2ban.org/wiki/index.php/Main_Page",
    ],
    related_cwe="CWE-284",
    tags=["remote-access", "ssh", "authentication", "network-security"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-rdp",
    title="Secure Exposed RDP Service",
    summary="RDP exposed to internet is a critical risk - implement VPN/gateway access and enable NLA immediately.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-4 hours",
    required_access=[RequiredAccess.ADMIN, RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="Block RDP from internet immediately",
            description="Add firewall rule to block port 3389 from public internet while you implement proper access.",
            command="# AWS Security Group - remove 0.0.0.0/0 rule for port 3389\naws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr 0.0.0.0/0",
            notes="URGENT: Do this first to stop active exploitation attempts."
        ),
        RemediationStep(
            order=2,
            title="Enable Network Level Authentication (NLA)",
            description="NLA requires authentication before the RDP session is established, blocking many attacks.",
            command="# PowerShell:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
        ),
        RemediationStep(
            order=3,
            title="Implement VPN or RD Gateway",
            description="Set up Azure AD Application Proxy, Windows RD Gateway, or require VPN connection for RDP access.",
            notes="This is the most important long-term fix. Direct RDP should never be exposed."
        ),
        RemediationStep(
            order=4,
            title="Enable account lockout policies",
            description="Configure account lockout after failed login attempts to prevent brute-force.",
            command="# Group Policy path:\n# Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy\n# Set: Account lockout threshold = 5 attempts"
        ),
        RemediationStep(
            order=5,
            title="Ensure systems are patched",
            description="Apply all Windows security updates, especially for RDP vulnerabilities like BlueKeep (CVE-2019-0708).",
            command="# Check for updates:\nGet-WindowsUpdate\n\n# Or use Windows Update"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify RDP is not accessible from internet",
            expected_result="Connection refused or timeout from public internet",
            command="nmap -p 3389 target-ip",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm NLA is enabled",
            expected_result="UserAuthentication = 1",
            command="Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication'"
        ),
        VerificationStep(
            order=3,
            description="Test RDP access works via VPN/Gateway only",
            expected_result="RDP accessible only after VPN connection",
            automated=False
        ),
    ],
    impact_if_not_fixed="Exposed RDP is actively exploited by ransomware gangs. BlueKeep and related vulnerabilities allow unauthenticated remote code execution. This is a top vector for ransomware attacks.",
    common_mistakes=[
        "Changing RDP port instead of blocking it (security through obscurity doesn't work)",
        "Forgetting to set up alternative access before blocking RDP",
        "Not patching for BlueKeep and related CVEs"
    ],
    references=[
        "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations",
        "https://www.cisa.gov/uscert/ncas/alerts/aa19-168a",
    ],
    related_cwe="CWE-284",
    related_cve=["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
    tags=["remote-access", "rdp", "windows", "ransomware-vector", "critical-exposure"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-telnet",
    title="Disable Exposed Telnet Service",
    summary="Telnet transmits all data in cleartext - disable immediately and replace with SSH.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MINIMAL,
    estimated_time="30 minutes",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Disable Telnet service",
            description="Stop and disable the Telnet service on the target system.",
            command="# Linux:\nsudo systemctl stop telnet.socket\nsudo systemctl disable telnet.socket\n\n# Or remove:\nsudo apt remove telnetd"
        ),
        RemediationStep(
            order=2,
            title="Enable SSH if not already available",
            description="Ensure SSH is installed and configured as the replacement.",
            command="sudo apt install openssh-server\nsudo systemctl enable ssh\nsudo systemctl start ssh"
        ),
        RemediationStep(
            order=3,
            title="Update access credentials",
            description="Since Telnet may have exposed credentials, rotate passwords for any accounts that used Telnet.",
            notes="Assume any credentials used over Telnet have been compromised."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify Telnet port is closed",
            expected_result="Port 23 closed or filtered",
            command="nmap -p 23 target-ip",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm SSH is working as replacement",
            expected_result="SSH connection successful",
            command="ssh user@target-ip"
        ),
    ],
    impact_if_not_fixed="All Telnet traffic including usernames and passwords is transmitted in cleartext. Anyone on the network path can capture credentials.",
    common_mistakes=[
        "Leaving Telnet enabled 'just in case'",
        "Not rotating credentials that were used over Telnet"
    ],
    references=[
        "https://www.ssh.com/academy/ssh/telnet",
    ],
    related_cwe="CWE-319",
    tags=["remote-access", "telnet", "cleartext", "deprecated"],
))

# -----------------------------------------------------------------------------
# DATABASE EXPOSURE PLAYBOOKS
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="exposed-mysql",
    title="Secure Exposed MySQL Database",
    summary="Block public MySQL access and implement proper security controls.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-4 hours",
    required_access=[RequiredAccess.ADMIN, RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="Block MySQL from internet immediately",
            description="Add firewall rules to block port 3306 from public access.",
            command="# AWS Security Group:\naws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3306 --cidr 0.0.0.0/0"
        ),
        RemediationStep(
            order=2,
            title="Bind MySQL to localhost or specific IPs",
            description="Configure MySQL to only listen on internal interfaces.",
            command="# Edit /etc/mysql/mysql.conf.d/mysqld.cnf:\nbind-address = 127.0.0.1\n\n# Or for specific internal IP:\nbind-address = 10.0.1.5\n\nsudo systemctl restart mysql"
        ),
        RemediationStep(
            order=3,
            title="Disable remote root login",
            description="Ensure root can only connect from localhost.",
            command="mysql -u root -p\nDELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');\nFLUSH PRIVILEGES;"
        ),
        RemediationStep(
            order=4,
            title="Enable SSL/TLS for connections",
            description="Configure MySQL to require encrypted connections.",
            command="# In my.cnf:\n[mysqld]\nrequire_secure_transport = ON\nssl-ca = /path/to/ca.pem\nssl-cert = /path/to/server-cert.pem\nssl-key = /path/to/server-key.pem"
        ),
        RemediationStep(
            order=5,
            title="Review and rotate credentials",
            description="Change all database passwords and review user privileges.",
            command="ALTER USER 'username'@'host' IDENTIFIED BY 'new_strong_password';\nFLUSH PRIVILEGES;"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify MySQL is not accessible from internet",
            expected_result="Connection refused from public IPs",
            command="mysql -h target-ip -u root -p",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm bind address is set correctly",
            expected_result="MySQL listening on localhost or internal IP only",
            command="sudo netstat -tlnp | grep 3306"
        ),
    ],
    impact_if_not_fixed="Exposed databases are primary targets for data theft, ransomware, and crypto mining. Attackers actively scan for exposed MySQL instances.",
    common_mistakes=[
        "Only blocking at firewall but leaving MySQL bound to 0.0.0.0",
        "Using weak passwords for database users",
        "Granting excessive privileges (e.g., GRANT ALL)"
    ],
    references=[
        "https://dev.mysql.com/doc/refman/8.0/en/security.html",
        "https://www.shodan.io/search?query=mysql",
    ],
    related_cwe="CWE-284",
    tags=["database", "mysql", "data-exposure", "critical"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-redis",
    title="Secure Exposed Redis Instance",
    summary="Redis often runs without authentication - enable password and restrict access immediately.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.LOW,
    estimated_time="1 hour",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Block Redis from internet",
            description="Immediately restrict Redis port 6379 at the firewall.",
            command="# iptables:\nsudo iptables -A INPUT -p tcp --dport 6379 -s 0.0.0.0/0 -j DROP\n\n# Or AWS Security Group"
        ),
        RemediationStep(
            order=2,
            title="Bind Redis to localhost",
            description="Configure Redis to only listen on localhost.",
            command="# Edit /etc/redis/redis.conf:\nbind 127.0.0.1\n\nsudo systemctl restart redis"
        ),
        RemediationStep(
            order=3,
            title="Enable authentication",
            description="Set a strong password for Redis access.",
            command="# Edit /etc/redis/redis.conf:\nrequirepass your_very_strong_password_here\n\nsudo systemctl restart redis"
        ),
        RemediationStep(
            order=4,
            title="Disable dangerous commands",
            description="Rename or disable commands that could be used for RCE.",
            command="# In redis.conf:\nrename-command CONFIG \"\"\nrename-command EVAL \"\"\nrename-command FLUSHALL \"\"\nrename-command DEBUG \"\""
        ),
        RemediationStep(
            order=5,
            title="Check for compromise indicators",
            description="Look for unauthorized SSH keys or cron jobs that may have been added.",
            command="# Check for unauthorized SSH keys:\ncat ~/.ssh/authorized_keys\n\n# Check cron jobs:\ncrontab -l\nls -la /etc/cron.d/"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify Redis is not accessible from internet",
            expected_result="Connection refused",
            command="redis-cli -h target-ip ping",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm authentication is required",
            expected_result="NOAUTH Authentication required",
            command="redis-cli ping"
        ),
    ],
    impact_if_not_fixed="Exposed Redis without authentication allows attackers to write arbitrary files to the server, commonly used to add SSH keys for persistent access or deploy cryptominers.",
    common_mistakes=[
        "Using default or weak Redis password",
        "Not checking if system was already compromised before securing",
        "Forgetting to update application connection strings with new password"
    ],
    references=[
        "https://redis.io/topics/security",
        "https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html",
    ],
    related_cwe="CWE-284",
    tags=["database", "redis", "cache", "rce-possible", "critical"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-mongodb",
    title="Secure Exposed MongoDB Instance",
    summary="MongoDB has been involved in massive data breaches - enable authentication and restrict access.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-3 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Block MongoDB from internet",
            description="Immediately block ports 27017-27019 from public access.",
            command="# Firewall rule to block public access"
        ),
        RemediationStep(
            order=2,
            title="Enable authentication",
            description="Create admin user and enable authentication.",
            command="# Connect to MongoDB:\nmongo\n\n# Create admin user:\nuse admin\ndb.createUser({\n  user: \"adminUser\",\n  pwd: \"strongPassword\",\n  roles: [ { role: \"userAdminAnyDatabase\", db: \"admin\" } ]\n})"
        ),
        RemediationStep(
            order=3,
            title="Enable authorization in config",
            description="Update MongoDB config to require authentication.",
            command="# Edit /etc/mongod.conf:\nsecurity:\n  authorization: enabled\n\nsudo systemctl restart mongod"
        ),
        RemediationStep(
            order=4,
            title="Bind to specific IP",
            description="Configure MongoDB to listen only on internal interfaces.",
            command="# Edit /etc/mongod.conf:\nnet:\n  bindIp: 127.0.0.1,10.0.1.5"
        ),
        RemediationStep(
            order=5,
            title="Check for data exfiltration",
            description="Review if any databases show signs of ransom notes or data deletion.",
            command="# Look for databases named 'README', 'PLEASE_READ', etc.:\nmongo --eval \"db.adminCommand('listDatabases')\""
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify MongoDB requires authentication",
            expected_result="Authentication required error",
            command="mongo --eval 'db.stats()' target-ip:27017",
            automated=True
        ),
    ],
    impact_if_not_fixed="Exposed MongoDB instances have led to breaches affecting hundreds of millions of records. Attackers actively scan for and ransom unprotected databases.",
    common_mistakes=[
        "Running MongoDB with default settings (auth disabled)",
        "Only binding to localhost but leaving port open in firewall",
        "Using MongoDB version before 4.0 which had weaker defaults"
    ],
    references=[
        "https://docs.mongodb.com/manual/security/",
        "https://www.shodan.io/search?query=mongodb",
    ],
    related_cwe="CWE-284",
    tags=["database", "mongodb", "nosql", "data-exposure", "critical"],
))

# -----------------------------------------------------------------------------
# WEB SECURITY PLAYBOOKS
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="missing-https",
    title="Implement HTTPS/TLS Encryption",
    summary="Enable HTTPS with modern TLS configuration to encrypt web traffic.",
    priority=RemediationPriority.MEDIUM,
    effort=RemediationEffort.LOW,
    estimated_time="1-2 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Obtain TLS certificate",
            description="Get a certificate from Let's Encrypt (free) or your preferred CA.",
            command="# Using certbot for Let's Encrypt:\nsudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com"
        ),
        RemediationStep(
            order=2,
            title="Configure HTTPS in web server",
            description="Update Nginx/Apache configuration for HTTPS.",
            code_snippet="# Nginx example:\nserver {\n    listen 443 ssl http2;\n    ssl_certificate /etc/letsencrypt/live/domain/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/domain/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n}"
        ),
        RemediationStep(
            order=3,
            title="Redirect HTTP to HTTPS",
            description="Configure automatic redirect from HTTP to HTTPS.",
            code_snippet="# Nginx:\nserver {\n    listen 80;\n    server_name yourdomain.com;\n    return 301 https://$server_name$request_uri;\n}"
        ),
        RemediationStep(
            order=4,
            title="Enable HSTS header",
            description="Add HTTP Strict Transport Security header to prevent downgrade attacks.",
            command="# Nginx:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify HTTPS is working",
            expected_result="Valid TLS certificate and secure connection",
            command="curl -I https://yourdomain.com",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm HTTP redirects to HTTPS",
            expected_result="301/302 redirect to HTTPS",
            command="curl -I http://yourdomain.com"
        ),
        VerificationStep(
            order=3,
            description="Check TLS configuration",
            expected_result="A or A+ rating",
            command="# Use SSL Labs: https://www.ssllabs.com/ssltest/"
        ),
    ],
    impact_if_not_fixed="Unencrypted HTTP exposes all data including credentials to network observers. Search engines may flag site as insecure.",
    common_mistakes=[
        "Mixed content (loading HTTP resources on HTTPS page)",
        "Not setting up auto-renewal for Let's Encrypt certificates",
        "Using outdated TLS versions (TLS 1.0/1.1)"
    ],
    references=[
        "https://letsencrypt.org/",
        "https://ssl-config.mozilla.org/",
    ],
    related_cwe="CWE-319",
    tags=["web", "https", "tls", "encryption"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-admin-panel",
    title="Secure Exposed Admin Panel",
    summary="Restrict access to administrative interfaces to prevent unauthorized access.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.LOW,
    estimated_time="1-2 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Implement IP-based access control",
            description="Restrict admin panel access to specific IP addresses.",
            code_snippet="# Nginx example:\nlocation /admin {\n    allow 10.0.0.0/8;\n    allow 192.168.1.0/24;\n    deny all;\n}"
        ),
        RemediationStep(
            order=2,
            title="Add additional authentication layer",
            description="Implement HTTP Basic Auth or require VPN for admin access.",
            command="# Nginx basic auth:\nauth_basic \"Admin Area\";\nauth_basic_user_file /etc/nginx/.htpasswd;"
        ),
        RemediationStep(
            order=3,
            title="Enable MFA for admin accounts",
            description="Require multi-factor authentication for all admin logins.",
            notes="Use TOTP apps like Google Authenticator, or hardware keys like YubiKey."
        ),
        RemediationStep(
            order=4,
            title="Move admin to non-standard path",
            description="Change admin URL from default (e.g., /admin, /wp-admin) to custom path.",
            notes="This is defense-in-depth, not a primary security control."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify admin is not accessible from public internet",
            expected_result="403 Forbidden or not found",
            command="curl -I https://target.com/admin",
            automated=True
        ),
    ],
    impact_if_not_fixed="Exposed admin panels are primary targets for brute-force attacks and credential stuffing. Successful access gives attackers full control.",
    common_mistakes=[
        "Only hiding the admin URL (security through obscurity)",
        "Not using strong/unique passwords for admin accounts",
        "Sharing admin credentials among team members"
    ],
    references=[
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
    related_cwe="CWE-284",
    tags=["web", "admin", "authentication", "access-control"],
))

# -----------------------------------------------------------------------------
# FILE SHARING PLAYBOOKS
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="exposed-smb",
    title="Block Exposed SMB Service",
    summary="SMB exposed to internet is a critical risk - block immediately at perimeter firewall.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MINIMAL,
    estimated_time="15-30 minutes",
    required_access=[RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="Block SMB at perimeter firewall",
            description="Block ports 139 and 445 from internet at the network edge.",
            command="# These ports should NEVER be accessible from internet"
        ),
        RemediationStep(
            order=2,
            title="Disable SMBv1",
            description="Disable the vulnerable SMBv1 protocol on all systems.",
            command="# Windows PowerShell:\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n\n# Or via Group Policy"
        ),
        RemediationStep(
            order=3,
            title="Apply security patches",
            description="Ensure all systems are patched for EternalBlue and related vulnerabilities.",
            command="# Check installed patches:\nwmic qfe list | findstr KB4012212"
        ),
        RemediationStep(
            order=4,
            title="Enable SMB signing",
            description="Configure SMB signing to prevent MITM attacks.",
            command="# Group Policy:\n# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options\n# Microsoft network client: Digitally sign communications (always) = Enabled"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify SMB is not accessible from internet",
            expected_result="Ports 139/445 filtered or closed",
            command="nmap -p 139,445 target-ip",
            automated=True
        ),
    ],
    impact_if_not_fixed="WannaCry and NotPetya ransomware spread via exposed SMB. EternalBlue exploit allows unauthenticated remote code execution.",
    common_mistakes=[
        "Only blocking 445 but leaving 139 open",
        "Thinking 'we need SMB for file sharing' - internal != internet",
        "Not patching promptly for new SMB vulnerabilities"
    ],
    references=[
        "https://www.cisa.gov/uscert/ncas/current-activity/2017/05/17/ICS-CERT-Releases-WannaCry-Fact-Sheet",
        "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    ],
    related_cwe="CWE-284",
    related_cve=["CVE-2017-0144", "CVE-2017-0145"],
    tags=["file-sharing", "smb", "ransomware-vector", "critical"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-ftp",
    title="Secure or Replace Exposed FTP Service",
    summary="FTP transmits data in cleartext - replace with SFTP or at minimum secure the configuration.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-4 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Evaluate need for FTP",
            description="Determine if FTP is actually required. If not, disable it and use SFTP instead.",
            notes="SFTP (SSH File Transfer) is almost always the better choice."
        ),
        RemediationStep(
            order=2,
            title="Disable anonymous access",
            description="If FTP must be used, ensure anonymous access is disabled.",
            command="# vsftpd: Edit /etc/vsftpd.conf:\nanonymous_enable=NO"
        ),
        RemediationStep(
            order=3,
            title="Enable FTPS (FTP over TLS)",
            description="If FTP must be used, enable TLS encryption.",
            command="# vsftpd:\nssl_enable=YES\nrsa_cert_file=/path/to/cert.pem\nrsa_private_key_file=/path/to/key.pem\nforce_local_logins_ssl=YES\nforce_local_data_ssl=YES"
        ),
        RemediationStep(
            order=4,
            title="Restrict to specific directories",
            description="Configure chroot to restrict users to specific directories.",
            command="# vsftpd:\nchroot_local_user=YES\nallow_writeable_chroot=YES"
        ),
        RemediationStep(
            order=5,
            title="Implement strong passwords",
            description="Ensure all FTP accounts have strong, unique passwords.",
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify anonymous access is disabled",
            expected_result="Login required",
            command="ftp target-ip",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Confirm TLS is enabled",
            expected_result="TLS negotiation successful",
            command="openssl s_client -connect target-ip:21 -starttls ftp"
        ),
    ],
    impact_if_not_fixed="FTP credentials are visible to anyone who can observe network traffic. Anonymous FTP can be used to host malicious content.",
    common_mistakes=[
        "Leaving anonymous access enabled 'temporarily'",
        "Not realizing FTPS is different from SFTP",
        "Using the same FTP password as other accounts"
    ],
    references=[
        "https://www.ssh.com/academy/ssh/sftp-ssh-ftp-protocol",
    ],
    related_cwe="CWE-319",
    tags=["file-transfer", "ftp", "cleartext"],
))


# -----------------------------------------------------------------------------
# OT/ICS - INDUSTRIAL CONTROL SYSTEMS PLAYBOOKS
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="exposed-modbus",
    title="Secure Exposed Modbus Protocol",
    summary="Modbus lacks authentication - immediately isolate from untrusted networks and implement OT network segmentation.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.HIGH,
    estimated_time="1-2 days (requires change window)",
    required_access=[RequiredAccess.INFRASTRUCTURE, RequiredAccess.SECURITY_TEAM],
    steps=[
        RemediationStep(
            order=1,
            title="Immediate: Block Modbus from internet",
            description="Add firewall rules to block port 502 from all untrusted networks immediately.",
            command="# Modbus TCP uses port 502\n# Block at perimeter firewall immediately",
            notes="This is critical - Modbus has NO authentication. Any attacker can read/write PLC registers."
        ),
        RemediationStep(
            order=2,
            title="Implement IT/OT network segmentation",
            description="Create a dedicated OT network zone with controlled access points. Use industrial firewalls or DMZ architecture.",
            notes="Follow IEC 62443 zone and conduit model. The Purdue Model recommends 5 levels of segmentation."
        ),
        RemediationStep(
            order=3,
            title="Deploy OT-aware monitoring",
            description="Install industrial intrusion detection that understands Modbus protocol semantics.",
            notes="Solutions like Claroty, Dragos, Nozomi Networks can detect malicious Modbus commands."
        ),
        RemediationStep(
            order=4,
            title="Enable Modbus/TCP filtering",
            description="If Modbus must cross trust boundaries, use a Modbus-aware firewall that can filter by function code and register ranges.",
            notes="Block dangerous function codes like Write Single Coil (05), Write Multiple Coils (15), Write Single Register (06)."
        ),
        RemediationStep(
            order=5,
            title="Document and inventory",
            description="Create an asset inventory of all Modbus devices including IP, unit ID, and function.",
            command="# Use nmap to enumerate Modbus devices:\nnmap -p 502 --script modbus-discover <network/24>"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify Modbus is not accessible from internet",
            expected_result="Port 502 closed or filtered from external networks",
            command="nmap -p 502 <target-ip>",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Verify OT network segmentation",
            expected_result="Cannot reach Modbus from corporate IT network without going through firewall",
            automated=False
        ),
    ],
    impact_if_not_fixed="Exposed Modbus allows attackers to directly control PLCs, pumps, valves, and industrial equipment. This could cause physical damage, safety incidents, or production outages.",
    common_mistakes=[
        "Thinking 'we need Modbus for SCADA' - use secure tunnels or proxies instead",
        "Trusting VLANs alone for segmentation (they can be bypassed)",
        "Not inventorying all Modbus devices in the environment"
    ],
    references=[
        "https://www.cisa.gov/uscert/ics/advisories",
        "https://www.fortiguard.com/services/operational-technology-security-service",
        "https://ics-cert.us-cert.gov/Recommended-Practices",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "scada", "modbus", "plc", "critical-infrastructure"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-s7",
    title="Secure Exposed Siemens S7 Protocol",
    summary="S7comm protocol is exposed - this was targeted by Stuxnet. Immediately isolate and implement defense-in-depth.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.HIGH,
    estimated_time="1-2 days (requires change window)",
    required_access=[RequiredAccess.INFRASTRUCTURE, RequiredAccess.SECURITY_TEAM],
    steps=[
        RemediationStep(
            order=1,
            title="Immediate: Block S7 from untrusted networks",
            description="Add firewall rules to block port 102 (ISO-TSAP) from all untrusted networks.",
            command="# S7comm uses port 102 (ISO-on-TCP)\n# Block at perimeter immediately",
            notes="S7comm was the protocol exploited by Stuxnet to damage Iranian centrifuges."
        ),
        RemediationStep(
            order=2,
            title="Enable PLC access protection",
            description="Configure password protection on Siemens PLCs using TIA Portal or STEP 7.",
            notes="Enable at minimum: Know-how protection, Copy protection, and Access protection (read/write passwords)."
        ),
        RemediationStep(
            order=3,
            title="Implement network segmentation",
            description="Place all Siemens PLCs in a dedicated control network zone with strict access controls.",
            notes="Follow Siemens defense-in-depth recommendations and IEC 62443."
        ),
        RemediationStep(
            order=4,
            title="Update PLC firmware",
            description="Ensure all S7 PLCs are running latest firmware with security patches.",
            command="# Check current firmware in TIA Portal or via:\nnmap -p 102 --script s7-info <target-ip>"
        ),
        RemediationStep(
            order=5,
            title="Deploy industrial monitoring",
            description="Install OT-aware IDS that can detect S7comm exploitation attempts.",
            notes="Monitor for unauthorized S7 STOP/START commands, program downloads, and memory writes."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify S7 is not accessible from internet or IT networks",
            expected_result="Port 102 closed or filtered",
            command="nmap -p 102 --script s7-info <target-ip>",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Verify PLC access protection is enabled",
            expected_result="Password required for read/write operations",
            automated=False
        ),
    ],
    impact_if_not_fixed="Exposed S7comm allows attackers to stop/start PLCs, modify programs, and cause physical damage. Stuxnet demonstrated nation-state level attacks on these protocols.",
    common_mistakes=[
        "Relying only on S7 password protection (can be bypassed in some firmware versions)",
        "Not patching CVE-2019-13945 and other S7 vulnerabilities",
        "Allowing engineering workstations direct internet access"
    ],
    references=[
        "https://www.fortiguard.com/encyclopedia?type=otsapp",
        "https://www.siemens.com/global/en/products/automation/topic-areas/industrial-security.html",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "scada", "siemens", "s7", "plc", "critical-infrastructure"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-ethernet-ip",
    title="Secure Exposed EtherNet/IP Protocol",
    summary="EtherNet/IP (CIP) is exposed - segment Rockwell/Allen-Bradley controllers from untrusted networks.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.HIGH,
    estimated_time="1-2 days",
    required_access=[RequiredAccess.INFRASTRUCTURE, RequiredAccess.SECURITY_TEAM],
    steps=[
        RemediationStep(
            order=1,
            title="Block EtherNet/IP from untrusted networks",
            description="Add firewall rules to block port 44818 (explicit messaging) and 2222 (I/O) from untrusted networks.",
            command="# EtherNet/IP ports:\n# 44818/TCP - Explicit messaging\n# 2222/UDP - Implicit I/O\n# Block both at perimeter"
        ),
        RemediationStep(
            order=2,
            title="Implement CIP Security if supported",
            description="Enable CIP Security on compatible devices for authentication and encryption.",
            notes="CIP Security requires compatible devices (check with Rockwell). Older devices don't support it."
        ),
        RemediationStep(
            order=3,
            title="Segment control networks",
            description="Create dedicated cell/area zones for controllers with industrial DMZ architecture.",
            notes="Follow Rockwell CPwE (Converged Plantwide Ethernet) architecture guidelines."
        ),
        RemediationStep(
            order=4,
            title="Deploy industrial monitoring",
            description="Install OT-aware monitoring that understands CIP/EtherNet/IP protocol.",
            command="# Enumerate EtherNet/IP devices:\nnmap -p 44818 --script enip-info <network/24>"
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify EtherNet/IP is not accessible from untrusted networks",
            expected_result="Ports 44818 and 2222 closed or filtered",
            command="nmap -p 44818 --script enip-info <target-ip>",
            automated=True
        ),
    ],
    impact_if_not_fixed="Exposed EtherNet/IP allows attackers to read/write PLC data, stop controllers, and cause production outages or safety incidents.",
    common_mistakes=[
        "Blocking only 44818 but leaving 2222 open",
        "Assuming VLANs provide sufficient isolation",
        "Not inventorying all EtherNet/IP devices"
    ],
    references=[
        "https://www.fortiguard.com/services/operational-technology-security-service",
        "https://www.rockwellautomation.com/en-us/capabilities/industrial-cybersecurity.html",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "ethernet-ip", "cip", "rockwell", "allen-bradley", "plc"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-dnp3",
    title="Secure Exposed DNP3 Protocol",
    summary="DNP3 is exposed - critical for utilities and power grids. Implement secure authentication and network isolation.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.HIGH,
    estimated_time="2-5 days (compliance considerations)",
    required_access=[RequiredAccess.INFRASTRUCTURE, RequiredAccess.SECURITY_TEAM],
    steps=[
        RemediationStep(
            order=1,
            title="Block DNP3 from internet immediately",
            description="Add firewall rules to block port 20000 from all untrusted networks.",
            command="# DNP3 uses port 20000 (default)\n# Block at perimeter immediately"
        ),
        RemediationStep(
            order=2,
            title="Enable DNP3 Secure Authentication",
            description="Implement DNP3 Secure Authentication (SA) version 5 or higher on compatible devices.",
            notes="DNP3-SA provides challenge-response authentication. Requires compatible RTUs/IEDs."
        ),
        RemediationStep(
            order=3,
            title="Use encrypted tunnels for WAN",
            description="If DNP3 must traverse WAN, use IPsec VPN tunnels between control centers and substations.",
            notes="This is required for NERC CIP compliance in bulk electric systems."
        ),
        RemediationStep(
            order=4,
            title="Deploy DNP3-aware monitoring",
            description="Install IDS with DNP3 protocol inspection capabilities.",
            notes="Monitor for unauthorized control commands and protocol anomalies.",
            command="# Enumerate DNP3 devices:\nnmap -p 20000 --script dnp3-info <network/24>"
        ),
        RemediationStep(
            order=5,
            title="Review NERC CIP compliance",
            description="For bulk electric systems, ensure compliance with NERC CIP standards.",
            notes="CIP-005 requires electronic security perimeters. CIP-007 requires access controls."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify DNP3 is not accessible from internet",
            expected_result="Port 20000 closed or filtered from external networks",
            command="nmap -p 20000 --script dnp3-info <target-ip>",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Verify DNP3 Secure Authentication is enabled",
            expected_result="Authentication required for control operations",
            automated=False
        ),
    ],
    impact_if_not_fixed="Exposed DNP3 in utility environments could allow attackers to manipulate power grid operations, open breakers, or cause cascading failures.",
    common_mistakes=[
        "Not enabling DNP3 Secure Authentication",
        "Using DNP3 over public networks without encryption",
        "Ignoring NERC CIP compliance requirements"
    ],
    references=[
        "https://www.cisa.gov/uscert/ics",
        "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "scada", "dnp3", "utilities", "power-grid", "nerc-cip", "critical-infrastructure"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-bacnet",
    title="Secure Exposed BACnet Protocol",
    summary="BACnet building automation protocol is exposed - segment from untrusted networks and enable security features.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.MEDIUM,
    estimated_time="4-8 hours",
    required_access=[RequiredAccess.ADMIN, RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="Block BACnet from internet",
            description="Add firewall rules to block port 47808 from untrusted networks.",
            command="# BACnet/IP uses port 47808/UDP\n# Block at perimeter"
        ),
        RemediationStep(
            order=2,
            title="Segment BACnet to BMS network",
            description="Place all BACnet devices in a dedicated building management system (BMS) network zone.",
            notes="Separate from corporate IT network and other OT systems."
        ),
        RemediationStep(
            order=3,
            title="Enable BACnet/SC if supported",
            description="Implement BACnet Secure Connect for TLS-based authentication and encryption.",
            notes="BACnet/SC requires compatible devices. Legacy devices may not support it."
        ),
        RemediationStep(
            order=4,
            title="Disable unnecessary BACnet broadcasts",
            description="Configure BBMD (BACnet Broadcast Management Device) to limit broadcast scope.",
            notes="This prevents BACnet device discovery from spreading across network segments."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify BACnet is not accessible from internet",
            expected_result="Port 47808 closed or filtered",
            automated=True
        ),
    ],
    impact_if_not_fixed="Exposed BACnet allows attackers to control HVAC, lighting, and access control systems. Could be used to cause discomfort, disable physical security, or increase energy costs.",
    common_mistakes=[
        "Connecting BMS directly to corporate network for remote access",
        "Not disabling BACnet broadcasts",
        "Using default passwords on BACnet devices"
    ],
    references=[
        "https://www.ashrae.org/technical-resources/bookstore/bacnet",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "bacnet", "building-automation", "bms", "hvac"],
))

_register_playbook(RemediationPlaybook(
    id="exposed-opc-ua",
    title="Secure Exposed OPC UA Protocol",
    summary="OPC UA is exposed - enable security mode and certificate authentication.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-4 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Block OPC UA from untrusted networks",
            description="Add firewall rules to restrict port 4840 to authorized clients only.",
            command="# OPC UA uses port 4840 by default"
        ),
        RemediationStep(
            order=2,
            title="Enable OPC UA security mode",
            description="Configure OPC UA servers to require Sign or SignAndEncrypt security mode. Disable None.",
            notes="Security mode 'None' allows unauthenticated access. Always disable it."
        ),
        RemediationStep(
            order=3,
            title="Implement certificate authentication",
            description="Configure OPC UA to require client certificates for authentication.",
            notes="Use a proper PKI infrastructure. Don't accept self-signed certificates from unknown clients."
        ),
        RemediationStep(
            order=4,
            title="Review user authentication",
            description="Ensure OPC UA user authentication is enabled with strong passwords.",
            notes="Disable anonymous authentication unless explicitly required."
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify OPC UA requires authentication",
            expected_result="Anonymous access denied",
            automated=False
        ),
    ],
    impact_if_not_fixed="Misconfigured OPC UA can expose read/write access to industrial data and control systems without authentication.",
    common_mistakes=[
        "Leaving security mode set to 'None'",
        "Accepting all client certificates without validation",
        "Using weak or default passwords"
    ],
    references=[
        "https://opcfoundation.org/developer-tools/specifications-unified-architecture",
    ],
    related_cwe="CWE-306",
    tags=["ot", "ics", "opc-ua", "industrial-automation"],
))


# =============================================================================
# PLAYBOOK LOOKUP SERVICE
# =============================================================================

class RemediationPlaybookService:
    """Service for looking up and matching remediation playbooks to findings."""
    
    # Map finding titles/template IDs to playbook IDs
    FINDING_TO_PLAYBOOK_MAP = {
        # Port-based findings
        "ssh service exposed": "exposed-ssh",
        "rdp service exposed": "exposed-rdp",
        "telnet service exposed": "exposed-telnet",
        "mysql database exposed": "exposed-mysql",
        "redis exposed": "exposed-redis",
        "mongodb exposed": "exposed-mongodb",
        "smb/cifs service exposed": "exposed-smb",
        "ftp service exposed": "exposed-ftp",
        "http service (unencrypted)": "missing-https",
        
        # OT/ICS findings
        "modbus protocol exposed": "exposed-modbus",
        "siemens s7 protocol exposed": "exposed-s7",
        "ethernet/ip protocol exposed": "exposed-ethernet-ip",
        "dnp3 protocol exposed": "exposed-dnp3",
        "bacnet protocol exposed": "exposed-bacnet",
        "opc ua protocol exposed": "exposed-opc-ua",
        "iec 60870-5-104 protocol exposed": "exposed-dnp3",  # Similar remediation
        "omron fins protocol exposed": "exposed-modbus",  # Similar remediation
        "mitsubishi melsec protocol exposed": "exposed-modbus",  # Similar remediation
        "ge srtp protocol exposed": "exposed-modbus",  # Similar remediation
        
        # Nuclei template patterns
        "exposed-panels": "exposed-admin-panel",
        "admin-panel": "exposed-admin-panel",
        "default-login": "exposed-admin-panel",
    }
    
    # Map ports to playbook IDs (fallback)
    PORT_TO_PLAYBOOK_MAP = {
        # IT services
        22: "exposed-ssh",
        3389: "exposed-rdp",
        23: "exposed-telnet",
        3306: "exposed-mysql",
        6379: "exposed-redis",
        27017: "exposed-mongodb",
        27018: "exposed-mongodb",
        27019: "exposed-mongodb",
        445: "exposed-smb",
        139: "exposed-smb",
        21: "exposed-ftp",
        
        # OT/ICS protocols
        502: "exposed-modbus",
        102: "exposed-s7",
        44818: "exposed-ethernet-ip",
        2222: "exposed-ethernet-ip",
        20000: "exposed-dnp3",
        47808: "exposed-bacnet",
        4840: "exposed-opc-ua",
        2404: "exposed-dnp3",  # IEC 60870-5-104
        9600: "exposed-modbus",  # OMRON FINS
        5007: "exposed-modbus",  # Mitsubishi MELSEC
        18245: "exposed-modbus",  # GE SRTP
        18246: "exposed-modbus",  # GE SRTP
        1911: "exposed-bacnet",  # Niagara Fox
        1962: "exposed-bacnet",  # Niagara Fox
    }
    
    @classmethod
    def get_playbook(cls, playbook_id: str) -> Optional[RemediationPlaybook]:
        """Get a specific playbook by ID."""
        return REMEDIATION_PLAYBOOKS.get(playbook_id)
    
    @classmethod
    def get_playbook_for_finding(
        cls,
        title: Optional[str] = None,
        template_id: Optional[str] = None,
        port: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> Optional[RemediationPlaybook]:
        """
        Find the most relevant playbook for a finding.
        
        Matches based on title, template ID, port, or tags.
        """
        # Try title match first
        if title:
            title_lower = title.lower()
            for pattern, playbook_id in cls.FINDING_TO_PLAYBOOK_MAP.items():
                if pattern in title_lower:
                    return REMEDIATION_PLAYBOOKS.get(playbook_id)
        
        # Try template ID match
        if template_id:
            template_lower = template_id.lower()
            for pattern, playbook_id in cls.FINDING_TO_PLAYBOOK_MAP.items():
                if pattern in template_lower:
                    return REMEDIATION_PLAYBOOKS.get(playbook_id)
        
        # Try port match
        if port and port in cls.PORT_TO_PLAYBOOK_MAP:
            return REMEDIATION_PLAYBOOKS.get(cls.PORT_TO_PLAYBOOK_MAP[port])
        
        # Try tag match
        if tags:
            for tag in tags:
                tag_lower = tag.lower()
                # IT services
                if "ssh" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-ssh")
                if "rdp" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-rdp")
                if "mysql" in tag_lower or "database" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-mysql")
                # OT/ICS
                if "modbus" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-modbus")
                if "s7" in tag_lower or "siemens" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-s7")
                if "ethernet-ip" in tag_lower or "cip" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-ethernet-ip")
                if "dnp3" in tag_lower or "iec-104" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-dnp3")
                if "bacnet" in tag_lower or "bms" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-bacnet")
                if "opc-ua" in tag_lower or "opc ua" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-opc-ua")
                if "ot" in tag_lower or "ics" in tag_lower or "scada" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("exposed-modbus")  # General OT playbook
        
        return None
    
    @classmethod
    def get_all_playbooks(cls) -> List[RemediationPlaybook]:
        """Get all available playbooks."""
        return list(REMEDIATION_PLAYBOOKS.values())
    
    @classmethod
    def search_playbooks(cls, query: str) -> List[RemediationPlaybook]:
        """Search playbooks by title, tags, or content."""
        query_lower = query.lower()
        results = []
        
        for playbook in REMEDIATION_PLAYBOOKS.values():
            if (query_lower in playbook.title.lower() or
                query_lower in playbook.summary.lower() or
                any(query_lower in tag for tag in playbook.tags)):
                results.append(playbook)
        
        return results
