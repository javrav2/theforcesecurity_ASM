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
    CRITICAL = "critical"  # Fix immediately (within hours) - active exploitation risk
    HIGH = "high"          # Fix same day / within 24 hours
    MEDIUM = "medium"      # Fix within 1 week
    LOW = "low"            # Fix within 30 days
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
    summary="URGENT: Restrict SSH access immediately. Exposed SSH is actively targeted by automated attacks within minutes of exposure.",
    priority=RemediationPriority.HIGH,  # Fix within 24-48 hours (ideally same day)
    effort=RemediationEffort.LOW,
    estimated_time="30 minutes - 2 hours",
    required_access=[RequiredAccess.ADMIN, RequiredAccess.INFRASTRUCTURE],
    steps=[
        RemediationStep(
            order=1,
            title="IMMEDIATE: Restrict access to trusted IPs only",
            description="This is the most critical step. Block SSH from the internet and only allow access from trusted IP ranges (office, VPN, management network). Do this FIRST.",
            command="""# Linux iptables (immediate):
sudo iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -s <your-office-ip>/32 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Cisco IOS/ASA:
access-list SSH-ACCESS permit tcp 10.0.0.0 0.255.255.255 host <device-ip> eq 22
access-list SSH-ACCESS deny tcp any host <device-ip> eq 22
line vty 0 15
 access-class SSH-ACCESS in

# Palo Alto / Fortinet / Other NGFW:
# Security Policy: Source=Trusted-Mgmt-IPs, Dest=<device>, Port=22, Action=Allow
# Default deny rule for all other SSH attempts

# AWS Security Group:
aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr <your-office-ip>/32""",
            notes="CRITICAL: This single step eliminates 99% of the risk. Automated SSH attacks start within minutes of exposure. Complete this step immediately, then proceed with hardening."
        ),
        RemediationStep(
            order=2,
            title="Enable key-based or certificate authentication",
            description="Disable password authentication where possible. Use SSH keys for servers, and TACACS+/RADIUS with MFA for network devices.",
            command="""# Linux/Unix - Edit /etc/ssh/sshd_config:
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
# Restart SSH:
sudo systemctl restart sshd

# Cisco IOS - Centralized AAA:
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local

# Network devices without key support:
# Use TACACS+/RADIUS server with MFA (Duo, RSA SecurID, etc.)""",
            notes="For network devices (routers, switches, firewalls), SSH keys may not be supported. Use centralized AAA (TACACS+/RADIUS) with MFA instead."
        ),
        RemediationStep(
            order=3,
            title="Enable brute-force protection",
            description="Rate-limit or block repeated failed login attempts.",
            command="""# Linux - fail2ban (blocks after 5 failures):
sudo apt install fail2ban
sudo systemctl enable --now fail2ban

# Cisco IOS:
login block-for 120 attempts 5 within 60
login delay 2

# Juniper:
set system login retry-options tries-before-disconnect 3
set system login retry-options backoff-threshold 1
set system login retry-options backoff-factor 5

# Palo Alto:
# Device > Setup > Management > Authentication Settings > Lockout""",
            notes="This provides defense-in-depth but is NOT a substitute for Step 1 (IP restrictions)."
        ),
        RemediationStep(
            order=4,
            title="Long-term: Implement VPN or bastion architecture",
            description="For production environments, eliminate direct SSH exposure entirely by requiring VPN or using a bastion/jump host.",
            command="""# Options by environment:

# On-premises / Network devices:
# - Out-of-band management network (OOB) - isolate management traffic
# - Require VPN connection to reach management interfaces
# - Hardened bastion/jump server with full audit logging

# Cloud:
# - AWS: Use Systems Manager Session Manager (no SSH port needed)
# - Azure: Use Azure Bastion
# - Deploy bastion host in private subnet, SSH only from bastion""",
            notes="This is the gold standard for SSH security. Management traffic should never traverse the public internet directly."
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
            command="""# Perimeter firewall (Palo Alto, Fortinet, etc.):
# Create deny rule: Source=any, Dest=<your-subnet>, Port=3389, Action=Deny

# Windows Firewall (on the host):
netsh advfirewall firewall add rule name="Block RDP Internet" dir=in action=block protocol=tcp localport=3389

# Linux iptables (if forwarding to Windows):
sudo iptables -A FORWARD -p tcp --dport 3389 -j DROP

# AWS Security Group:
aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr 0.0.0.0/0""",
            notes="URGENT: Do this first to stop active exploitation attempts."
        ),
        RemediationStep(
            order=2,
            title="Enable Network Level Authentication (NLA)",
            description="NLA requires authentication before the RDP session is established, blocking many attacks.",
            command="""# PowerShell:
Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1

# Or via Group Policy:
# Computer Configuration > Administrative Templates > Windows Components > 
# Remote Desktop Services > Remote Desktop Session Host > Security
# Set: Require user authentication for remote connections = Enabled"""
        ),
        RemediationStep(
            order=3,
            title="Implement VPN or RD Gateway",
            description="All RDP access should go through a VPN, RD Gateway, or zero-trust access solution.",
            command="""# Options by environment:

# On-premises:
# - Deploy Windows Remote Desktop Gateway (RD Gateway)
# - Require VPN connection (OpenVPN, WireGuard, Cisco AnyConnect)
# - Use jump server in DMZ with MFA

# Cloud:
# - Azure: Use Azure Bastion (no public IP needed)
# - AWS: Use Systems Manager Fleet Manager or a bastion host
# - Any: Deploy Guacamole as web-based RDP gateway""",
            notes="This is the most important long-term fix. Direct RDP should never be exposed."
        ),
        RemediationStep(
            order=4,
            title="Enable account lockout policies",
            description="Configure account lockout after failed login attempts to prevent brute-force.",
            command="""# Group Policy path:
# Computer Configuration > Windows Settings > Security Settings > 
# Account Policies > Account Lockout Policy

# Recommended settings:
# - Account lockout threshold: 5 attempts
# - Account lockout duration: 30 minutes
# - Reset lockout counter after: 30 minutes"""
        ),
        RemediationStep(
            order=5,
            title="Ensure systems are patched",
            description="Apply all Windows security updates, especially for RDP vulnerabilities like BlueKeep (CVE-2019-0708).",
            command="""# PowerShell - Check for updates:
Get-WindowsUpdate

# Or check patch level:
systeminfo | findstr /B /C:"OS Version" /C:"KB"

# Critical RDP patches to verify:
# - KB4499175 (BlueKeep - CVE-2019-0708)
# - KB4512501 (DejaBlue - CVE-2019-1181/1182)"""
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
            description="Add firewall rules to block port 3306 from public access at the perimeter.",
            command="# Linux iptables:\nsudo iptables -A INPUT -p tcp --dport 3306 -s 0.0.0.0/0 -j DROP\n\n# Perimeter firewall (Palo Alto, Fortinet, Cisco ASA):\n# Create deny rule: Source=any-external, Dest=<db-server>, Port=3306\n\n# AWS Security Group:\naws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3306 --cidr 0.0.0.0/0"
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
            command="# Linux iptables:\nsudo iptables -A INPUT -p tcp --dport 6379 -s 0.0.0.0/0 -j DROP\n\n# Perimeter firewall (Palo Alto, Fortinet, Cisco ASA):\n# Create deny rule: Source=any, Dest=<redis-server>, Port=6379, Action=Deny\n\n# AWS Security Group:\naws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 6379 --cidr 0.0.0.0/0"
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


# -----------------------------------------------------------------------------
# WEB VULNERABILITY PLAYBOOKS (CWE-based for Nuclei findings)
# -----------------------------------------------------------------------------

_register_playbook(RemediationPlaybook(
    id="vuln-ssrf",
    title="Remediate Server-Side Request Forgery (SSRF)",
    summary="SSRF allows attackers to make requests from your server to internal resources. Upgrade the affected software and implement request validation.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-4 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Upgrade the vulnerable software immediately",
            description="Most SSRF vulnerabilities are fixed in newer versions. Check the CVE details for the patched version.",
            command="""# Check current version and upgrade:
# For Keycloak: https://www.keycloak.org/downloads
# For other software, check vendor security advisories

# Docker example:
docker pull jboss/keycloak:latest
docker-compose up -d

# Package manager example:
apt update && apt upgrade <package-name>""",
            notes="Always test upgrades in a staging environment first."
        ),
        RemediationStep(
            order=2,
            title="Implement URL validation and allowlisting",
            description="If the feature requires external URLs, validate and restrict them to known-safe domains.",
            command="""# Application-level fix - allowlist approach:
ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.trusted.com']

def validate_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Domain not allowed")
    if parsed.scheme not in ['https']:
        raise ValueError("Only HTTPS allowed")
    return url""",
            notes="Blocklists are insufficient - attackers can bypass with DNS rebinding, IP encoding tricks, etc."
        ),
        RemediationStep(
            order=3,
            title="Block internal network access from web servers",
            description="Use network segmentation to prevent web servers from reaching internal resources.",
            command="""# Network-level controls:
# 1. Web servers should not be able to reach internal metadata endpoints
# 2. Block access to private IP ranges (10.x, 172.16.x, 192.168.x)
# 3. Block cloud metadata endpoints (169.254.169.254)

# AWS: Use IMDSv2 to protect metadata endpoint
aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required"""
        ),
        RemediationStep(
            order=4,
            title="Disable or restrict the vulnerable feature",
            description="If the feature (like request_uri in OIDC) is not needed, disable it.",
            command="""# Keycloak specific - disable request_uri:
# In keycloak admin console, disable "Request Object Required"
# Or configure client to not use request_uri

# General: Disable unused features in security-sensitive applications"""
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Re-run the vulnerability scan",
            expected_result="Vulnerability no longer detected",
            command="nuclei -t CVE-xxx.yaml -u https://target.com",
            automated=True
        ),
        VerificationStep(
            order=2,
            description="Test SSRF manually with internal targets",
            expected_result="Requests to internal IPs should fail",
            command="curl 'https://target.com/vuln-endpoint?url=http://169.254.169.254/'"
        ),
    ],
    impact_if_not_fixed="SSRF can lead to internal network scanning, access to cloud metadata (credentials), and in some cases remote code execution.",
    common_mistakes=[
        "Only blocking localhost - attackers use 127.0.0.1, 0.0.0.0, IPv6, decimal IP notation",
        "Using blocklists instead of allowlists",
        "Not blocking cloud metadata endpoints (169.254.169.254)"
    ],
    references=[
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://portswigger.net/web-security/ssrf",
    ],
    related_cwe="CWE-918",
    tags=["web", "ssrf", "nuclei", "cve"],
))

_register_playbook(RemediationPlaybook(
    id="vuln-sqli",
    title="Remediate SQL Injection Vulnerability",
    summary="SQL injection allows attackers to execute arbitrary database queries. Use parameterized queries and upgrade affected software.",
    priority=RemediationPriority.CRITICAL,
    effort=RemediationEffort.MEDIUM,
    estimated_time="2-8 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Identify and patch the vulnerable component",
            description="If this is a CVE in third-party software, upgrade to the patched version immediately.",
            command="""# Check vendor advisories for patched versions
# Apply security updates

# For custom code, identify the vulnerable query:
# Look for string concatenation in SQL queries"""
        ),
        RemediationStep(
            order=2,
            title="Use parameterized queries",
            description="Replace string concatenation with parameterized/prepared statements.",
            command="""# WRONG - Vulnerable:
query = f"SELECT * FROM users WHERE id = {user_input}"

# CORRECT - Parameterized:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# Or use ORM:
User.objects.filter(id=user_input)"""
        ),
        RemediationStep(
            order=3,
            title="Implement input validation",
            description="Validate and sanitize all user input as defense-in-depth.",
            command="""# Validate input types and ranges:
def validate_user_id(user_id):
    if not isinstance(user_id, int):
        raise ValueError("User ID must be integer")
    if user_id < 0 or user_id > 999999999:
        raise ValueError("User ID out of range")
    return user_id"""
        ),
        RemediationStep(
            order=4,
            title="Apply least privilege to database accounts",
            description="Ensure the application uses a database account with minimal permissions.",
            command="""-- Create limited database user:
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'localhost';
-- Do NOT grant DELETE, DROP, or admin privileges"""
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Re-run vulnerability scan",
            expected_result="SQL injection no longer detected",
            automated=True
        ),
    ],
    impact_if_not_fixed="SQL injection can lead to complete database compromise, data theft, data modification, and potentially server takeover.",
    common_mistakes=[
        "Using blocklists to filter SQL characters (easily bypassed)",
        "Only fixing the specific payload that was detected",
        "Not reviewing similar code patterns throughout the application"
    ],
    references=[
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
    related_cwe="CWE-89",
    tags=["web", "sqli", "injection", "nuclei", "cve", "critical"],
))

_register_playbook(RemediationPlaybook(
    id="vuln-xss",
    title="Remediate Cross-Site Scripting (XSS)",
    summary="XSS allows attackers to inject malicious scripts. Implement output encoding and Content Security Policy.",
    priority=RemediationPriority.MEDIUM,
    effort=RemediationEffort.LOW,
    estimated_time="1-4 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Upgrade vulnerable software",
            description="If this is a CVE in third-party software, upgrade to the patched version.",
            command="# Check vendor security advisories and apply patches"
        ),
        RemediationStep(
            order=2,
            title="Implement context-aware output encoding",
            description="Encode all user-supplied data before including in HTML output.",
            command="""# Use framework's built-in escaping:

# Python/Jinja2:
{{ user_input }}  # Auto-escaped in Jinja2

# React:
{userInput}  // Auto-escaped in JSX

# PHP:
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');"""
        ),
        RemediationStep(
            order=3,
            title="Implement Content Security Policy (CSP)",
            description="Add CSP headers to prevent inline script execution.",
            command="""# Nginx:
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'";

# Apache:
Header set Content-Security-Policy "default-src 'self'; script-src 'self'"

# Application-level:
response.headers['Content-Security-Policy'] = "default-src 'self'";"""
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Re-run vulnerability scan",
            expected_result="XSS no longer detected",
            automated=True
        ),
    ],
    impact_if_not_fixed="XSS can lead to session hijacking, credential theft, malware distribution, and defacement.",
    common_mistakes=[
        "Only encoding in some contexts but not others",
        "Using innerHTML or dangerouslySetInnerHTML with user input"
    ],
    references=[
        "https://owasp.org/www-community/attacks/xss/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    related_cwe="CWE-79",
    tags=["web", "xss", "injection", "nuclei", "cve"],
))

_register_playbook(RemediationPlaybook(
    id="vuln-outdated-software",
    title="Upgrade Outdated/Vulnerable Software",
    summary="This software version has known security vulnerabilities. Upgrade to the latest patched version.",
    priority=RemediationPriority.HIGH,
    effort=RemediationEffort.MEDIUM,
    estimated_time="1-4 hours",
    required_access=[RequiredAccess.ADMIN],
    steps=[
        RemediationStep(
            order=1,
            title="Identify the current version and required update",
            description="Check the CVE details to find which version fixes the vulnerability.",
            command="""# Check current version:
# Web apps: Look at response headers, /version endpoints, login pages
# Servers: Check package version with apt/yum/brew

# Find patched version:
# - Check CVE details in NVD: https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
# - Check vendor security advisories
# - Check GitHub security advisories"""
        ),
        RemediationStep(
            order=2,
            title="Test upgrade in staging environment",
            description="Before upgrading production, test the new version in a staging environment.",
            command="""# Clone production environment
# Apply the upgrade
# Run integration tests
# Verify application functionality"""
        ),
        RemediationStep(
            order=3,
            title="Apply the upgrade to production",
            description="Schedule a maintenance window and apply the upgrade.",
            command="""# Docker:
docker pull <image>:latest
docker-compose up -d

# Linux packages:
apt update && apt upgrade <package>
# or
yum update <package>

# Manual install:
# Follow vendor upgrade documentation"""
        ),
        RemediationStep(
            order=4,
            title="Verify the upgrade and re-scan",
            description="Confirm the new version is running and the vulnerability is resolved.",
            command="""# Check version after upgrade
# Re-run vulnerability scan to confirm fix
nuclei -u https://target.com -t CVE-xxxx-xxxxx.yaml"""
        ),
    ],
    verification=[
        VerificationStep(
            order=1,
            description="Verify new version is running",
            expected_result="Updated version number displayed",
            automated=False
        ),
        VerificationStep(
            order=2,
            description="Re-run vulnerability scan",
            expected_result="CVE no longer detected",
            automated=True
        ),
    ],
    impact_if_not_fixed="Known vulnerabilities in outdated software are actively exploited by attackers. Exploit code is often publicly available.",
    common_mistakes=[
        "Upgrading without testing (breaking production)",
        "Only upgrading the main package but not dependencies",
        "Not checking for new vulnerabilities in the updated version"
    ],
    references=[
        "https://nvd.nist.gov/",
        "https://cve.mitre.org/",
    ],
    related_cwe="CWE-1104",
    tags=["upgrade", "patch", "cve", "outdated", "nuclei"],
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
    
    # CWE to playbook mapping for vulnerability findings
    CWE_TO_PLAYBOOK_MAP = {
        # SSRF
        "CWE-918": "vuln-ssrf",
        "cwe-918": "vuln-ssrf",
        # SQL Injection
        "CWE-89": "vuln-sqli",
        "cwe-89": "vuln-sqli",
        # XSS
        "CWE-79": "vuln-xss",
        "cwe-79": "vuln-xss",
        # Path Traversal
        "CWE-22": "vuln-outdated-software",
        "cwe-22": "vuln-outdated-software",
        # Command Injection
        "CWE-78": "vuln-sqli",  # Similar remediation pattern
        "cwe-78": "vuln-sqli",
        # Outdated software
        "CWE-1104": "vuln-outdated-software",
        "cwe-1104": "vuln-outdated-software",
        # Authentication issues
        "CWE-287": "exposed-admin-panel",
        "cwe-287": "exposed-admin-panel",
        # Missing encryption
        "CWE-319": "missing-https",
        "cwe-319": "missing-https",
        # Access control
        "CWE-284": "exposed-admin-panel",
        "cwe-284": "exposed-admin-panel",
    }
    
    @classmethod
    def get_playbook_for_finding(
        cls,
        title: Optional[str] = None,
        template_id: Optional[str] = None,
        port: Optional[int] = None,
        tags: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> Optional[RemediationPlaybook]:
        """
        Find the most relevant playbook for a finding.
        
        Matches based on title, template ID, port, tags, CWE, or CVE.
        """
        # Try title match first (most specific)
        if title:
            title_lower = title.lower()
            for pattern, playbook_id in cls.FINDING_TO_PLAYBOOK_MAP.items():
                if pattern in title_lower:
                    return REMEDIATION_PLAYBOOKS.get(playbook_id)
        
        # Try template ID match (for Nuclei findings)
        if template_id:
            template_lower = template_id.lower()
            for pattern, playbook_id in cls.FINDING_TO_PLAYBOOK_MAP.items():
                if pattern in template_lower:
                    return REMEDIATION_PLAYBOOKS.get(playbook_id)
        
        # Try CWE match (for vulnerability type-based remediation)
        if cwe_id:
            cwe_normalized = cwe_id.upper().replace("_", "-")
            if not cwe_normalized.startswith("CWE-"):
                cwe_normalized = f"CWE-{cwe_normalized}"
            
            if cwe_normalized in cls.CWE_TO_PLAYBOOK_MAP:
                return REMEDIATION_PLAYBOOKS.get(cls.CWE_TO_PLAYBOOK_MAP[cwe_normalized])
            # Also try lowercase
            if cwe_id.lower() in cls.CWE_TO_PLAYBOOK_MAP:
                return REMEDIATION_PLAYBOOKS.get(cls.CWE_TO_PLAYBOOK_MAP[cwe_id.lower()])
        
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
                # Web vulnerabilities
                if "ssrf" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("vuln-ssrf")
                if "sqli" in tag_lower or "sql-injection" in tag_lower or "injection" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("vuln-sqli")
                if "xss" in tag_lower or "cross-site" in tag_lower:
                    return REMEDIATION_PLAYBOOKS.get("vuln-xss")
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
                    return REMEDIATION_PLAYBOOKS.get("exposed-modbus")
        
        # If this is a CVE-based finding, return generic upgrade playbook
        if cve_id or (template_id and "cve" in template_id.lower()):
            return REMEDIATION_PLAYBOOKS.get("vuln-outdated-software")
        
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
