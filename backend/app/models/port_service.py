"""Port and Service model for tracking exposed services on assets."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


class Protocol(str, enum.Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class PortState(str, enum.Enum):
    """Port state from scanning."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"


class PortService(Base):
    """
    Port and Service model for tracking exposed services on assets.
    
    Structure: port-protocol-service
    Example: 443-tcp-https, 22-tcp-ssh, 53-udp-dns
    """
    
    __tablename__ = "port_services"
    
    # Ensure unique port-protocol-asset combination
    __table_args__ = (
        UniqueConstraint('asset_id', 'port', 'protocol', name='unique_asset_port_protocol'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Port identification
    port = Column(Integer, nullable=False, index=True)
    protocol = Column(Enum(Protocol), default=Protocol.TCP, nullable=False, index=True)
    
    # Service identification
    service_name = Column(String(100), nullable=True, index=True)  # e.g., "https", "ssh", "mysql"
    service_product = Column(String(255), nullable=True)  # e.g., "nginx", "OpenSSH"
    service_version = Column(String(100), nullable=True)  # e.g., "1.18.0", "8.4"
    service_extra_info = Column(String(500), nullable=True)  # Additional service info
    
    # CPE (Common Platform Enumeration) for vulnerability mapping
    cpe = Column(String(255), nullable=True)  # e.g., "cpe:/a:nginx:nginx:1.18.0"
    
    # Banner/fingerprint
    banner = Column(Text, nullable=True)  # Raw banner grabbed from service
    
    # Port state
    state = Column(Enum(PortState), default=PortState.OPEN, index=True)
    reason = Column(String(100), nullable=True)  # Why port is in this state (e.g., "syn-ack")
    
    # Asset relationship
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    asset = relationship("Asset", back_populates="port_services")
    
    # Discovery info
    discovered_by = Column(String(100), nullable=True)  # Scanner that found this (naabu, nmap, etc.)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # TLS/SSL info (for secure ports)
    is_ssl = Column(Boolean, default=False)
    ssl_version = Column(String(50), nullable=True)  # e.g., "TLSv1.3"
    ssl_cipher = Column(String(100), nullable=True)
    ssl_cert_subject = Column(String(500), nullable=True)
    ssl_cert_issuer = Column(String(500), nullable=True)
    ssl_cert_expiry = Column(DateTime, nullable=True)
    
    # Risk assessment
    is_risky = Column(Boolean, default=False)  # Flagged as potentially risky
    risk_reason = Column(String(500), nullable=True)  # Why it's risky
    
    # Tags and metadata
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def port_string(self) -> str:
        """Get port-protocol-service string representation."""
        service = self.service_name or "unknown"
        return f"{self.port}-{self.protocol.value}-{service}"
    
    @property
    def display_name(self) -> str:
        """Get human-readable display name."""
        parts = [f"{self.port}/{self.protocol.value}"]
        if self.service_name:
            parts.append(self.service_name)
        if self.service_product:
            parts.append(f"({self.service_product}")
            if self.service_version:
                parts[-1] += f" {self.service_version}"
            parts[-1] += ")"
        return " ".join(parts)
    
    def __repr__(self):
        return f"<PortService {self.port_string}>"


# Common risky ports that should be flagged
RISKY_PORTS = {
    21: "FTP - often allows anonymous access",
    22: "SSH - brute force target",
    23: "Telnet - unencrypted protocol",
    25: "SMTP - can be used for relay",
    53: "DNS - zone transfer possible",
    110: "POP3 - unencrypted email",
    111: "RPC - information disclosure",
    135: "MSRPC - Windows exploitation",
    139: "NetBIOS - Windows file sharing",
    143: "IMAP - unencrypted email",
    161: "SNMP - information disclosure",
    389: "LDAP - directory access",
    445: "SMB - ransomware vector",
    512: "rexec - remote execution",
    513: "rlogin - remote login",
    514: "rsh - remote shell",
    1433: "MSSQL - database access",
    1521: "Oracle - database access",
    2049: "NFS - file sharing",
    3306: "MySQL - database access",
    3389: "RDP - remote desktop",
    5432: "PostgreSQL - database access",
    5900: "VNC - remote desktop",
    5984: "CouchDB - NoSQL database",
    6379: "Redis - in-memory database",
    8080: "HTTP-Alt - web proxy",
    9200: "Elasticsearch - database",
    11211: "Memcached - cache server",
    27017: "MongoDB - NoSQL database",
}


# Common service name mappings
SERVICE_NAMES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpc",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    520: "rip",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1434: "mssql-m",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-ssl",
    3000: "grafana",
    3306: "mysql",
    3389: "rdp",
    4443: "https-alt",
    5000: "upnp",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "cslistener",
    9090: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq",
    27017: "mongodb",
    28017: "mongodb-web",
}




