"""Risk Driver Service.

Calculates and populates meaningful risk drivers for assets based on:
- Login portal detection
- Technology fingerprinting (SAP, databases, admin panels, etc.)
- Open/risky ports
- Vulnerability count and severity
- Public accessibility
- Hosting classification

Risk drivers are stored in the asset's acs_drivers field and influence the ACS score.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# High-risk technology categories (from Wappalyzer)
HIGH_RISK_CATEGORIES = {
    "CRM": {"risk": "high", "reason": "Contains customer data"},
    "Database managers": {"risk": "critical", "reason": "Database administration interface"},
    "Databases": {"risk": "high", "reason": "Direct database access"},
    "Hosting panels": {"risk": "critical", "reason": "Server control panel"},
    "Control systems": {"risk": "critical", "reason": "Industrial control system"},
    "Remote access": {"risk": "critical", "reason": "Remote access service"},
    "Web mail": {"risk": "high", "reason": "Email access portal"},
    "Ecommerce": {"risk": "high", "reason": "Payment/transaction system"},
    "Payment processors": {"risk": "critical", "reason": "Payment processing"},
    "Accounting": {"risk": "high", "reason": "Financial system"},
    "Document management": {"risk": "medium", "reason": "Document storage"},
    "Network devices": {"risk": "high", "reason": "Network infrastructure"},
    "Network storage": {"risk": "high", "reason": "File storage system"},
    "Webcams": {"risk": "medium", "reason": "Surveillance system"},
    "CI": {"risk": "medium", "reason": "CI/CD pipeline"},
    "Issue trackers": {"risk": "medium", "reason": "Project management system"},
    "Authentication": {"risk": "high", "reason": "Authentication service"},
}

# High-risk technology names (specific products)
HIGH_RISK_TECHNOLOGIES = {
    # ERP/Business Systems
    "sap": {"risk": "critical", "reason": "SAP ERP System"},
    "oracle": {"risk": "critical", "reason": "Oracle Enterprise System"},
    "salesforce": {"risk": "high", "reason": "Salesforce CRM"},
    "dynamics": {"risk": "high", "reason": "Microsoft Dynamics"},
    "workday": {"risk": "high", "reason": "Workday HR System"},
    "netsuite": {"risk": "high", "reason": "NetSuite ERP"},
    
    # Databases
    "mysql": {"risk": "high", "reason": "MySQL Database"},
    "postgresql": {"risk": "high", "reason": "PostgreSQL Database"},
    "mongodb": {"risk": "high", "reason": "MongoDB Database"},
    "redis": {"risk": "high", "reason": "Redis Database"},
    "elasticsearch": {"risk": "high", "reason": "Elasticsearch"},
    "phpmyadmin": {"risk": "critical", "reason": "phpMyAdmin Database Admin"},
    "adminer": {"risk": "critical", "reason": "Adminer Database Admin"},
    "pgadmin": {"risk": "critical", "reason": "pgAdmin Database Admin"},
    
    # Admin/Control Panels
    "cpanel": {"risk": "critical", "reason": "cPanel Hosting Control"},
    "plesk": {"risk": "critical", "reason": "Plesk Hosting Control"},
    "webmin": {"risk": "critical", "reason": "Webmin Server Admin"},
    "directadmin": {"risk": "critical", "reason": "DirectAdmin Control Panel"},
    
    # Remote Access
    "citrix": {"risk": "critical", "reason": "Citrix Remote Access"},
    "vmware": {"risk": "high", "reason": "VMware Infrastructure"},
    "rdp": {"risk": "critical", "reason": "Remote Desktop"},
    "vnc": {"risk": "critical", "reason": "VNC Remote Access"},
    "teamviewer": {"risk": "high", "reason": "TeamViewer Remote Access"},
    
    # CI/CD
    "jenkins": {"risk": "high", "reason": "Jenkins CI/CD"},
    "gitlab": {"risk": "high", "reason": "GitLab DevOps"},
    "bamboo": {"risk": "high", "reason": "Bamboo CI/CD"},
    "teamcity": {"risk": "high", "reason": "TeamCity CI/CD"},
    
    # Email
    "exchange": {"risk": "high", "reason": "Microsoft Exchange"},
    "zimbra": {"risk": "high", "reason": "Zimbra Email"},
    "roundcube": {"risk": "medium", "reason": "Roundcube Webmail"},
    
    # CMS with known vulns
    "wordpress": {"risk": "medium", "reason": "WordPress CMS"},
    "drupal": {"risk": "medium", "reason": "Drupal CMS"},
    "joomla": {"risk": "medium", "reason": "Joomla CMS"},
    
    # Industrial/OT
    "scada": {"risk": "critical", "reason": "SCADA System"},
    "plc": {"risk": "critical", "reason": "PLC Controller"},
    "hmi": {"risk": "critical", "reason": "HMI Interface"},
    "rockwell": {"risk": "critical", "reason": "Rockwell Automation"},
    "siemens": {"risk": "critical", "reason": "Siemens Industrial"},
    "schneider": {"risk": "critical", "reason": "Schneider Electric"},
    "allen-bradley": {"risk": "critical", "reason": "Allen-Bradley PLC"},
}

# Risky ports and services
RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class RiskDriverService:
    """Service to calculate and populate risk drivers for assets."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def calculate_risk_drivers(self, asset: Asset) -> Dict[str, Any]:
        """
        Calculate risk drivers for an asset based on all available data.
        
        Returns a dictionary of risk drivers with their values and reasons.
        """
        drivers = {}
        
        # 1. Check for login portals
        if asset.has_login_portal:
            login_count = len(asset.login_portals or [])
            drivers["login_portal"] = {
                "value": True,
                "count": login_count,
                "risk": "high",
                "reason": f"Has {login_count} login portal(s) detected"
            }
        
        # 2. Check technologies
        tech_drivers = self._analyze_technologies(asset)
        if tech_drivers:
            drivers["technologies"] = tech_drivers
        
        # 3. Check risky ports
        port_drivers = self._analyze_ports(asset)
        if port_drivers:
            drivers["risky_ports"] = port_drivers
        
        # 4. Check vulnerabilities
        vuln_drivers = self._analyze_vulnerabilities(asset)
        if vuln_drivers:
            drivers["vulnerabilities"] = vuln_drivers
        
        # 5. Check public accessibility
        if asset.is_public:
            drivers["public_facing"] = {
                "value": True,
                "risk": "medium",
                "reason": "Publicly accessible from internet"
            }
        
        # 6. Check hosting type
        if asset.hosting_type == "owned":
            drivers["owned_infrastructure"] = {
                "value": True,
                "risk": "high",
                "reason": "Owned infrastructure (not CDN/cloud ephemeral)"
            }
        
        # 7. Calculate overall risk level
        drivers["overall_risk"] = self._calculate_overall_risk(drivers)
        
        return drivers
    
    def _analyze_technologies(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze detected technologies for risk factors."""
        if not asset.technologies:
            return None
        
        high_risk_techs = []
        
        for tech in asset.technologies:
            tech_name = tech.name.lower()
            categories = tech.categories or []
            
            # Check by technology name
            for pattern, info in HIGH_RISK_TECHNOLOGIES.items():
                if pattern in tech_name:
                    high_risk_techs.append({
                        "name": tech.name,
                        "risk": info["risk"],
                        "reason": info["reason"]
                    })
                    break
            else:
                # Check by category
                for category in categories:
                    if category in HIGH_RISK_CATEGORIES:
                        cat_info = HIGH_RISK_CATEGORIES[category]
                        high_risk_techs.append({
                            "name": tech.name,
                            "category": category,
                            "risk": cat_info["risk"],
                            "reason": cat_info["reason"]
                        })
                        break
        
        if not high_risk_techs:
            return None
        
        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        high_risk_techs.sort(key=lambda x: risk_order.get(x["risk"], 4))
        
        highest_risk = high_risk_techs[0]["risk"] if high_risk_techs else "low"
        
        return {
            "count": len(high_risk_techs),
            "risk": highest_risk,
            "items": high_risk_techs[:5],  # Top 5
            "reason": f"{len(high_risk_techs)} high-risk technologies detected"
        }
    
    def _analyze_ports(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze open ports for risk factors."""
        if not asset.port_services:
            return None
        
        risky_ports = []
        
        for port_service in asset.port_services:
            if port_service.is_risky or port_service.port in RISKY_PORTS:
                service_name = RISKY_PORTS.get(port_service.port, port_service.service or "Unknown")
                risky_ports.append({
                    "port": port_service.port,
                    "service": service_name,
                    "protocol": port_service.protocol
                })
        
        if not risky_ports:
            return None
        
        # Determine risk level based on what's exposed
        critical_ports = {23, 3389, 5900, 445, 135, 139}  # Telnet, RDP, VNC, SMB, etc.
        has_critical = any(p["port"] in critical_ports for p in risky_ports)
        
        return {
            "count": len(risky_ports),
            "risk": "critical" if has_critical else "high",
            "items": risky_ports[:10],  # Top 10
            "reason": f"{len(risky_ports)} risky port(s) exposed"
        }
    
    def _analyze_vulnerabilities(self, asset: Asset) -> Optional[Dict[str, Any]]:
        """Analyze vulnerabilities for risk factors."""
        if not asset.vulnerabilities:
            return None
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in asset.vulnerabilities:
            severity = (vuln.severity or "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total = sum(severity_counts.values())
        if total == 0:
            return None
        
        # Determine overall risk
        if severity_counts["critical"] > 0:
            risk = "critical"
        elif severity_counts["high"] > 0:
            risk = "high"
        elif severity_counts["medium"] > 0:
            risk = "medium"
        else:
            risk = "low"
        
        return {
            "total": total,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "risk": risk,
            "reason": f"{total} vulnerabilities ({severity_counts['critical']} critical, {severity_counts['high']} high)"
        }
    
    def _calculate_overall_risk(self, drivers: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk level from all drivers."""
        risk_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_risk = "low"
        max_score = 0
        risk_factors = []
        
        for key, value in drivers.items():
            if key == "overall_risk":
                continue
            if isinstance(value, dict) and "risk" in value:
                risk = value["risk"]
                score = risk_scores.get(risk, 0)
                if score > max_score:
                    max_score = score
                    max_risk = risk
                if score >= 3:  # high or critical
                    risk_factors.append(value.get("reason", key))
        
        return {
            "level": max_risk,
            "score": max_score,
            "factors": risk_factors[:5]  # Top 5 risk factors
        }
    
    def update_asset_risk_drivers(self, asset: Asset) -> Dict[str, Any]:
        """
        Calculate and update risk drivers for an asset.
        
        Returns the calculated drivers.
        """
        drivers = self.calculate_risk_drivers(asset)
        
        # Update the asset
        asset.acs_drivers = drivers
        
        # Optionally update ACS score based on risk
        overall = drivers.get("overall_risk", {})
        risk_level = overall.get("level", "low")
        
        # Map risk level to ACS score adjustment
        risk_to_acs = {
            "critical": 9,
            "high": 7,
            "medium": 5,
            "low": 3
        }
        
        # Only increase ACS if calculated risk is higher
        calculated_acs = risk_to_acs.get(risk_level, 5)
        if calculated_acs > asset.acs_score:
            asset.acs_score = calculated_acs
        
        self.db.commit()
        
        logger.info(f"Updated risk drivers for asset {asset.id} ({asset.value}): {risk_level} risk")
        
        return drivers
    
    def update_all_assets(
        self, 
        organization_id: Optional[int] = None,
        limit: int = 1000
    ) -> Dict[str, int]:
        """
        Update risk drivers for multiple assets.
        
        Args:
            organization_id: Optional filter by organization
            limit: Maximum assets to process
            
        Returns:
            Statistics about the update
        """
        query = self.db.query(Asset)
        
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
        
        assets = query.limit(limit).all()
        
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for asset in assets:
            drivers = self.update_asset_risk_drivers(asset)
            stats["total"] += 1
            
            overall = drivers.get("overall_risk", {})
            risk_level = overall.get("level", "low")
            if risk_level in stats:
                stats[risk_level] += 1
        
        logger.info(f"Updated risk drivers for {stats['total']} assets")
        return stats


def get_risk_driver_service(db: Session) -> RiskDriverService:
    """Factory function to create a RiskDriverService instance."""
    return RiskDriverService(db)
