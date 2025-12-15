"""
Nuclei findings import service.

Maps Nuclei scan results to the Vulnerability model and creates
proper security findings with all relevant metadata.
"""

import logging
import re
from typing import Optional, List
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.scan import Scan
from app.services.nuclei_service import NucleiResult, NucleiScanResult

logger = logging.getLogger(__name__)


# Map Nuclei severity to our Severity enum
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiFindingsService:
    """
    Service for importing Nuclei scan results into the vulnerabilities table.
    
    Handles:
    - Severity mapping from Nuclei to internal model
    - Asset lookup/creation
    - CVE/CWE extraction
    - Deduplication of findings
    - Label/tag creation on assets
    """
    
    def __init__(self, db: Session):
        """
        Initialize the service.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def import_scan_results(
        self,
        scan_result: NucleiScanResult,
        organization_id: int,
        scan_id: Optional[int] = None,
        create_assets: bool = True,
        create_labels: bool = True
    ) -> dict:
        """
        Import all findings from a Nuclei scan result.
        
        Args:
            scan_result: Complete Nuclei scan result
            organization_id: Organization to associate findings with
            scan_id: Optional scan record ID
            create_assets: Create assets for unknown hosts
            create_labels: Create technology/CVE labels on assets
            
        Returns:
            Summary of import results
        """
        summary = {
            "findings_created": 0,
            "findings_updated": 0,
            "assets_created": 0,
            "labels_created": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "cves_found": set(),
            "errors": []
        }
        
        for nuclei_result in scan_result.findings:
            try:
                result = self.import_single_finding(
                    nuclei_result=nuclei_result,
                    organization_id=organization_id,
                    scan_id=scan_id,
                    create_assets=create_assets,
                    create_labels=create_labels
                )
                
                if result.get("created"):
                    summary["findings_created"] += 1
                    severity = nuclei_result.severity.lower()
                    if severity in summary["by_severity"]:
                        summary["by_severity"][severity] += 1
                elif result.get("updated"):
                    summary["findings_updated"] += 1
                
                if result.get("asset_created"):
                    summary["assets_created"] += 1
                
                if result.get("labels_added"):
                    summary["labels_created"] += result["labels_added"]
                
                if nuclei_result.cve_id:
                    summary["cves_found"].add(nuclei_result.cve_id)
                    
            except Exception as e:
                logger.error(f"Error importing finding {nuclei_result.template_id}: {e}")
                summary["errors"].append(f"{nuclei_result.template_id}: {str(e)}")
        
        self.db.commit()
        
        # Convert set to list for JSON serialization
        summary["cves_found"] = list(summary["cves_found"])
        
        logger.info(
            f"Nuclei import complete: {summary['findings_created']} created, "
            f"{summary['findings_updated']} updated"
        )
        
        return summary
    
    def import_single_finding(
        self,
        nuclei_result: NucleiResult,
        organization_id: int,
        scan_id: Optional[int] = None,
        create_assets: bool = True,
        create_labels: bool = True
    ) -> dict:
        """
        Import a single Nuclei finding into the vulnerabilities table.
        
        Args:
            nuclei_result: Single Nuclei scan result
            organization_id: Organization ID
            scan_id: Optional scan ID
            create_assets: Create asset if not found
            create_labels: Add labels to asset
            
        Returns:
            Result dict with created/updated status
        """
        result = {
            "created": False,
            "updated": False,
            "asset_created": False,
            "labels_added": 0,
            "vulnerability_id": None
        }
        
        # Find or create the asset
        asset = self._find_or_create_asset(
            nuclei_result, organization_id, create_assets
        )
        
        if not asset:
            logger.warning(f"No asset found for {nuclei_result.host}")
            return result
        
        if create_assets and asset.id is None:
            result["asset_created"] = True
        
        # Check for existing finding
        existing = self._find_existing_vulnerability(asset.id, nuclei_result)
        
        if existing:
            # Update existing finding
            self._update_vulnerability(existing, nuclei_result)
            result["updated"] = True
            result["vulnerability_id"] = existing.id
        else:
            # Create new finding
            vulnerability = self._create_vulnerability(
                asset, nuclei_result, scan_id
            )
            self.db.add(vulnerability)
            self.db.flush()
            result["created"] = True
            result["vulnerability_id"] = vulnerability.id
        
        # Add labels to asset
        if create_labels:
            labels_added = self._add_asset_labels(asset, nuclei_result)
            result["labels_added"] = labels_added
        
        return result
    
    def _find_or_create_asset(
        self,
        nuclei_result: NucleiResult,
        organization_id: int,
        create: bool
    ) -> Optional[Asset]:
        """Find or create asset for the Nuclei finding."""
        # Extract host info
        host = nuclei_result.host
        ip = nuclei_result.ip
        
        # Try to parse URL to get hostname
        if host.startswith(("http://", "https://")):
            parsed = urlparse(host)
            hostname = parsed.netloc.split(":")[0]
        else:
            hostname = host.split(":")[0]
        
        # First, try to find by exact host/value match
        asset = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == hostname
        ).first()
        
        # Try by IP if we have one
        if not asset and ip:
            asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == ip
            ).first()
        
        # Try to find by URL match
        if not asset and host.startswith(("http://", "https://")):
            asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host
            ).first()
        
        # Create if requested
        if not asset and create:
            # Determine asset type
            asset_type = self._determine_asset_type(hostname, ip)
            
            asset = Asset(
                organization_id=organization_id,
                name=hostname,
                value=hostname,
                asset_type=asset_type,
                discovery_source="nuclei"
            )
            self.db.add(asset)
            self.db.flush()
        
        return asset
    
    def _determine_asset_type(self, hostname: str, ip: Optional[str]) -> AssetType:
        """Determine the asset type from hostname/IP."""
        # Check if it's an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, hostname):
            return AssetType.IP_ADDRESS
        
        # Check for IPv6
        if ":" in hostname and not hostname.startswith("http"):
            return AssetType.IP_ADDRESS
        
        # Default to domain/subdomain
        if hostname.count(".") > 1:
            return AssetType.SUBDOMAIN
        
        return AssetType.DOMAIN
    
    def _find_existing_vulnerability(
        self,
        asset_id: int,
        nuclei_result: NucleiResult
    ) -> Optional[Vulnerability]:
        """Find existing vulnerability matching this finding."""
        # Match by template_id and asset
        existing = self.db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset_id,
            Vulnerability.template_id == nuclei_result.template_id,
            Vulnerability.status.in_([
                VulnerabilityStatus.OPEN,
                VulnerabilityStatus.IN_PROGRESS
            ])
        ).first()
        
        if existing:
            return existing
        
        # Also check by CVE if available
        if nuclei_result.cve_id:
            existing = self.db.query(Vulnerability).filter(
                Vulnerability.asset_id == asset_id,
                Vulnerability.cve_id == nuclei_result.cve_id,
                Vulnerability.status.in_([
                    VulnerabilityStatus.OPEN,
                    VulnerabilityStatus.IN_PROGRESS
                ])
            ).first()
        
        return existing
    
    def _create_vulnerability(
        self,
        asset: Asset,
        nuclei_result: NucleiResult,
        scan_id: Optional[int]
    ) -> Vulnerability:
        """Create a new Vulnerability from Nuclei result."""
        # Map severity
        severity = NUCLEI_SEVERITY_MAP.get(
            nuclei_result.severity.lower(),
            Severity.INFO
        )
        
        # Build title
        title = nuclei_result.template_name or nuclei_result.template_id
        if nuclei_result.cve_id:
            title = f"[{nuclei_result.cve_id}] {title}"
        
        # Build description
        description = nuclei_result.description or ""
        if nuclei_result.matched_at:
            description += f"\n\n**Matched at:** {nuclei_result.matched_at}"
        if nuclei_result.extracted_results:
            description += f"\n\n**Extracted data:**\n"
            for extract in nuclei_result.extracted_results[:10]:  # Limit to 10
                description += f"- {extract}\n"
        
        # Build evidence
        evidence = f"Nuclei template {nuclei_result.template_id} matched"
        if nuclei_result.matcher_name:
            evidence += f" (matcher: {nuclei_result.matcher_name})"
        if nuclei_result.curl_command:
            evidence += f"\n\nReproduction:\n```\n{nuclei_result.curl_command}\n```"
        
        # Build tags
        tags = list(nuclei_result.tags) if nuclei_result.tags else []
        tags.append(f"nuclei:{nuclei_result.template_id}")
        if nuclei_result.cve_id:
            tags.append(f"cve:{nuclei_result.cve_id}")
        tags.append(f"severity:{severity.value}")
        
        # Build references
        references = nuclei_result.reference if nuclei_result.reference else []
        if nuclei_result.cve_id:
            references.append(f"https://nvd.nist.gov/vuln/detail/{nuclei_result.cve_id}")
            references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={nuclei_result.cve_id}")
        
        vulnerability = Vulnerability(
            title=title,
            description=description,
            severity=severity,
            cvss_score=nuclei_result.cvss_score,
            cve_id=nuclei_result.cve_id,
            cwe_id=nuclei_result.cwe_id,
            references=references,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="nuclei",
            template_id=nuclei_result.template_id,
            matcher_name=nuclei_result.matcher_name,
            status=VulnerabilityStatus.OPEN,
            evidence=evidence,
            tags=tags,
            metadata_={
                "nuclei_host": nuclei_result.host,
                "nuclei_ip": nuclei_result.ip,
                "nuclei_matched_at": nuclei_result.matched_at,
                "nuclei_timestamp": nuclei_result.timestamp.isoformat() if nuclei_result.timestamp else None,
                "nuclei_extracted_results": nuclei_result.extracted_results[:10] if nuclei_result.extracted_results else [],
            }
        )
        
        return vulnerability
    
    def _update_vulnerability(
        self,
        vulnerability: Vulnerability,
        nuclei_result: NucleiResult
    ) -> None:
        """Update existing vulnerability with new scan data."""
        vulnerability.last_detected = datetime.utcnow()
        
        # Update extracted results if new ones found
        if nuclei_result.extracted_results:
            if vulnerability.metadata_ is None:
                vulnerability.metadata_ = {}
            vulnerability.metadata_["nuclei_extracted_results"] = nuclei_result.extracted_results[:10]
            vulnerability.metadata_["last_scan_timestamp"] = datetime.utcnow().isoformat()
        
        # Potentially update severity if it changed (unusual but possible)
        new_severity = NUCLEI_SEVERITY_MAP.get(nuclei_result.severity.lower(), Severity.INFO)
        if new_severity.value != vulnerability.severity.value:
            # Only upgrade severity, never downgrade
            severity_order = ["info", "low", "medium", "high", "critical"]
            if severity_order.index(new_severity.value) > severity_order.index(vulnerability.severity.value):
                vulnerability.severity = new_severity
                
                # Update tags
                if vulnerability.tags:
                    vulnerability.tags = [t for t in vulnerability.tags if not t.startswith("severity:")]
                    vulnerability.tags.append(f"severity:{new_severity.value}")
    
    def _add_asset_labels(
        self,
        asset: Asset,
        nuclei_result: NucleiResult
    ) -> int:
        """Add labels/tags to asset based on finding."""
        labels_added = 0
        
        # Ensure asset has tags list
        if asset.tags is None:
            asset.tags = []
        
        existing_tags = set(asset.tags)
        new_tags = []
        
        # Add severity label
        severity_label = f"vuln:{nuclei_result.severity.lower()}"
        if severity_label not in existing_tags:
            new_tags.append(severity_label)
        
        # Add CVE label
        if nuclei_result.cve_id:
            cve_label = f"cve:{nuclei_result.cve_id}"
            if cve_label not in existing_tags:
                new_tags.append(cve_label)
        
        # Add technology labels from tags
        tech_tags = ["wordpress", "drupal", "joomla", "magento", "nginx", "apache", 
                     "iis", "tomcat", "jenkins", "gitlab", "aws", "azure", "gcp",
                     "php", "java", "python", "nodejs", "docker", "kubernetes"]
        
        for tag in (nuclei_result.tags or []):
            tag_lower = tag.lower()
            if tag_lower in tech_tags:
                tech_label = f"tech:{tag_lower}"
                if tech_label not in existing_tags:
                    new_tags.append(tech_label)
        
        # Add template category labels
        category_tags = ["rce", "sqli", "xss", "ssrf", "lfi", "xxe", "ssti", 
                        "auth-bypass", "misconfig", "exposure", "default-login"]
        
        for tag in (nuclei_result.tags or []):
            tag_lower = tag.lower()
            if tag_lower in category_tags:
                cat_label = f"vuln-type:{tag_lower}"
                if cat_label not in existing_tags:
                    new_tags.append(cat_label)
        
        # Update asset tags
        if new_tags:
            asset.tags = list(existing_tags) + new_tags
            labels_added = len(new_tags)
        
        return labels_added
    
    def get_findings_summary(
        self,
        organization_id: int,
        scan_id: Optional[int] = None
    ) -> dict:
        """Get summary of Nuclei findings for an organization."""
        query = self.db.query(Vulnerability).filter(
            Vulnerability.detected_by == "nuclei"
        ).join(Asset).filter(
            Asset.organization_id == organization_id
        )
        
        if scan_id:
            query = query.filter(Vulnerability.scan_id == scan_id)
        
        findings = query.all()
        
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_template = {}
        cves = set()
        
        for f in findings:
            by_severity[f.severity.value] += 1
            
            if f.template_id:
                by_template[f.template_id] = by_template.get(f.template_id, 0) + 1
            
            if f.cve_id:
                cves.add(f.cve_id)
        
        # Top templates
        top_templates = sorted(
            by_template.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "unique_cves": len(cves),
            "cves": list(cves)[:50],  # Limit for response size
            "top_templates": [{"template": t, "count": c} for t, c in top_templates],
            "critical_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "asset": f.asset.value if f.asset else None,
                    "cve": f.cve_id
                }
                for f in findings if f.severity == Severity.CRITICAL
            ][:20]
        }
    
    def close_stale_findings(
        self,
        organization_id: int,
        scan_id: int,
        days_threshold: int = 30
    ) -> int:
        """
        Close findings that haven't been detected in recent scans.
        
        Useful for cleanup after regular scanning.
        
        Args:
            organization_id: Organization ID
            scan_id: Current scan ID
            days_threshold: Close findings not seen in this many days
            
        Returns:
            Number of findings closed
        """
        from datetime import timedelta
        
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)
        
        stale_findings = self.db.query(Vulnerability).filter(
            Vulnerability.detected_by == "nuclei",
            Vulnerability.status == VulnerabilityStatus.OPEN,
            Vulnerability.last_detected < threshold_date
        ).join(Asset).filter(
            Asset.organization_id == organization_id
        ).all()
        
        closed_count = 0
        for finding in stale_findings:
            finding.status = VulnerabilityStatus.RESOLVED
            finding.resolved_at = datetime.utcnow()
            closed_count += 1
        
        if closed_count:
            self.db.commit()
            logger.info(f"Closed {closed_count} stale Nuclei findings")
        
        return closed_count














