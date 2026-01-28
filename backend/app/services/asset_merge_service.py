"""
Asset Merge Service

Merges related assets to follow the canonical model:
- Domain/subdomain is the primary asset
- IP addresses are attributes on the domain, not separate assets
- Findings, ports, and technologies are consolidated to the primary asset

Use cases:
1. Merge IP asset into its parent domain when IP was resolved from domain
2. Merge duplicate assets discovered from multiple sources
3. Clean up orphaned IP assets that belong to known domains
"""

import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset, AssetType, AssetStatus
from app.models.vulnerability import Vulnerability
from app.models.port_service import PortService
from app.models.screenshot import Screenshot

logger = logging.getLogger(__name__)


class AssetMergeService:
    """Service for merging related assets."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_mergeable_assets(
        self,
        organization_id: int,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Find assets that should be merged.
        
        Returns groups of assets that are related and should be merged:
        - IP assets that were resolved from a domain
        - Duplicate domains/subdomains
        """
        results = {
            "ip_to_domain_merges": [],
            "duplicate_domains": [],
            "total_mergeable": 0,
        }
        
        # Find IP assets that have resolved_from pointing to a domain
        ip_assets = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type == AssetType.IP_ADDRESS,
            Asset.resolved_from.isnot(None),
        ).all()
        
        for ip_asset in ip_assets:
            # Find the parent domain asset
            domain_asset = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == ip_asset.resolved_from,
                Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            ).first()
            
            if domain_asset:
                results["ip_to_domain_merges"].append({
                    "ip_asset_id": ip_asset.id,
                    "ip_value": ip_asset.value,
                    "domain_asset_id": domain_asset.id,
                    "domain_value": domain_asset.value,
                    "ip_vulns_count": len(ip_asset.vulnerabilities),
                    "ip_ports_count": len(ip_asset.port_services),
                })
                results["total_mergeable"] += 1
        
        # Find duplicate domains (same value, different records)
        duplicates = self.db.query(
            Asset.value,
            func.count(Asset.id).label('count')
        ).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).group_by(Asset.value).having(func.count(Asset.id) > 1).all()
        
        for value, count in duplicates:
            dup_assets = self.db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == value,
            ).order_by(Asset.created_at.asc()).all()
            
            results["duplicate_domains"].append({
                "value": value,
                "count": count,
                "asset_ids": [a.id for a in dup_assets],
                "primary_id": dup_assets[0].id if dup_assets else None,
            })
            results["total_mergeable"] += count - 1  # All but primary
        
        return results
    
    def merge_ip_into_domain(
        self,
        ip_asset_id: int,
        domain_asset_id: int,
        delete_ip_asset: bool = True,
    ) -> Dict[str, Any]:
        """
        Merge an IP asset into its parent domain asset.
        
        - Moves vulnerabilities from IP to domain
        - Moves port services from IP to domain
        - Moves screenshots from IP to domain
        - Updates the domain's ip_addresses field
        - Optionally deletes the IP asset
        """
        ip_asset = self.db.query(Asset).filter(Asset.id == ip_asset_id).first()
        domain_asset = self.db.query(Asset).filter(Asset.id == domain_asset_id).first()
        
        if not ip_asset or not domain_asset:
            raise ValueError("Asset not found")
        
        if ip_asset.asset_type != AssetType.IP_ADDRESS:
            raise ValueError(f"Asset {ip_asset_id} is not an IP address")
        
        if domain_asset.asset_type not in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            raise ValueError(f"Asset {domain_asset_id} is not a domain/subdomain")
        
        result = {
            "ip_asset_id": ip_asset_id,
            "domain_asset_id": domain_asset_id,
            "vulnerabilities_moved": 0,
            "ports_moved": 0,
            "screenshots_moved": 0,
            "ip_added": False,
        }
        
        # 1. Add IP to domain's ip_addresses
        ip_value = ip_asset.value
        current_ips = list(domain_asset.ip_addresses or [])
        if ip_value not in current_ips:
            domain_asset.add_ip_address(ip_value)
            result["ip_added"] = True
        
        # 2. Move vulnerabilities - update finding metadata to track the original IP
        for vuln in ip_asset.vulnerabilities:
            # Update metadata to track where finding was actually discovered
            metadata = dict(vuln.metadata_ or {})
            metadata["discovered_on_ip"] = ip_value
            metadata["merged_from_asset_id"] = ip_asset_id
            vuln.metadata_ = metadata
            
            # Move to domain asset
            vuln.asset_id = domain_asset_id
            result["vulnerabilities_moved"] += 1
        
        # 3. Move port services - track the scanned IP
        for port in ip_asset.port_services:
            # Check if domain already has this port
            existing_port = self.db.query(PortService).filter(
                PortService.asset_id == domain_asset_id,
                PortService.port == port.port,
                PortService.protocol == port.protocol,
            ).first()
            
            if existing_port:
                # Update existing with latest info
                existing_port.scanned_ip = ip_value
                existing_port.last_seen = datetime.utcnow()
                if port.service_name and not existing_port.service_name:
                    existing_port.service_name = port.service_name
                if port.banner and not existing_port.banner:
                    existing_port.banner = port.banner
            else:
                # Move port to domain
                port.asset_id = domain_asset_id
                port.scanned_ip = ip_value
                result["ports_moved"] += 1
        
        # 4. Move screenshots
        for screenshot in ip_asset.screenshots:
            screenshot.asset_id = domain_asset_id
            result["screenshots_moved"] += 1
        
        # 5. Merge metadata
        ip_meta = dict(ip_asset.metadata_ or {})
        domain_meta = dict(domain_asset.metadata_ or {})
        domain_meta["merged_ips"] = domain_meta.get("merged_ips", [])
        domain_meta["merged_ips"].append({
            "ip": ip_value,
            "merged_at": datetime.utcnow().isoformat(),
            "original_asset_id": ip_asset_id,
        })
        domain_asset.metadata_ = domain_meta
        
        # 6. Update domain with any enrichment from IP asset
        if ip_asset.system_type and not domain_asset.system_type:
            domain_asset.system_type = ip_asset.system_type
        if ip_asset.operating_system and not domain_asset.operating_system:
            domain_asset.operating_system = ip_asset.operating_system
        if ip_asset.device_class and not domain_asset.device_class:
            domain_asset.device_class = ip_asset.device_class
        if ip_asset.device_subclass and not domain_asset.device_subclass:
            domain_asset.device_subclass = ip_asset.device_subclass
        
        # Copy geo data if domain doesn't have it
        if ip_asset.country and not domain_asset.country:
            domain_asset.country = ip_asset.country
            domain_asset.country_code = ip_asset.country_code
            domain_asset.city = ip_asset.city
            domain_asset.region = ip_asset.region
            domain_asset.isp = ip_asset.isp
            domain_asset.asn = ip_asset.asn
        
        # 7. Delete IP asset if requested
        if delete_ip_asset:
            self.db.delete(ip_asset)
            result["ip_asset_deleted"] = True
        
        self.db.commit()
        
        logger.info(f"Merged IP {ip_value} into domain {domain_asset.value}: "
                   f"{result['vulnerabilities_moved']} vulns, {result['ports_moved']} ports")
        
        return result
    
    def merge_duplicate_domains(
        self,
        asset_ids: List[int],
    ) -> Dict[str, Any]:
        """
        Merge duplicate domain assets into one.
        
        The oldest asset (lowest ID) becomes the primary.
        All findings, ports, etc. are moved to the primary.
        """
        if len(asset_ids) < 2:
            raise ValueError("Need at least 2 assets to merge")
        
        assets = self.db.query(Asset).filter(
            Asset.id.in_(asset_ids)
        ).order_by(Asset.created_at.asc()).all()
        
        if len(assets) < 2:
            raise ValueError("Could not find all assets")
        
        primary = assets[0]
        duplicates = assets[1:]
        
        result = {
            "primary_id": primary.id,
            "primary_value": primary.value,
            "merged_count": len(duplicates),
            "merged_ids": [a.id for a in duplicates],
            "vulnerabilities_moved": 0,
            "ports_moved": 0,
        }
        
        for dup in duplicates:
            # Move vulnerabilities
            for vuln in dup.vulnerabilities:
                # Check for duplicate finding
                existing = self.db.query(Vulnerability).filter(
                    Vulnerability.asset_id == primary.id,
                    Vulnerability.template_id == vuln.template_id,
                    Vulnerability.title == vuln.title,
                ).first()
                
                if existing:
                    # Update existing with any new info
                    if vuln.last_seen and (not existing.last_seen or vuln.last_seen > existing.last_seen):
                        existing.last_seen = vuln.last_seen
                    self.db.delete(vuln)
                else:
                    vuln.asset_id = primary.id
                    result["vulnerabilities_moved"] += 1
            
            # Move ports
            for port in dup.port_services:
                existing = self.db.query(PortService).filter(
                    PortService.asset_id == primary.id,
                    PortService.port == port.port,
                    PortService.protocol == port.protocol,
                ).first()
                
                if existing:
                    # Update existing
                    if port.last_seen and (not existing.last_seen or port.last_seen > existing.last_seen):
                        existing.last_seen = port.last_seen
                    self.db.delete(port)
                else:
                    port.asset_id = primary.id
                    result["ports_moved"] += 1
            
            # Move screenshots
            for ss in dup.screenshots:
                ss.asset_id = primary.id
            
            # Merge IPs
            if dup.ip_addresses:
                for ip in dup.ip_addresses:
                    primary.add_ip_address(ip)
            
            # Merge discovery sources
            if dup.discovery_source and dup.discovery_source != primary.discovery_source:
                primary_sources = (primary.discovery_source or "").split(",")
                if dup.discovery_source not in primary_sources:
                    primary.discovery_source = f"{primary.discovery_source},{dup.discovery_source}"
            
            # Delete duplicate
            self.db.delete(dup)
        
        self.db.commit()
        
        logger.info(f"Merged {len(duplicates)} duplicates into asset {primary.id} ({primary.value})")
        
        return result
    
    def run_full_merge(
        self,
        organization_id: int,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Run full asset merge for an organization.
        
        1. Merge IP assets into their parent domains
        2. Merge duplicate domain records
        """
        results = {
            "dry_run": dry_run,
            "organization_id": organization_id,
            "ip_merges": [],
            "domain_merges": [],
            "errors": [],
        }
        
        # Find mergeable assets
        mergeable = self.find_mergeable_assets(organization_id, dry_run=True)
        
        if dry_run:
            return {
                "dry_run": True,
                "preview": mergeable,
                "message": "Set dry_run=false to execute merges",
            }
        
        # Execute IP to domain merges
        for merge in mergeable["ip_to_domain_merges"]:
            try:
                result = self.merge_ip_into_domain(
                    merge["ip_asset_id"],
                    merge["domain_asset_id"],
                    delete_ip_asset=True,
                )
                results["ip_merges"].append(result)
            except Exception as e:
                logger.error(f"Error merging IP {merge['ip_asset_id']}: {e}")
                results["errors"].append({
                    "type": "ip_merge",
                    "ip_asset_id": merge["ip_asset_id"],
                    "error": str(e),
                })
        
        # Execute duplicate domain merges
        for dup in mergeable["duplicate_domains"]:
            try:
                result = self.merge_duplicate_domains(dup["asset_ids"])
                results["domain_merges"].append(result)
            except Exception as e:
                logger.error(f"Error merging duplicates for {dup['value']}: {e}")
                results["errors"].append({
                    "type": "domain_merge",
                    "value": dup["value"],
                    "error": str(e),
                })
        
        results["summary"] = {
            "ip_merges_completed": len(results["ip_merges"]),
            "domain_merges_completed": len(results["domain_merges"]),
            "errors": len(results["errors"]),
        }
        
        return results


def get_asset_merge_service(db: Session) -> AssetMergeService:
    """Get an instance of the asset merge service."""
    return AssetMergeService(db)
