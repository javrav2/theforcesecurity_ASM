"""
Data Normalizer Service

Converts raw output from any data source/scanner to the unified ASMDataModel.
This enables consistent handling of all scan results regardless of source.

Usage:
    normalizer = DataNormalizerService()
    
    # From raw JSON
    findings = normalizer.normalize_json(DataSourceType.NAABU, raw_json)
    
    # From raw output string
    findings = normalizer.normalize_output(DataSourceType.NUCLEI, raw_output)
"""

import json
import re
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from xml.etree import ElementTree

from app.schemas.data_sources import (
    ASMDataModel,
    DataSourceType,
    FindingCategory,
    SeverityLevel,
    ConfidenceLevel,
    PortState,
    Protocol,
    DataSourceMapping,
    FieldMapping,
    DATA_SOURCE_MAPPINGS,
    get_source_mapping,
)

logger = logging.getLogger(__name__)


class DataNormalizerService:
    """
    Normalizes output from any data source to the unified ASMDataModel.
    
    Supports:
    - JSON output (most ProjectDiscovery tools)
    - XML output (nmap)
    - Text output (simple line-based tools)
    """
    
    def __init__(self):
        self.mappings = DATA_SOURCE_MAPPINGS
    
    # =========================================================================
    # Main Normalization Methods
    # =========================================================================
    
    def normalize(
        self,
        source: DataSourceType,
        data: Union[str, Dict, List],
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """
        Normalize data from any source to ASMDataModel.
        
        Args:
            source: The data source type
            data: Raw data (JSON string, dict, list, or raw output)
            target: Original scan target
            organization_id: Organization ID
            scan_id: Scan ID
            
        Returns:
            List of normalized ASMDataModel findings
        """
        mapping = get_source_mapping(source)
        if not mapping:
            logger.warning(f"No mapping found for source: {source}")
            return []
        
        # Parse data if string
        if isinstance(data, str):
            if mapping.output_format == "json":
                data = self._parse_json_lines(data)
            elif mapping.output_format == "xml":
                return self._normalize_xml(source, data, target, organization_id, scan_id)
            else:
                return self._normalize_text(source, data, target, organization_id, scan_id)
        
        # Handle list vs single dict
        if isinstance(data, dict):
            data = [data]
        
        findings = []
        for item in data:
            finding = self._normalize_item(mapping, item, target, organization_id, scan_id)
            if finding:
                findings.append(finding)
        
        return findings
    
    def normalize_json(
        self,
        source: DataSourceType,
        json_data: Union[str, Dict, List],
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """Normalize JSON output from a tool."""
        return self.normalize(source, json_data, target, organization_id, scan_id)
    
    def normalize_output(
        self,
        source: DataSourceType,
        raw_output: str,
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """Normalize raw string output from a tool."""
        return self.normalize(source, raw_output, target, organization_id, scan_id)
    
    # =========================================================================
    # Item Normalization
    # =========================================================================
    
    def _normalize_item(
        self,
        mapping: DataSourceMapping,
        item: Dict[str, Any],
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> Optional[ASMDataModel]:
        """Normalize a single item using the source mapping."""
        try:
            # Start with default values
            data = {
                "source": mapping.source,
                "category": mapping.category,
                "target": target or "",
                "organization_id": organization_id,
                "scan_id": scan_id,
                "timestamp": datetime.utcnow(),
            }
            
            # Apply default values from mapping
            for key, value in mapping.default_values.items():
                data[key] = value
            
            # Apply field mappings
            for fm in mapping.field_mappings:
                value = self._extract_value(item, fm.source_field)
                if value is not None:
                    transformed = self._transform_value(value, fm.transform)
                    if transformed is not None:
                        data[fm.model_field] = transformed
            
            # Generate title if not set
            if not data.get("title"):
                data["title"] = self._generate_title(mapping.category, data)
            
            # Set target from extracted data if not provided
            if not data.get("target"):
                data["target"] = data.get("hostname") or data.get("ip_address") or data.get("url") or ""
            
            return ASMDataModel(**data)
            
        except Exception as e:
            logger.error(f"Error normalizing item from {mapping.source}: {e}")
            return None
    
    # =========================================================================
    # Value Extraction & Transformation
    # =========================================================================
    
    def _extract_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract value from nested dict using dot notation path.
        
        Supports:
        - Simple paths: "host"
        - Nested paths: "info.name"
        - Array paths: "ports[].port"
        """
        if not path or not data:
            return None
        
        # Handle array notation
        if "[]" in path:
            parts = path.split("[]")
            if len(parts) == 2:
                array_key = parts[0].strip(".")
                item_path = parts[1].strip(".")
                array = self._get_nested(data, array_key)
                if isinstance(array, list) and array:
                    if item_path:
                        return [self._get_nested(item, item_path) for item in array if isinstance(item, dict)]
                    return array
            return None
        
        return self._get_nested(data, path)
    
    def _get_nested(self, data: Dict[str, Any], path: str) -> Any:
        """Get nested value using dot notation."""
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
            
            if value is None:
                return None
        
        return value
    
    def _transform_value(self, value: Any, transform: Optional[str]) -> Any:
        """Apply transformation to a value."""
        if transform is None or value is None:
            return value
        
        try:
            if transform == "lowercase":
                return str(value).lower()
            
            elif transform == "uppercase":
                return str(value).upper()
            
            elif transform == "to_float":
                return float(value)
            
            elif transform == "to_int":
                return int(value)
            
            elif transform == "to_bool":
                if isinstance(value, bool):
                    return value
                return str(value).lower() in ("true", "1", "yes")
            
            elif transform == "first_item":
                if isinstance(value, list) and value:
                    return value[0]
                return value
            
            elif transform == "array":
                if isinstance(value, list):
                    return value
                return [value] if value else []
            
            elif transform == "split_comma":
                if isinstance(value, str):
                    return [v.strip() for v in value.split(",")]
                return value if isinstance(value, list) else [value]
            
            elif transform == "split_newline":
                if isinstance(value, str):
                    return [v.strip() for v in value.split("\n") if v.strip()]
                return value if isinstance(value, list) else [value]
            
            elif transform == "parse_date":
                return self._parse_date(value)
            
            elif transform == "parse_iso":
                if isinstance(value, str):
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                return value
            
            elif transform == "unix_to_datetime":
                if isinstance(value, (int, float)):
                    return datetime.utcfromtimestamp(value)
                return value
            
            elif transform == "wayback_date":
                # Wayback timestamp format: YYYYMMDDHHmmss
                if isinstance(value, str) and len(value) >= 14:
                    return datetime.strptime(value[:14], "%Y%m%d%H%M%S")
                return value
            
            elif transform == "parse_duration":
                # Parse duration strings like "123ms" or "1.5s"
                if isinstance(value, str):
                    match = re.match(r"([\d.]+)(ms|s)?", value)
                    if match:
                        num = float(match.group(1))
                        unit = match.group(2) or "ms"
                        if unit == "s":
                            num *= 1000
                        return num
                return value
            
            else:
                logger.warning(f"Unknown transform: {transform}")
                return value
                
        except Exception as e:
            logger.warning(f"Transform {transform} failed: {e}")
            return value
    
    def _parse_date(self, value: Any) -> Optional[datetime]:
        """Parse various date formats."""
        if isinstance(value, datetime):
            return value
        
        if not isinstance(value, str):
            return None
        
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%m/%d/%Y",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        
        # Try ISO format
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        
        return None
    
    # =========================================================================
    # Format-Specific Parsing
    # =========================================================================
    
    def _parse_json_lines(self, output: str) -> List[Dict]:
        """Parse JSON lines (one JSON object per line)."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results
    
    def _normalize_xml(
        self,
        source: DataSourceType,
        xml_content: str,
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """Normalize XML output (primarily for nmap)."""
        if source != DataSourceType.NMAP:
            return []
        
        return self._parse_nmap_xml(xml_content, target, organization_id, scan_id)
    
    def _parse_nmap_xml(
        self,
        xml_content: str,
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """Parse nmap XML output."""
        findings = []
        
        try:
            root = ElementTree.fromstring(xml_content)
        except ElementTree.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return []
        
        for host in root.findall(".//host"):
            # Get host address
            address = host.find("address")
            if address is None:
                continue
            
            ip_address = address.get("addr")
            
            # Get hostname
            hostname = None
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hostname_elem = hostnames.find("hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name")
            
            # Get ports
            ports = host.find("ports")
            if ports is None:
                continue
            
            for port in ports.findall("port"):
                port_num = int(port.get("portid", 0))
                protocol = port.get("protocol", "tcp").lower()
                
                # Get state
                state_elem = port.find("state")
                port_state = PortState.OPEN
                reason = None
                if state_elem is not None:
                    state_str = state_elem.get("state", "open").lower()
                    if state_str in [s.value for s in PortState]:
                        port_state = PortState(state_str)
                    reason = state_elem.get("reason")
                
                # Get service info
                service = port.find("service")
                service_name = None
                service_product = None
                service_version = None
                service_extra = None
                cpe = None
                
                if service is not None:
                    service_name = service.get("name")
                    service_product = service.get("product")
                    service_version = service.get("version")
                    service_extra = service.get("extrainfo")
                    
                    cpe_elem = service.find("cpe")
                    if cpe_elem is not None:
                        cpe = cpe_elem.text
                
                # Get banner from scripts
                banner = None
                for script in port.findall("script"):
                    if script.get("id") == "banner":
                        banner = script.get("output")
                        break
                
                finding = ASMDataModel(
                    source=DataSourceType.NMAP,
                    category=FindingCategory.PORT,
                    target=target or ip_address or "",
                    hostname=hostname,
                    ip_address=ip_address,
                    port=port_num,
                    protocol=Protocol(protocol) if protocol in [p.value for p in Protocol] else Protocol.TCP,
                    port_state=port_state,
                    service_name=service_name,
                    service_product=service_product,
                    service_version=service_version,
                    service_extra_info=service_extra,
                    banner=banner,
                    cpe=cpe,
                    risk_reason=reason,
                    title=f"Port {port_num}/{protocol} Open",
                    severity=SeverityLevel.INFO,
                    confidence=ConfidenceLevel.CONFIRMED,
                    organization_id=organization_id,
                    scan_id=scan_id,
                )
                findings.append(finding)
        
        return findings
    
    def _normalize_text(
        self,
        source: DataSourceType,
        text_content: str,
        target: Optional[str] = None,
        organization_id: Optional[int] = None,
        scan_id: Optional[int] = None,
    ) -> List[ASMDataModel]:
        """Normalize plain text output (one item per line)."""
        mapping = get_source_mapping(source)
        if not mapping:
            return []
        
        findings = []
        for line in text_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            # Create finding from line content
            finding = ASMDataModel(
                source=source,
                category=mapping.category,
                target=target or line,
                hostname=line if mapping.category == FindingCategory.SUBDOMAIN else None,
                url=line if mapping.category in [FindingCategory.URL, FindingCategory.WAYBACK_URL] else None,
                title=self._generate_title(mapping.category, {"hostname": line, "url": line}),
                severity=SeverityLevel.INFO,
                confidence=ConfidenceLevel.HIGH,
                organization_id=organization_id,
                scan_id=scan_id,
            )
            findings.append(finding)
        
        return findings
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _generate_title(self, category: FindingCategory, data: Dict[str, Any]) -> str:
        """Generate a human-readable title for a finding."""
        if category == FindingCategory.PORT:
            port = data.get("port", "?")
            protocol = data.get("protocol", "tcp")
            service = data.get("service_name", "")
            if service:
                return f"Port {port}/{protocol} - {service}"
            return f"Port {port}/{protocol} Open"
        
        elif category == FindingCategory.VULNERABILITY:
            return data.get("template_name") or data.get("title") or "Vulnerability Detected"
        
        elif category == FindingCategory.SUBDOMAIN:
            return f"Subdomain: {data.get('hostname', 'unknown')}"
        
        elif category == FindingCategory.DOMAIN:
            return f"Domain: {data.get('hostname', 'unknown')}"
        
        elif category == FindingCategory.IP_ADDRESS:
            return f"IP: {data.get('ip_address', 'unknown')}"
        
        elif category == FindingCategory.URL:
            return data.get("http_title") or data.get("url") or "URL Discovered"
        
        elif category == FindingCategory.TECHNOLOGY:
            techs = data.get("technologies", [])
            if techs:
                return f"Technologies: {', '.join(techs[:3])}"
            return "Technology Detected"
        
        elif category == FindingCategory.CERTIFICATE:
            return f"Certificate: {data.get('hostname', 'unknown')}"
        
        elif category == FindingCategory.SCREENSHOT:
            return f"Screenshot: {data.get('url', 'unknown')}"
        
        elif category == FindingCategory.WAYBACK_URL:
            return f"Archived URL: {data.get('url', 'unknown')}"
        
        else:
            return f"{category.value.title()} Finding"


# =============================================================================
# Convenience Functions
# =============================================================================

def normalize_tool_output(
    source: Union[str, DataSourceType],
    data: Union[str, Dict, List],
    target: Optional[str] = None,
    organization_id: Optional[int] = None,
    scan_id: Optional[int] = None,
) -> List[ASMDataModel]:
    """
    Convenience function to normalize any tool output.
    
    Example:
        from app.services.data_normalizer_service import normalize_tool_output
        
        findings = normalize_tool_output(
            "naabu",
            '{"host":"example.com","ip":"1.2.3.4","port":443}',
            target="example.com"
        )
    """
    if isinstance(source, str):
        try:
            source = DataSourceType(source.lower())
        except ValueError:
            logger.error(f"Unknown data source: {source}")
            return []
    
    normalizer = DataNormalizerService()
    return normalizer.normalize(source, data, target, organization_id, scan_id)


def get_supported_sources() -> List[str]:
    """Get list of all supported data sources."""
    return [s.value for s in DataSourceType]


def get_source_info(source: Union[str, DataSourceType]) -> Optional[Dict[str, Any]]:
    """Get information about a data source."""
    if isinstance(source, str):
        try:
            source = DataSourceType(source.lower())
        except ValueError:
            return None
    
    mapping = get_source_mapping(source)
    if not mapping:
        return None
    
    return {
        "source": mapping.source.value,
        "category": mapping.category.value,
        "description": mapping.description,
        "output_format": mapping.output_format,
        "fields_mapped": len(mapping.field_mappings),
        "field_mappings": [
            {"source": fm.source_field, "model": fm.model_field, "transform": fm.transform}
            for fm in mapping.field_mappings
        ],
    }

