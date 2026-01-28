"""
Nuclei Template Parser Service

Parses Nuclei YAML templates to auto-generate remediation playbook stubs.
Extracts template metadata including:
- ID, name, severity
- Tags and classification
- Description and remediation text
- CWE, CVE, and CVSS information

Usage:
    parser = NucleiTemplateParser()
    
    # Parse a single template
    template = parser.parse_template("/path/to/template.yaml")
    
    # Generate a playbook stub from template
    playbook = parser.generate_playbook_stub(template)
    
    # Parse all templates in Nuclei templates directory
    templates = parser.parse_templates_directory()
    
    # Export generated playbooks to JSON
    parser.export_playbook_stubs(templates, "/path/to/output.json")
"""

import os
import logging
import yaml
import json
import subprocess
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


@dataclass
class NucleiTemplateInfo:
    """Parsed information from a Nuclei template."""
    id: str
    name: str
    author: str = ""
    severity: str = "info"
    description: str = ""
    remediation: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Classification
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_metrics: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Template metadata
    template_path: str = ""
    template_type: str = ""  # http, network, dns, file, etc.
    
    # Extracted from classification
    category: str = ""  # exposure, cve, misconfig, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GeneratedPlaybookStub:
    """A generated playbook stub from Nuclei template."""
    id: str
    title: str
    summary: str
    priority: str  # critical, high, medium, low, informational
    effort: str  # minimal, low, medium, high, significant
    estimated_time: str
    
    # Source template info
    nuclei_template_id: str
    severity: str
    tags: List[str]
    
    # Remediation content
    remediation_text: str
    references: List[str]
    
    # Classification
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    # Whether we have actionable remediation
    has_remediation: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NucleiTemplateParser:
    """Parser for Nuclei YAML templates."""
    
    # Default Nuclei templates path
    DEFAULT_TEMPLATES_PATH = os.path.expanduser("~/.local/nuclei-templates")
    
    # Severity to effort mapping (default estimates)
    SEVERITY_EFFORT_MAP = {
        "critical": ("critical", "low", "1-2 hours"),
        "high": ("high", "low", "1-2 hours"),
        "medium": ("medium", "low", "30 min - 1 hour"),
        "low": ("low", "minimal", "15-30 minutes"),
        "info": ("informational", "minimal", "15 minutes"),
        "unknown": ("medium", "low", "1 hour"),
    }
    
    # Tag-based effort overrides (more specific estimates)
    TAG_EFFORT_OVERRIDES = {
        # Quick fixes - config changes
        "misconfig": ("minimal", "15-30 minutes"),
        "exposure": ("minimal", "15-30 minutes"),
        "config": ("minimal", "15-30 minutes"),
        "default-login": ("minimal", "15-30 minutes"),
        "default-credentials": ("minimal", "15-30 minutes"),
        
        # Moderate effort - updates/patches
        "cve": ("low", "1-2 hours"),
        "rce": ("low", "1-2 hours"),
        "sqli": ("medium", "2-4 hours"),
        "xss": ("low", "1-2 hours"),
        
        # Higher effort - architectural
        "ssrf": ("medium", "2-4 hours"),
        "lfi": ("medium", "2-4 hours"),
        "rfi": ("medium", "2-4 hours"),
        
        # Port blocking - quick
        "network": ("minimal", "15-30 minutes"),
        "port": ("minimal", "15-30 minutes"),
    }
    
    def __init__(self, templates_path: Optional[str] = None):
        """Initialize parser with optional custom templates path."""
        self.templates_path = templates_path or self.DEFAULT_TEMPLATES_PATH
    
    def parse_template(self, template_path: str) -> Optional[NucleiTemplateInfo]:
        """Parse a single Nuclei template file."""
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data or 'id' not in data:
                return None
            
            info_section = data.get('info', {})
            classification = info_section.get('classification', {})
            
            # Extract references
            refs = info_section.get('reference', [])
            if isinstance(refs, str):
                refs = [refs]
            
            # Extract tags
            tags = info_section.get('tags', '')
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]
            
            # Determine template type from structure
            template_type = "unknown"
            for t in ['http', 'network', 'dns', 'file', 'headless', 'ssl', 'websocket']:
                if t in data:
                    template_type = t
                    break
            
            # Extract category from path or tags
            category = self._infer_category(template_path, tags)
            
            template = NucleiTemplateInfo(
                id=data['id'],
                name=info_section.get('name', data['id']),
                author=info_section.get('author', ''),
                severity=info_section.get('severity', 'info').lower(),
                description=info_section.get('description', ''),
                remediation=info_section.get('remediation', ''),
                reference=refs,
                tags=tags,
                cve_id=classification.get('cve-id'),
                cwe_id=self._extract_cwe(classification),
                cvss_metrics=classification.get('cvss-metrics'),
                cvss_score=classification.get('cvss-score'),
                template_path=template_path,
                template_type=template_type,
                category=category,
            )
            
            return template
            
        except Exception as e:
            logger.warning(f"Failed to parse template {template_path}: {e}")
            return None
    
    def _extract_cwe(self, classification: dict) -> Optional[str]:
        """Extract CWE ID from classification."""
        cwe = classification.get('cwe-id')
        if cwe:
            if isinstance(cwe, list):
                return cwe[0] if cwe else None
            return cwe
        return None
    
    def _infer_category(self, path: str, tags: List[str]) -> str:
        """Infer category from template path and tags."""
        path_lower = path.lower()
        
        # Check path for category hints
        categories = {
            'cves': 'cve',
            'vulnerabilities': 'vulnerability',
            'exposures': 'exposure',
            'misconfiguration': 'misconfig',
            'default-logins': 'default-login',
            'takeovers': 'takeover',
            'technologies': 'technology',
            'panels': 'panel',
            'iot': 'iot',
            'network': 'network',
        }
        
        for folder, cat in categories.items():
            if f'/{folder}/' in path_lower or path_lower.endswith(f'/{folder}'):
                return cat
        
        # Infer from tags
        tag_categories = ['cve', 'exposure', 'misconfig', 'rce', 'sqli', 'xss', 'lfi', 'ssrf']
        for tag in tags:
            if tag.lower() in tag_categories:
                return tag.lower()
        
        return "general"
    
    def generate_playbook_stub(self, template: NucleiTemplateInfo) -> GeneratedPlaybookStub:
        """Generate a playbook stub from parsed template."""
        
        # Get base effort from severity
        priority, effort, estimated_time = self.SEVERITY_EFFORT_MAP.get(
            template.severity, 
            self.SEVERITY_EFFORT_MAP["unknown"]
        )
        
        # Override effort based on tags
        for tag in template.tags:
            if tag.lower() in self.TAG_EFFORT_OVERRIDES:
                effort, estimated_time = self.TAG_EFFORT_OVERRIDES[tag.lower()]
                break
        
        # Generate ID from template ID
        playbook_id = f"nuclei-{template.id}"
        
        # Generate title
        title = f"Remediate: {template.name}"
        
        # Generate summary
        if template.remediation:
            summary = template.remediation[:200] + "..." if len(template.remediation) > 200 else template.remediation
        elif template.description:
            summary = f"Fix: {template.description[:150]}..." if len(template.description) > 150 else f"Fix: {template.description}"
        else:
            summary = f"Remediate {template.name} ({template.severity} severity)"
        
        # Build remediation text
        remediation_text = template.remediation or ""
        if not remediation_text and template.description:
            remediation_text = f"This finding indicates: {template.description}\n\nReview the references for remediation guidance."
        
        stub = GeneratedPlaybookStub(
            id=playbook_id,
            title=title,
            summary=summary,
            priority=priority,
            effort=effort,
            estimated_time=estimated_time,
            nuclei_template_id=template.id,
            severity=template.severity,
            tags=template.tags,
            remediation_text=remediation_text,
            references=template.reference,
            cwe_id=template.cwe_id,
            cve_id=template.cve_id,
            has_remediation=bool(template.remediation),
        )
        
        return stub
    
    def parse_templates_directory(
        self,
        subdirectory: Optional[str] = None,
        limit: Optional[int] = None,
        severity_filter: Optional[List[str]] = None,
        category_filter: Optional[List[str]] = None,
    ) -> List[NucleiTemplateInfo]:
        """
        Parse all templates in the Nuclei templates directory.
        
        Args:
            subdirectory: Optional subdirectory to scan (e.g., "http/cves")
            limit: Maximum number of templates to parse
            severity_filter: Only include templates with these severities
            category_filter: Only include templates in these categories
        """
        templates = []
        base_path = self.templates_path
        
        if subdirectory:
            base_path = os.path.join(base_path, subdirectory)
        
        if not os.path.exists(base_path):
            logger.warning(f"Templates path does not exist: {base_path}")
            return templates
        
        count = 0
        for root, dirs, files in os.walk(base_path):
            for filename in files:
                if not filename.endswith(('.yaml', '.yml')):
                    continue
                
                filepath = os.path.join(root, filename)
                template = self.parse_template(filepath)
                
                if not template:
                    continue
                
                # Apply filters
                if severity_filter and template.severity not in severity_filter:
                    continue
                
                if category_filter and template.category not in category_filter:
                    continue
                
                templates.append(template)
                count += 1
                
                if limit and count >= limit:
                    return templates
        
        logger.info(f"Parsed {len(templates)} Nuclei templates")
        return templates
    
    def export_playbook_stubs(
        self,
        templates: List[NucleiTemplateInfo],
        output_path: str,
        only_with_remediation: bool = False,
    ) -> int:
        """
        Export generated playbook stubs to JSON file.
        
        Returns the number of stubs exported.
        """
        stubs = []
        
        for template in templates:
            stub = self.generate_playbook_stub(template)
            
            if only_with_remediation and not stub.has_remediation:
                continue
            
            stubs.append(stub.to_dict())
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(stubs, f, indent=2)
        
        logger.info(f"Exported {len(stubs)} playbook stubs to {output_path}")
        return len(stubs)
    
    def get_templates_stats(self, templates: List[NucleiTemplateInfo]) -> Dict[str, Any]:
        """Get statistics about parsed templates."""
        by_severity = {}
        by_category = {}
        by_type = {}
        with_remediation = 0
        with_cve = 0
        with_cwe = 0
        
        for t in templates:
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
            by_category[t.category] = by_category.get(t.category, 0) + 1
            by_type[t.template_type] = by_type.get(t.template_type, 0) + 1
            
            if t.remediation:
                with_remediation += 1
            if t.cve_id:
                with_cve += 1
            if t.cwe_id:
                with_cwe += 1
        
        return {
            "total": len(templates),
            "with_remediation": with_remediation,
            "with_cve": with_cve,
            "with_cwe": with_cwe,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_type": by_type,
        }
    
    def update_nuclei_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode == 0:
                logger.info("Successfully updated Nuclei templates")
                return True
            else:
                logger.warning(f"Failed to update templates: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating templates: {e}")
            return False


# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_template_parser(templates_path: Optional[str] = None) -> NucleiTemplateParser:
    """Get a configured template parser instance."""
    return NucleiTemplateParser(templates_path)


def generate_playbooks_from_nuclei(
    output_path: str,
    subdirectory: Optional[str] = None,
    severity_filter: Optional[List[str]] = None,
    only_with_remediation: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Generate playbook stubs from Nuclei templates.
    
    Args:
        output_path: Path to write the JSON output
        subdirectory: Optional subdirectory to scan (e.g., "http/cves")
        severity_filter: Only include templates with these severities
        only_with_remediation: Only include templates that have remediation text
        limit: Maximum number of templates to process
    
    Returns:
        Statistics about the generated playbooks
    """
    parser = get_template_parser()
    
    # Parse templates
    templates = parser.parse_templates_directory(
        subdirectory=subdirectory,
        limit=limit,
        severity_filter=severity_filter,
    )
    
    # Get stats
    stats = parser.get_templates_stats(templates)
    
    # Export stubs
    exported = parser.export_playbook_stubs(
        templates,
        output_path,
        only_with_remediation=only_with_remediation,
    )
    
    stats["exported"] = exported
    stats["output_path"] = output_path
    
    return stats


def find_matching_nuclei_template(
    template_id: str,
    templates_path: Optional[str] = None,
) -> Optional[NucleiTemplateInfo]:
    """
    Find and parse a specific Nuclei template by ID.
    
    Searches the templates directory for a template matching the given ID.
    """
    parser = get_template_parser(templates_path)
    base_path = parser.templates_path
    
    if not os.path.exists(base_path):
        return None
    
    # Search for the template file
    for root, dirs, files in os.walk(base_path):
        for filename in files:
            if not filename.endswith(('.yaml', '.yml')):
                continue
            
            # Quick check if filename matches
            name_without_ext = os.path.splitext(filename)[0]
            if name_without_ext == template_id or template_id in filename:
                filepath = os.path.join(root, filename)
                template = parser.parse_template(filepath)
                if template and template.id == template_id:
                    return template
    
    return None
