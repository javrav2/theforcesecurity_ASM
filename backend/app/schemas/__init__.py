# Pydantic schemas module
from app.schemas.user import UserCreate, UserUpdate, UserResponse, UserLogin
from app.schemas.token import Token, TokenPayload
from app.schemas.organization import OrganizationCreate, OrganizationUpdate, OrganizationResponse
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityResponse
from app.schemas.scan import ScanCreate, ScanUpdate, ScanResponse
from app.schemas.technology import TechnologyCreate, TechnologyResponse, DetectedTechnologyResponse
from app.schemas.discovery import (
    DiscoveryRequest,
    DiscoveryResultResponse,
    DiscoveryProgressResponse,
    TechnologyScanRequest,
    TechnologyScanResultResponse
)
from app.schemas.unified_results import (
    ResultType,
    Severity,
    ConfidenceLevel,
    UnifiedFinding,
    UnifiedScanResult,
    ASMExportFormat,
    port_result_to_unified,
    nuclei_result_to_unified,
    discovery_result_to_unified_list,
    httpx_result_to_unified,
)
from app.schemas.data_sources import (
    DataSourceType,
    FindingCategory,
    SeverityLevel,
    ConfidenceLevel as DSConfidenceLevel,
    PortState,
    Protocol,
    ASMDataModel,
    DataSourceMapping,
    FieldMapping,
    DATA_SOURCE_MAPPINGS,
    get_source_mapping,
    list_all_model_fields,
    get_fields_for_source,
    get_unmapped_fields_for_source,
)
from app.schemas.hisac_format import (
    HISACResult,
    HISACBatchResult,
    HISACProtocol,
    asm_to_hisac,
    hisac_to_asm,
    batch_asm_to_hisac,
    batch_hisac_to_asm,
    parse_hisac_jsonl,
)

__all__ = [
    "UserCreate", "UserUpdate", "UserResponse", "UserLogin",
    "Token", "TokenPayload",
    "OrganizationCreate", "OrganizationUpdate", "OrganizationResponse",
    "AssetCreate", "AssetUpdate", "AssetResponse",
    "VulnerabilityCreate", "VulnerabilityUpdate", "VulnerabilityResponse",
    "ScanCreate", "ScanUpdate", "ScanResponse",
    "TechnologyCreate", "TechnologyResponse", "DetectedTechnologyResponse",
    "DiscoveryRequest", "DiscoveryResultResponse", "DiscoveryProgressResponse",
    "TechnologyScanRequest", "TechnologyScanResultResponse",
    # Unified results schema
    "ResultType", "Severity", "ConfidenceLevel",
    "UnifiedFinding", "UnifiedScanResult", "ASMExportFormat",
    "port_result_to_unified", "nuclei_result_to_unified",
    "discovery_result_to_unified_list", "httpx_result_to_unified",
    # Data source mappings
    "DataSourceType", "FindingCategory", "SeverityLevel",
    "PortState", "Protocol", "ASMDataModel",
    "DataSourceMapping", "FieldMapping", "DATA_SOURCE_MAPPINGS",
    "get_source_mapping", "list_all_model_fields",
    "get_fields_for_source", "get_unmapped_fields_for_source",
    # H-ISAC format
    "HISACResult", "HISACBatchResult", "HISACProtocol",
    "asm_to_hisac", "hisac_to_asm",
    "batch_asm_to_hisac", "batch_hisac_to_asm",
    "parse_hisac_jsonl",
]
