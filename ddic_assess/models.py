"""
models.py
─────────
Shared Pydantic models for the SAP DDIC Assessment Orchestrator.
All agents and the main orchestrator import from here.
"""

from pydantic import BaseModel, field_validator, model_validator, ConfigDict
from typing import List, Dict, Optional, Any, Union


# ══════════════════════════════════════════════════════════════
# COMMON FINDING MODEL (unified across all agents)
# ══════════════════════════════════════════════════════════════
class Finding(BaseModel):
    """Universal finding structure returned by every agent."""
    object_name: Optional[str] = None       # e.g. tabname or rollname
    fieldname: Optional[str] = None
    type: Optional[str] = None              # TABLE, FIELD, DATA_ELEMENT, DOMAIN
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None        # e.g. Check01_TableClass, DTYP_01
    severity: Optional[str] = None          # critical, high, warning, info
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


# ══════════════════════════════════════════════════════════════
# TABLE ASSESSMENT MODELS
# ══════════════════════════════════════════════════════════════
class DDICField(BaseModel):
    """One row from the ABAP table-field extract (DD03L + DD02L joined)."""
    model_config = ConfigDict(populate_by_name=True)

    tabname: str = ""
    tabclass: Optional[str] = ""
    contflag: Optional[str] = ""
    authclass: Optional[Union[str, int, Dict[str, Any]]] = ""
    exclass: Optional[Union[str, int]] = ""
    tabart: Optional[str] = ""
    schfeldanz: Optional[Union[str, int]] = ""
    bufallow: Optional[str] = ""
    pufferung: Optional[str] = ""
    logging: Optional[str] = ""
    fieldname: Optional[str] = ""
    keyflag: Optional[str] = ""
    inttype: Optional[str] = ""
    intlen: Optional[int] = 0
    reftable: Optional[str] = ""
    reffield: Optional[str] = ""
    rollname: Optional[str] = ""
    domname: Optional[str] = ""
    checktable: Optional[str] = ""
    datatype: Optional[str] = ""
    leng: Optional[int] = 0
    decimals: Optional[int] = 0
    fk_checktable: Optional[str] = ""
    fk_fieldname: Optional[str] = ""
    fk_frkart: Optional[str] = ""
    has_sec_index: Optional[str] = ""
    sec_index_id: Optional[str] = ""
    fieldtext: Optional[str] = ""

    @model_validator(mode="before")
    @classmethod
    def lowercase_keys(cls, data):
        if isinstance(data, dict):
            return {k.lower(): v for k, v in data.items()}
        return data

    @field_validator("authclass", mode="before")
    @classmethod
    def flatten_authclass(cls, v):
        if isinstance(v, dict):
            for key, val in v.items():
                if val and str(val).strip() and str(val).strip() != "00":
                    return str(val).strip()
            return ""
        if isinstance(v, int):
            return str(v) if v != 0 else ""
        return v or ""

    @field_validator("schfeldanz", mode="before")
    @classmethod
    def normalize_schfeldanz(cls, v):
        if isinstance(v, int):
            return str(v)
        return v or ""

    @field_validator("exclass", mode="before")
    @classmethod
    def normalize_exclass(cls, v):
        if isinstance(v, int):
            return str(v)
        return v or ""

    @field_validator("intlen", mode="before")
    @classmethod
    def normalize_intlen(cls, v):
        if isinstance(v, str):
            return int(v) if v.strip() else 0
        return v or 0

    @field_validator("leng", mode="before")
    @classmethod
    def normalize_leng(cls, v):
        if isinstance(v, str):
            return int(v) if v.strip() else 0
        return v or 0

    @field_validator("decimals", mode="before")
    @classmethod
    def normalize_decimals(cls, v):
        if isinstance(v, str):
            return int(v) if v.strip() else 0
        return v or 0


# ══════════════════════════════════════════════════════════════
# DATA ELEMENT ASSESSMENT MODELS
# ══════════════════════════════════════════════════════════════
class DTELProperty(BaseModel):
    """One property row from the ABAP data-element extract."""
    model_config = ConfigDict(populate_by_name=True)

    category: str = ""
    property: str = ""
    value: str = ""

    @model_validator(mode="before")
    @classmethod
    def lowercase_keys(cls, data):
        if isinstance(data, dict):
            return {k.lower(): v for k, v in data.items()}
        return data


# ══════════════════════════════════════════════════════════════
# ORCHESTRATOR REQUEST / RESPONSE MODELS
# ══════════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    """
    Unified request body for /scan-all.
    Send whichever payload sections you have; agents pick what they need.
    """
    table_fields: Optional[List[DDICField]] = None
    dtel_properties: Optional[List[DTELProperty]] = None
    struct_fields: Optional[List[DDICField]] = None      # ← NEW
    doma_properties: Optional[List[DTELProperty]] = None     # ← NEW
    agents: Optional[List[str]] = None 


class AgentResult(BaseModel):
    """Result block for one agent execution."""
    agent_name: str
    status: str = "success"                     # success | error
    finding_count: int = 0
    results: Optional[List[Dict[str, Any]]] = None
    error_message: Optional[str] = None


class ScanResponse(BaseModel):
    """Top-level response from the orchestrator."""
    total_findings: int = 0
    agents_called: int = 0
    agents_succeeded: int = 0
    agents_failed: int = 0
    agent_results: List[AgentResult] = []
    all_findings: List[Dict[str, Any]] = []


##### 
