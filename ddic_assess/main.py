from fastapi import FastAPI
from pydantic import BaseModel, field_validator, model_validator, ConfigDict
from typing import List, Dict, Optional, Any, Union

app = FastAPI(
    title="SAP Table DDIC Assessment — S/4HANA Readiness Checks",
    version="1.2"
)

# --- Rule descriptions ---
RULES = {
    1:  "Table class check: Pool/Cluster tables are not supported in S/4HANA.",
    2:  "Delivery class check: Verify delivery class is correctly maintained.",
    3:  "Enhancement category check: Must be classified for S/4HANA.",
    4:  "Client handling check: MANDT must be in primary key if present.",
    5:  "Primary key quality check: Avoid wide keys and deep types in keys.",
    6:  "CURR/QUAN reference check: Currency/unit fields must have references.",
    7:  "Buffering check: Review buffering settings for S/4HANA.",
    8:  "Technical settings check: Data class and size category must be set.",
    9:  "Change logging check: Consider enabling for audit-critical tables.",
    10: "Authorization group check: Assign for sensitive data tables.",
    11: "Field completeness check: All fields should have data element and domain.",
    12: "Field count check: Tables with too many fields should be normalized.",
    13: "Change log vs data class check: Change log active despite data class APPL0 or APPL1 causes unnecessary overhead.",
}


# --- Models ---
class Finding(BaseModel):
    tabname: Optional[str] = None
    fieldname: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


class DDICField(BaseModel):
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
    # ─── NEW FIELDS from updated ABAP extract ───
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
        """Convert all UPPERCASE keys to lowercase"""
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


# --- Utility: Build snippet from field data ---
def build_snippet(field: DDICField) -> str:
    return (
        f"TABLE={field.tabname} | FIELD={field.fieldname} | "
        f"KEY={field.keyflag} | TYPE={field.inttype} | "
        f"LEN={field.intlen} | DE={field.rollname} | DOM={field.domname}"
    )


# --- Utility: Build table-level snippet ---
def build_table_snippet(fields: List[DDICField]) -> str:
    if not fields:
        return ""
    f = fields[0]
    return (
        f"TABLE={f.tabname} | CLASS={f.tabclass} | "
        f"DELIVERY={f.contflag} | ENHANCE={f.exclass} | "
        f"DATACLASS={f.tabart} | SIZECAT={f.schfeldanz} | "
        f"BUFFER={f.bufallow} | LOG={f.logging}"
    )


# --- Core Assessment Logic ---
def assess_table(tabname: str, fields: List[DDICField]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    if not fields:
        return {
            "tabname": tabname,
            "fields": [],
            "assessment_findings": []
        }

    # Get table-level info from first row
    tbl = fields[0]
    tabclass = (tbl.tabclass or "").strip().upper()
    contflag = (tbl.contflag or "").strip().upper()
    exclass = str(tbl.exclass or "").strip()
    authclass = str(tbl.authclass or "").strip()
    tabart = (tbl.tabart or "").strip().upper()
    schfeldanz = str(tbl.schfeldanz or "").strip()
    bufallow = (tbl.bufallow or "").strip().upper()
    pufferung = (tbl.pufferung or "").strip().upper()
    logging = (tbl.logging or "").strip().upper()

    # Build field maps
    field_names = [f.fieldname for f in fields if f.fieldname]
    key_fields = [f.fieldname for f in fields
                  if (f.keyflag or "").strip().upper() == "X"]
    field_by_name = {f.fieldname: f for f in fields if f.fieldname}

    table_snippet = build_table_snippet(fields)

    # ─────────────────────────────────
    # CHECK 1: Table Class
    # ─────────────────────────────────
    if tabclass in ("POOL", "CLUSTER"):
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check01_TableClass",
            "severity": "critical",
            "line": None,
            "message": (
                f"Table class is '{tabclass}' (pool/cluster). "
                f"Not supported in S/4HANA. Must convert to transparent table."
            ),
            "suggestion": (
                f"Convert table '{tabname}' from {tabclass} to TRANSP "
                f"(transparent table) before S/4HANA migration."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 1,
                "check": "table_class",
                "current_value": tabclass,
                "expected_value": "TRANSP",
                "note": RULES[1],
            },
        })

    # ─────────────────────────────────
    # CHECK 2: Delivery Class
    # ─────────────────────────────────
    valid_contflags = {"A", "C", "L", "G", "E", "S", "W"}
    if contflag and contflag not in valid_contflags:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check02_DeliveryClass",
            "severity": "warning",
            "line": None,
            "message": f"Delivery class '{contflag}' is unusual or invalid.",
            "suggestion": (
                f"Set delivery class for '{tabname}' to one of: "
                f"A (Application), C (Customizing), L (Temporary), "
                f"G (SAP Customizing), E/S (System), W (System TR)."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 2,
                "check": "delivery_class",
                "current_value": contflag,
                "valid_values": list(valid_contflags),
                "note": RULES[2],
            },
        })
    elif not contflag:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check02_DeliveryClass",
            "severity": "warning",
            "line": None,
            "message": "Delivery class is empty. Must be maintained.",
            "suggestion": (
                f"Set delivery class for '{tabname}'. "
                f"Valid values: A, C, L, G, E, S, W."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 2,
                "check": "delivery_class",
                "current_value": "",
                "note": RULES[2],
            },
        })

    # ─────────────────────────────────
    # CHECK 3: Enhancement Category
    # ─────────────────────────────────
    valid_exclass = {"1", "2", "3", "4"}
    if exclass == "0" or not exclass:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check03_EnhancementCategory",
            "severity": "warning",
            "line": None,
            "message": (
                f"Enhancement category is '{exclass or 'empty'}' "
                f"(not classified). Must be set for S/4HANA."
            ),
            "suggestion": (
                f"Set enhancement category for '{tabname}': "
                f"1=Cannot enhance, 2=Character-like, "
                f"3=Character/Numeric, 4=Deep."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 3,
                "check": "enhancement_category",
                "current_value": exclass,
                "valid_values": list(valid_exclass),
                "note": RULES[3],
            },
        })

    # ─────────────────────────────────
    # CHECK 4: Client Handling
    # ─────────────────────────────────
    has_mandt = "MANDT" in field_by_name
    mandt_in_key = "MANDT" in key_fields

    if has_mandt and not mandt_in_key:
        mandt_field = field_by_name.get("MANDT")
        findings.append({
            "tabname": tabname,
            "fieldname": "MANDT",
            "type": "FIELD",
            "name": "MANDT",
            "start_line": None,
            "end_line": None,
            "issue_type": "Check04_ClientHandling",
            "severity": "high",
            "line": None,
            "message": (
                "MANDT field exists but is NOT part of primary key. "
                "Client-dependent table must have MANDT as first key field."
            ),
            "suggestion": (
                f"Add MANDT to primary key of '{tabname}' as first key field."
            ),
            "snippet": build_snippet(mandt_field) if mandt_field else "",
            "meta": {
                "rule": 4,
                "check": "client_handling",
                "has_mandt": True,
                "mandt_in_key": False,
                "note": RULES[4],
            },
        })

    # ─────────────────────────────────
    # CHECK 5: Primary Key Quality
    # ─────────────────────────────────
    if not key_fields:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check05_PrimaryKeyMissing",
            "severity": "critical",
            "line": None,
            "message": "No primary key fields detected.",
            "suggestion": f"Define primary key fields for table '{tabname}'.",
            "snippet": table_snippet,
            "meta": {
                "rule": 5,
                "check": "primary_key",
                "key_count": 0,
                "note": RULES[5],
            },
        })
    else:
        if len(key_fields) >= 7:
            findings.append({
                "tabname": tabname,
                "fieldname": "",
                "type": "TABLE",
                "name": tabname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check05_PrimaryKeyWide",
                "severity": "warning",
                "line": None,
                "message": (
                    f"Primary key has {len(key_fields)} fields (wide key). "
                    f"Key fields: {', '.join(key_fields)}."
                ),
                "suggestion": (
                    f"Review primary key of '{tabname}'. "
                    f"Wide keys impact performance and selectivity."
                ),
                "snippet": table_snippet,
                "meta": {
                    "rule": 5,
                    "check": "primary_key_width",
                    "key_count": len(key_fields),
                    "key_fields": key_fields,
                    "note": RULES[5],
                },
            })

        for k in key_fields:
            fld = field_by_name.get(k)
            if not fld:
                continue
            inttype = (fld.inttype or "").upper()
            if inttype in ("G", "Y", "STRING", "RAWSTRING"):
                findings.append({
                    "tabname": tabname,
                    "fieldname": k,
                    "type": "FIELD",
                    "name": k,
                    "start_line": None,
                    "end_line": None,
                    "issue_type": "Check05_PrimaryKeyDeepType",
                    "severity": "critical",
                    "line": None,
                    "message": (
                        f"Key field '{k}' uses deep type '{inttype}'. "
                        f"Deep types not allowed in primary keys."
                    ),
                    "suggestion": (
                        f"Change key field '{k}' in '{tabname}' to "
                        f"a flat type (C, N, D, T, I, P)."
                    ),
                    "snippet": build_snippet(fld),
                    "meta": {
                        "rule": 5,
                        "check": "key_deep_type",
                        "field": k,
                        "type": inttype,
                        "note": RULES[5],
                    },
                })

    # ─────────────────────────────────
    # CHECK 6: CURR/QUAN References
    # ─────────────────────────────────
    for f in fields:
        fname = (f.fieldname or "").strip()
        if not fname or fname.startswith("."):
            continue

        reftable = (f.reftable or "").strip()
        reffield = (f.reffield or "").strip()
        domname_upper = (f.domname or "").strip().upper()
        datatype_upper = (f.datatype or "").strip().upper()

        # Use DATATYPE (CURR/QUAN) if available, fallback to domain check
        is_curr = datatype_upper == "CURR" or domname_upper.startswith("CURR")
        is_quan = datatype_upper == "QUAN" or domname_upper.startswith("QUAN")

        if is_curr and not reffield:
            findings.append({
                "tabname": tabname,
                "fieldname": fname,
                "type": "FIELD",
                "name": fname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check06_CurrencyReference",
                "severity": "high",
                "line": None,
                "message": (
                    f"Field '{fname}' (domain '{f.domname}', datatype '{f.datatype}') "
                    f"is a currency amount but has no currency reference field."
                ),
                "suggestion": (
                    f"Assign REFFIELD (currency key field) for '{fname}' "
                    f"in table '{tabname}'."
                ),
                "snippet": build_snippet(f),
                "meta": {
                    "rule": 6,
                    "check": "currency_reference",
                    "field": fname,
                    "domain": f.domname,
                    "datatype": f.datatype,
                    "note": RULES[6],
                },
            })

        if is_quan and not reffield:
            findings.append({
                "tabname": tabname,
                "fieldname": fname,
                "type": "FIELD",
                "name": fname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check06_QuantityReference",
                "severity": "high",
                "line": None,
                "message": (
                    f"Field '{fname}' (domain '{f.domname}', datatype '{f.datatype}') "
                    f"is a quantity but has no unit reference field."
                ),
                "suggestion": (
                    f"Assign REFFIELD (unit of measure field) for '{fname}' "
                    f"in table '{tabname}'."
                ),
                "snippet": build_snippet(f),
                "meta": {
                    "rule": 6,
                    "check": "quantity_reference",
                    "field": fname,
                    "domain": f.domname,
                    "datatype": f.datatype,
                    "note": RULES[6],
                },
            })

        if reftable and not reffield:
            findings.append({
                "tabname": tabname,
                "fieldname": fname,
                "type": "FIELD",
                "name": fname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check06_MissingRefField",
                "severity": "warning",
                "line": None,
                "message": (
                    f"Field '{fname}' has REFTABLE='{reftable}' "
                    f"but REFFIELD is empty."
                ),
                "suggestion": (
                    f"Assign reference field for '{fname}' in '{tabname}'."
                ),
                "snippet": build_snippet(f),
                "meta": {
                    "rule": 6,
                    "check": "missing_reffield",
                    "field": fname,
                    "reftable": reftable,
                    "note": RULES[6],
                },
            })

    # ─────────────────────────────────
    # CHECK 7: Buffering
    # ─────────────────────────────────
    if bufallow in ("X", "A"):
        puffer_map = {
            "": "No buffering type",
            "P": "Single record",
            "Q": "Generic area",
            "R": "Fully buffered",
            "S": "Fully buffered",
            "X": "Fully buffered",
        }
        puffer_desc = puffer_map.get(pufferung, pufferung)

        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check07_Buffering",
            "severity": "warning",
            "line": None,
            "message": (
                f"Buffering is enabled (BUFALLOW='{bufallow}', "
                f"Type='{pufferung}' - {puffer_desc}). "
                f"Review for S/4HANA."
            ),
            "suggestion": (
                f"Review buffering settings for '{tabname}'. "
                f"In S/4HANA buffering needs justification."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 7,
                "check": "buffering",
                "bufallow": bufallow,
                "pufferung": pufferung,
                "note": RULES[7],
            },
        })

    # ─────────────────────────────────
    # CHECK 8: Technical Settings
    # ─────────────────────────────────
    if not tabart:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check08_DataClass",
            "severity": "warning",
            "line": None,
            "message": "Data class (TABART) is empty.",
            "suggestion": (
                f"Maintain data class in technical settings for '{tabname}'."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 8,
                "check": "data_class",
                "current_value": "",
                "note": RULES[8],
            },
        })

    if not schfeldanz or schfeldanz == "0":
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check08_SizeCategory",
            "severity": "warning",
            "line": None,
            "message": f"Size category (SCHFELDANZ) is '{schfeldanz or 'empty'}'.",
            "suggestion": (
                f"Maintain size category in technical settings for '{tabname}'."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 8,
                "check": "size_category",
                "current_value": schfeldanz,
                "note": RULES[8],
            },
        })

    # ─────────────────────────────────
    # CHECK 9: Change Logging
    # ─────────────────────────────────
    if logging != "X":
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check09_ChangeLogging",
            "severity": "warning",
            "line": None,
            "message": "Change logging is NOT enabled.",
            "suggestion": (
                f"Consider enabling change logging for '{tabname}' "
                f"if it contains audit-critical data."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 9,
                "check": "change_logging",
                "current_value": logging,
                "note": RULES[9],
            },
        })

    # ─────────────────────────────────
    # CHECK 10: Authorization Group
    # ─────────────────────────────────
    if not authclass:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check10_AuthGroup",
            "severity": "warning",
            "line": None,
            "message": "No authorization group assigned.",
            "suggestion": (
                f"Assign authorization group to '{tabname}' "
                f"for sensitive data protection."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 10,
                "check": "auth_group",
                "current_value": "",
                "note": RULES[10],
            },
        })

    # ─────────────────────────────────
    # CHECK 11: Field Completeness
    # ─────────────────────────────────
    fields_without_de = []
    fields_without_domain = []

    for f in fields:
        fname = (f.fieldname or "").strip()
        if not fname or fname.startswith("."):
            continue
        if not (f.rollname or "").strip():
            fields_without_de.append(fname)
        if not (f.domname or "").strip():
            fields_without_domain.append(fname)

    if fields_without_de:
        for fname in fields_without_de:
            fld = field_by_name.get(fname)
            findings.append({
                "tabname": tabname,
                "fieldname": fname,
                "type": "FIELD",
                "name": fname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check11_MissingDataElement",
                "severity": "warning",
                "line": None,
                "message": f"Field '{fname}' has no data element (ROLLNAME).",
                "suggestion": (
                    f"Assign a data element to field '{fname}' "
                    f"in table '{tabname}'."
                ),
                "snippet": build_snippet(fld) if fld else "",
                "meta": {
                    "rule": 11,
                    "check": "missing_data_element",
                    "field": fname,
                    "note": RULES[11],
                },
            })

    if fields_without_domain:
        for fname in fields_without_domain:
            fld = field_by_name.get(fname)
            findings.append({
                "tabname": tabname,
                "fieldname": fname,
                "type": "FIELD",
                "name": fname,
                "start_line": None,
                "end_line": None,
                "issue_type": "Check11_MissingDomain",
                "severity": "warning",
                "line": None,
                "message": f"Field '{fname}' has no domain (DOMNAME).",
                "suggestion": (
                    f"Assign a domain to field '{fname}' "
                    f"in table '{tabname}'."
                ),
                "snippet": build_snippet(fld) if fld else "",
                "meta": {
                    "rule": 11,
                    "check": "missing_domain",
                    "field": fname,
                    "note": RULES[11],
                },
            })

    # ─────────────────────────────────
    # CHECK 12: Field Count
    # ─────────────────────────────────
    real_fields = [f for f in fields
                   if f.fieldname and not f.fieldname.startswith(".")]
    field_count = len(real_fields)

    if field_count > 200:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check12_FieldCount",
            "severity": "warning",
            "line": None,
            "message": f"Table has {field_count} fields. Consider normalization.",
            "suggestion": f"Split table '{tabname}' into multiple tables.",
            "snippet": table_snippet,
            "meta": {
                "rule": 12,
                "check": "field_count",
                "count": field_count,
                "threshold": 200,
                "note": RULES[12],
            },
        })
    elif field_count > 100:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check12_FieldCount",
            "severity": "info",
            "line": None,
            "message": f"Table has {field_count} fields. Review if all needed.",
            "suggestion": f"Review fields in '{tabname}'. Remove unused fields.",
            "snippet": table_snippet,
            "meta": {
                "rule": 12,
                "check": "field_count",
                "count": field_count,
                "note": RULES[12],
            },
        })

    # ─────────────────────────────────
    # CHECK 13: Change Log vs Data Class
    # ─────────────────────────────────
    flagged_data_classes = {"APPL0", "APPL1"}

    if logging == "X" and tabart in flagged_data_classes:
        findings.append({
            "tabname": tabname,
            "fieldname": "",
            "type": "TABLE",
            "name": tabname,
            "start_line": None,
            "end_line": None,
            "issue_type": "Check13_ChangeLogDataClass",
            "severity": "warning",
            "line": None,
            "message": (
                f"Change logging is active but data class is '{tabart}'. "
                f"Tables with data class APPL0 or APPL1 are typically "
                f"high-volume tables. Active change logging causes "
                f"unnecessary performance overhead and log table growth."
            ),
            "suggestion": (
                f"Review change logging for table '{tabname}' "
                f"(data class '{tabart}'). Options: "
                f"(1) Disable change logging if not required for audit. "
                f"(2) If logging is mandatory, ensure DBTABLOG is archived. "
                f"(3) Consider application-level logging instead."
            ),
            "snippet": table_snippet,
            "meta": {
                "rule": 13,
                "check": "changelog_vs_dataclass",
                "logging_active": True,
                "data_class": tabart,
                "flagged_data_classes": list(flagged_data_classes),
                "atc_reference": "SAP ATC Check - Change log active "
                                 "despite Data Class APPL0 or APPL1",
                "note": RULES[13],
            },
        })

    # Build response
    obj = {
        "tabname": tabname,
        "fields": [f.model_dump() for f in fields],
        "assessment_findings": findings,
    }
    return obj


# ──────────────────────────────────────────────
# API ENDPOINTS
# ──────────────────────────────────────────────

@app.post("/assess-table")
async def assess_single_table(fields: List[DDICField]):
    if not fields:
        return {"tabname": "", "fields": [], "assessment_findings": []}
    tabname = fields[0].tabname
    result = assess_table(tabname, fields)
    return result


@app.post("/assess-tables")
async def assess_multiple_tables(fields: List[DDICField]):
    tables: Dict[str, List[DDICField]] = {}
    for f in fields:
        tab = f.tabname
        if tab not in tables:
            tables[tab] = []
        tables[tab].append(f)

    results = []
    for tabname, tab_fields in tables.items():
        result = assess_table(tabname, tab_fields)
        if result["assessment_findings"]:
            results.append(result)
    return results


@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "SAP Table DDIC Assessment",
        "version": "1.2",
        "total_checks": len(RULES),
        "checks": RULES,

    }


@app.get("/debug")
def debug_info():
    import os
    import sys

    agents_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents")

    files_in_agents = []
    if os.path.exists(agents_dir):
        files_in_agents = os.listdir(agents_dir)

    routes = []
    for route in app.routes:
        if hasattr(route, "methods"):
            for method in route.methods:
                routes.append(f"{method} {route.path}")

    return {
        "working_directory": os.getcwd(),
        "all_files_in_root": os.listdir("."),
        "agents_dir_exists": os.path.exists(agents_dir),
        "files_in_agents": files_in_agents,
        "init_py_exists": os.path.exists(os.path.join(agents_dir, "__init__.py")),
        "dtel_file_exists": os.path.exists(os.path.join(agents_dir, "dtel_assess_agent.py")),
        "table_file_exists": os.path.exists(os.path.join(agents_dir, "table_assess_agent.py")),
        "agents_loaded": len(AGENTS),
        "agent_names": [a["name"] for a in AGENTS],
        "registered_routes": routes,
        "python_version": sys.version,
    }
