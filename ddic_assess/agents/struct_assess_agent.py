"""
agents/struct_assess_agent.py
──────────────────────────────
SAP Structure (SE11) DDIC Assessment Agent — S/4HANA Readiness Checks.

Assesses ABAP Dictionary structures (TABCLASS = INTTAB) against
S/4HANA readiness rules covering:
  - Enhancement category
  - Component completeness (data element, domain)
  - Naming conventions
  - Deep type usage
  - CURR/QUAN reference integrity
  - Deprecated data types
  - S/4HANA field length changes (MATNR, BP, etc.)
  - Include structure references
  - Nested/deep structure risks
  - Component count / complexity
  - Simplification item references
  - Unicode compliance
  - Append structure compatibility

Exposes AGENT_DEF = {"name": ..., "scan": ..., "rules": ...}
so the registry can auto-discover it.
"""

from typing import List, Dict, Any
from models import DDICField


# ═══════════════════════════════════════════
# RULE CATALOGUE — 18 Structure-specific checks
# ═══════════════════════════════════════════
RULES: Dict[int, str] = {
    1:  "Structure type validation: Verify TABCLASS is INTTAB (structure).",
    2:  "Enhancement category check: Structure must have enhancement "
        "category set for S/4HANA compatibility.",
    3:  "Component completeness — Data Element: All components should "
        "have a data element (ROLLNAME) assigned.",
    4:  "Component completeness — Domain: All components should have "
        "a domain (DOMNAME) assigned for type consistency.",
    5:  "Naming convention: Custom structure and component names should "
        "follow SAP naming standards.",
    6:  "Deep type in structure: STRING, RAWSTRING, table types in "
        "structures restrict usage (e.g., cannot be used in DB tables, "
        "RFC, or certain contexts).",
    7:  "CURR/QUAN reference integrity: Currency and quantity fields "
        "must have proper reference fields.",
    8:  "Deprecated data type: Data types deprecated in S/4HANA "
        "(ACCP, PREC, LCHR, LRAW, VARC, DF16_SCL, DF34_SCL).",
    9:  "S/4HANA field length change: Fields referencing data elements "
        "or domains affected by S/4HANA length extensions "
        "(MATNR 18→40, BP fields, etc.).",
    10: "Include structure reference: Components referencing include "
        "structures — verify included structures are S/4HANA compatible.",
    11: "Component count / complexity: Structures with excessive "
        "components should be reviewed for simplification.",
    12: "Simplification item reference: Components using data elements "
        "or domains related to known S/4HANA simplification items.",
    13: "Unicode compliance: Internal length vs field length mismatch "
        "for character-type components in Unicode systems.",
    14: "Table type component: Structure contains table type (TTYP) "
        "components — deep structure, restricts usage contexts.",
    15: "Field description missing: Component has no field text "
        "(FIELDTEXT) — poor documentation.",
    16: "Redundant field patterns: Multiple components with same "
        "data type and length may indicate design issues.",
    17: "Reference table without reference field: REFTABLE set but "
        "REFFIELD missing — incomplete reference definition.",
    18: "Obsolete domain reference: Component uses a domain associated "
        "with deprecated S/4HANA functionality.",
}


# ═══════════════════════════════════════════
# REFERENCE DATA — S/4HANA Knowledge Base
# ═══════════════════════════════════════════

# Data types deprecated in S/4HANA
DEPRECATED_TYPES: Dict[str, Dict[str, str]] = {
    "ACCP":     {"replacement": "NUMC(6) or DATS",
                 "description": "Accounting Period — deprecated in S/4HANA"},
    "PREC":     {"replacement": "DEC or INT",
                 "description": "Precision field — deprecated"},
    "DF16_SCL": {"replacement": "D16R",
                 "description": "Decimal Float Scaled 16 — deprecated"},
    "DF34_SCL": {"replacement": "D34R",
                 "description": "Decimal Float Scaled 34 — deprecated"},
    "LRAW":     {"replacement": "RAWSTRING",
                 "description": "Long RAW — deprecated, use RAWSTRING"},
    "LCHR":     {"replacement": "STRING",
                 "description": "Long CHAR — deprecated, use STRING"},
    "VARC":     {"replacement": "STRING or SSTRING",
                 "description": "VARC (variable char) — Pool/Cluster type, "
                                "deprecated"},
}

# Deep / complex internal types
DEEP_INT_TYPES: Dict[str, str] = {
    "g":         "STRING type — deep, no fixed length",
    "y":         "RAWSTRING type — deep, binary stream",
    "h":         "Internal table type — deep nested structure",
    "STRING":    "STRING type — deep",
    "RAWSTRING": "RAWSTRING type — deep, binary",
}

# Deep data types (from DATATYPE field)
DEEP_DATA_TYPES = {"STRG", "RSTR", "TTYP", "REF"}

# Table type data types
TABLE_TYPE_DATA_TYPES = {"TTYP"}

# S/4HANA field length changes (data element / domain name based)
S4_FIELD_LENGTH_MAP: Dict[str, Dict[str, Any]] = {
    "MATNR":       {"old_length": 18, "new_length": 40,
                    "description": "Material Number"},
    "MATNR_LONG":  {"old_length": 18, "new_length": 40,
                    "description": "Material Number (Long)"},
    "BISMT":       {"old_length": 18, "new_length": 40,
                    "description": "Old Material Number"},
    "KUNNR":       {"old_length": 10, "new_length": 10,
                    "description": "Customer Number (BP migration)"},
    "LIFNR":       {"old_length": 10, "new_length": 10,
                    "description": "Vendor Number (BP migration)"},
    "SAKNR":       {"old_length": 10, "new_length": 10,
                    "description": "G/L Account Number"},
    "HKONT":       {"old_length": 10, "new_length": 10,
                    "description": "G/L Account Number"},
    "KOSTL":       {"old_length": 10, "new_length": 10,
                    "description": "Cost Center"},
    "PRCTR":       {"old_length": 10, "new_length": 10,
                    "description": "Profit Center"},
}

# Domains tied to S/4HANA simplification items
SIMPLIFICATION_DOMAINS: Dict[str, str] = {
    "KUNNR":  "Customer Number → Business Partner migration (SI #28)",
    "LIFNR":  "Vendor Number → Business Partner migration (SI #28)",
    "SAKNR":  "G/L Account → Universal Journal ACDOCA (SI #2)",
    "HKONT":  "G/L Account → Universal Journal ACDOCA (SI #2)",
    "KSTAR":  "Cost Element → G/L Account in S/4HANA (SI #7)",
    "MATNR":  "Material Number extended to 40 chars (SI #18)",
    "BELNR":  "Accounting Document — BSEG replaced by ACDOCA (SI #2)",
    "VBELN":  "Sales Document — review for S/4HANA simplification",
    "EBELN":  "Purchase Document — review for S/4HANA simplification",
    "AUFNR":  "Order Number — review for S/4HANA",
    "RSNUM":  "Reservation Number — material document changes (SI #22)",
    "KOART":  "Account Type — review for S/4HANA changes",
}

# Data elements tied to S/4HANA simplification
SIMPLIFICATION_DATAELEMENT: Dict[str, str] = {
    "KUNNR":       "Customer Number → Business Partner (SI #28)",
    "LIFNR":       "Vendor Number → Business Partner (SI #28)",
    "SAKNR":       "G/L Account (SI #2)",
    "HKONT":       "G/L Account (SI #2)",
    "MATNR":       "Material Number 40-char extension (SI #18)",
    "BISMT":       "Old Material Number 40-char extension (SI #18)",
    "MATNR_LONG":  "Material Number Long (SI #18)",
    "KSTAR":       "Cost Element → G/L Account (SI #7)",
    "BELNR_D":     "Accounting Document Number (SI #2)",
    "VBELN":       "Sales Document Number",
    "VBELN_VA":    "Sales Order Number",
    "VBELN_VL":    "Delivery Number",
    "VBELN_VF":    "Billing Document Number",
    "EBELN":       "Purchase Order Number",
    "AUFNR":       "Order Number",
    "RSNUM":       "Reservation Number (SI #22)",
}

# Deprecated domains (functional deprecation)
DEPRECATED_DOMAINS: Dict[str, str] = {
    "KUNNR": "Customer number domain → Business Partner",
    "LIFNR": "Vendor number domain → Business Partner",
    "SAKNR": "G/L Account domain → Universal Journal",
    "HKONT": "G/L Account domain → Universal Journal",
    "KSTAR": "Cost Element domain → G/L Account",
    "KOART": "Account type — review for S/4HANA changes",
}


# ═══════════════════════════════════════════
# SNIPPET HELPERS
# ═══════════════════════════════════════════
def _build_component_snippet(field: DDICField) -> str:
    """Build a concise snippet string for a single structure component."""
    return (
        f"STRUCT={field.tabname} | COMP={field.fieldname} | "
        f"TYPE={field.datatype} | INTTYPE={field.inttype} | "
        f"LEN={field.leng} | DE={field.rollname} | "
        f"DOM={field.domname}"
    )


def _build_structure_snippet(fields: List[DDICField]) -> str:
    """Build a concise snippet string for the structure header."""
    if not fields:
        return ""
    f = fields[0]
    comp_count = len([
        c for c in fields
        if c.fieldname and not c.fieldname.startswith(".")
    ])
    return (
        f"STRUCT={f.tabname} | CLASS={f.tabclass} | "
        f"ENHANCE={f.exclass} | COMPONENTS={comp_count}"
    )


def _make_finding(
    struct_name: str,
    rule_id: int,
    issue_type: str,
    severity: str,
    message: str,
    suggestion: str,
    snippet: str,
    fieldname: str = "",
    obj_type: str = "STRUCTURE",
    extra_meta: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create a standardized finding dict matching table agent format.
    'type' is always 'STRUCTURE' so LLM API extracts correct header type.
    'sub_type' preserves granular detail (COMPONENT, INCLUDE, etc.).
    'severity' is always 'error' as required."""
    meta = {
        "rule": rule_id,
        "check": issue_type.lower(),
        "note": RULES.get(rule_id, ""),
    }
    if extra_meta:
        meta.update(extra_meta)

    return {
        "object_name": struct_name,
        "fieldname": fieldname,
        "type": "STRUCTURE",
        "sub_type": obj_type,
        "name": fieldname if fieldname else struct_name,
        "start_line": None,
        "end_line": None,
        "issue_type": issue_type,
        "severity": "error",
        "line": None,
        "message": message,
        "suggestion": suggestion,
        "snippet": snippet,
        "meta": meta,
    }


# ═══════════════════════════════════════════
# CORE: assess one structure
# ═══════════════════════════════════════════
def _assess_structure(
    struct_name: str, fields: List[DDICField]
) -> Dict[str, Any]:
    """
    Run all S/4HANA readiness checks against a single
    ABAP Dictionary structure and its components.
    """
    findings: List[Dict[str, Any]] = []

    if not fields:
        return {
            "tabname": struct_name,
            "fields": [],
            "findings": [],
        }

    # ── Structure-level info from first row ──
    hdr = fields[0]
    tabclass = (hdr.tabclass or "").strip().upper()
    exclass = str(hdr.exclass or "").strip()
    struct_snippet = _build_structure_snippet(fields)

    # ── Real components (exclude includes starting with ".") ──
    real_components = [
        f for f in fields
        if f.fieldname and not f.fieldname.startswith(".")
    ]
    include_components = [
        f for f in fields
        if f.fieldname and f.fieldname.startswith(".")
    ]
    comp_by_name = {f.fieldname: f for f in fields if f.fieldname}

    is_custom = (
        struct_name.startswith("Z") or struct_name.startswith("Y")
    )

    # ─────────────────────────────────────
    # CHECK 1 — Structure Type Validation
    # ─────────────────────────────────────
    if tabclass and tabclass != "INTTAB":
        findings.append(_make_finding(
            struct_name, 1,
            "StructureType",
            "warning",
            f"Structure '{struct_name}' has TABCLASS='{tabclass}' "
            f"instead of expected 'INTTAB'. This may not be a "
            f"standard structure definition.",
            f"Verify that '{struct_name}' is correctly defined as "
            f"a structure (INTTAB) in SE11.",
            struct_snippet,
            extra_meta={
                "current_tabclass": tabclass,
                "expected_tabclass": "INTTAB",
            },
        ))

    # ─────────────────────────────────────
    # CHECK 2 — Enhancement Category
    # ─────────────────────────────────────
    valid_exclass = {"1", "2", "3", "4"}
    if exclass == "0" or not exclass:
        findings.append(_make_finding(
            struct_name, 2,
            "EnhancementCategory",
            "warning",
            f"Enhancement category is '{exclass or 'empty'}' "
            f"(not classified). Must be set for S/4HANA. "
            f"Structures without enhancement category cannot "
            f"be extended and may cause activation errors.",
            f"Set enhancement category for '{struct_name}': "
            f"1=Cannot be enhanced, 2=Character-like, "
            f"3=Character-like or numeric, 4=Any type.",
            struct_snippet,
            extra_meta={
                "current_value": exclass,
                "valid_values": list(valid_exclass),
            },
        ))
    elif exclass not in valid_exclass:
        findings.append(_make_finding(
            struct_name, 2,
            "EnhancementCategory",
            "info",
            f"Enhancement category is '{exclass}' — not a standard "
            f"value (1-4). Review for correctness.",
            f"Standard enhancement categories: "
            f"1=Cannot enhance, 2=Char-like, "
            f"3=Char/Numeric, 4=Any.",
            struct_snippet,
            extra_meta={
                "current_value": exclass,
                "valid_values": list(valid_exclass),
            },
        ))

    # ─────────────────────────────────────
    # CHECK 3 — Component Completeness: Data Element
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        rollname = (f.rollname or "").strip()
        datatype = (f.datatype or "").strip().upper()

        # Skip table types and deep types — they may not have ROLLNAME
        if datatype in ("TTYP", "STRG", "RSTR"):
            continue

        if not rollname:
            findings.append(_make_finding(
                struct_name, 3,
                "MissingDataElement",
                "warning",
                f"Component '{fname}' has no data element (ROLLNAME). "
                f"Direct type definition reduces reusability and "
                f"makes S/4HANA impact analysis harder.",
                f"Assign a data element to component '{fname}' in "
                f"structure '{struct_name}' for better reusability "
                f"and upgrade safety.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "datatype": datatype,
                },
            ))

    # ─────────────────────────────────────
    # CHECK 4 — Component Completeness: Domain
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        domname = (f.domname or "").strip()
        datatype = (f.datatype or "").strip().upper()

        if datatype in ("TTYP", "STRG", "RSTR"):
            continue

        if not domname:
            findings.append(_make_finding(
                struct_name, 4,
                "MissingDomain",
                "info",
                f"Component '{fname}' has no domain (DOMNAME). "
                f"Domains provide value ranges, fixed values, and "
                f"conversion routines for data consistency.",
                f"Assign a domain to component '{fname}' in "
                f"structure '{struct_name}' — either via data "
                f"element or directly.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "datatype": datatype,
                },
            ))

    # ─────────────────────────────────────
    # CHECK 5 — Naming Convention
    # ─────────────────────────────────────
    if is_custom:
        # 5a — Structure name too short
        if len(struct_name) < 4:
            findings.append(_make_finding(
                struct_name, 5,
                "NamingStructure",
                "warning",
                f"Custom structure name '{struct_name}' is very short "
                f"({len(struct_name)} chars). Poor discoverability.",
                f"Rename to Z<namespace>_S_<description> or "
                f"Z<namespace>_ST_<description>.",
                struct_snippet,
                extra_meta={"name_length": len(struct_name)},
            ))

        # 5b — Component naming
        for f in real_components:
            fname = f.fieldname.strip()
            if len(fname) < 2:
                findings.append(_make_finding(
                    struct_name, 5,
                    "NamingComponent",
                    "info",
                    f"Component '{fname}' name is very short "
                    f"({len(fname)} chars). Poor readability.",
                    f"Use descriptive component names "
                    f"(e.g., MATERIAL_NUMBER instead of M).",
                    _build_component_snippet(f),
                    fieldname=fname,
                    obj_type="COMPONENT",
                    extra_meta={
                        "component": fname,
                        "name_length": len(fname),
                    },
                ))

    # ─────────────────────────────────────
    # CHECK 6 — Deep Types in Structure
    # ─────────────────────────────────────
    deep_components = []
    for f in real_components:
        fname = f.fieldname.strip()
        inttype = (f.inttype or "").strip()
        datatype = (f.datatype or "").strip().upper()

        is_deep = (
            inttype in DEEP_INT_TYPES
            or datatype in DEEP_DATA_TYPES
        )
        if is_deep:
            deep_components.append(fname)
            type_desc = DEEP_INT_TYPES.get(
                inttype,
                f"Deep data type '{datatype}'"
            )
            findings.append(_make_finding(
                struct_name, 6,
                "DeepType",
                "high",
                f"Component '{fname}' uses deep type "
                f"(INTTYPE='{inttype}', DATATYPE='{datatype}'). "
                f"{type_desc}. Structures with deep types cannot "
                f"be used in database tables, some RFC interfaces, "
                f"or as MOVE-CORRESPONDING targets with flat "
                f"structures.",
                f"Review usage of '{fname}'. If structure is used "
                f"in DB contexts or RFC, replace deep type with "
                f"flat alternative. For STRING→CHAR(max), for "
                f"table type→separate table parameter.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "inttype": inttype,
                    "datatype": datatype,
                    "deep_type_description": type_desc,
                },
            ))

    # ─────────────────────────────────────
    # CHECK 7 — CURR/QUAN Reference Integrity
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        if not fname:
            continue

        reftable = (f.reftable or "").strip()
        reffield = (f.reffield or "").strip()
        domname_upper = (f.domname or "").strip().upper()
        datatype_upper = (f.datatype or "").strip().upper()

        is_curr = (
            datatype_upper == "CURR"
            or domname_upper.startswith("CURR")
        )
        is_quan = (
            datatype_upper == "QUAN"
            or domname_upper.startswith("QUAN")
        )

        if is_curr and not reffield:
            findings.append(_make_finding(
                struct_name, 7,
                "CurrencyReference",
                "high",
                f"Component '{fname}' (domain='{f.domname}', "
                f"datatype='{f.datatype}') is a currency amount "
                f"but has no reference to a currency key field. "
                f"S/4HANA requires strict CURR/CUKY pairing.",
                f"Assign REFFIELD (currency key component) for "
                f"'{fname}' in structure '{struct_name}'. "
                f"Reference should point to a CUKY-type component.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "domain": f.domname,
                    "datatype": f.datatype,
                    "missing": "currency_reference",
                },
            ))

        if is_quan and not reffield:
            findings.append(_make_finding(
                struct_name, 7,
                "QuantityReference",
                "high",
                f"Component '{fname}' (domain='{f.domname}', "
                f"datatype='{f.datatype}') is a quantity field "
                f"but has no reference to a unit of measure field. "
                f"S/4HANA requires strict QUAN/UNIT pairing.",
                f"Assign REFFIELD (unit of measure component) for "
                f"'{fname}' in structure '{struct_name}'. "
                f"Reference should point to a UNIT-type component.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "domain": f.domname,
                    "datatype": f.datatype,
                    "missing": "quantity_reference",
                },
            ))

    # ─────────────────────────────────────
    # CHECK 8 — Deprecated Data Types
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        datatype = (f.datatype or "").strip().upper()

        if datatype in DEPRECATED_TYPES:
            dep = DEPRECATED_TYPES[datatype]
            findings.append(_make_finding(
                struct_name, 8,
                "DeprecatedType",
                "critical",
                f"Component '{fname}' uses deprecated data type "
                f"'{datatype}'. {dep['description']}. "
                f"This type is not supported in S/4HANA and will "
                f"cause activation errors after migration.",
                f"Replace data type '{datatype}' with "
                f"'{dep['replacement']}' for component '{fname}' "
                f"in structure '{struct_name}'.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "current_type": datatype,
                    "replacement": dep["replacement"],
                    "deprecation_info": dep["description"],
                },
            ))

    # ─────────────────────────────────────
    # CHECK 9 — S/4HANA Field Length Changes
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        rollname = (f.rollname or "").strip().upper()
        domname = (f.domname or "").strip().upper()
        leng = f.leng or 0

        # Check by data element or domain name
        match_key = None
        if rollname in S4_FIELD_LENGTH_MAP:
            match_key = rollname
        elif domname in S4_FIELD_LENGTH_MAP:
            match_key = domname

        if match_key:
            fl = S4_FIELD_LENGTH_MAP[match_key]
            if leng > 0 and leng < fl["new_length"]:
                findings.append(_make_finding(
                    struct_name, 9,
                    "FieldLengthChange",
                    "critical",
                    f"Component '{fname}' references '{match_key}' "
                    f"({fl['description']}). Current length={leng} "
                    f"but S/4HANA requires {fl['new_length']}. "
                    f"This will cause data truncation after "
                    f"migration.",
                    f"Extend component '{fname}' length from "
                    f"{leng} to {fl['new_length']} and review "
                    f"all dependent programs, structures, and "
                    f"interfaces.",
                    _build_component_snippet(f),
                    fieldname=fname,
                    obj_type="COMPONENT",
                    extra_meta={
                        "component": fname,
                        "matched_on": match_key,
                        "current_length": leng,
                        "old_length": fl["old_length"],
                        "new_length": fl["new_length"],
                        "description": fl["description"],
                    },
                ))

    # ─────────────────────────────────────
    # CHECK 10 — Include Structure References
    # ─────────────────────────────────────
    for f in include_components:
        inc_name = f.fieldname.strip()
        rollname = (f.rollname or "").strip()

        if inc_name or rollname:
            display_name = rollname if rollname else inc_name
            findings.append(_make_finding(
                struct_name, 10,
                "IncludeStructure",
                "info",
                f"Structure includes '{display_name}'. Verify that "
                f"the included structure is S/4HANA compatible. "
                f"If the included structure is deprecated or "
                f"changed, this structure will also be affected.",
                f"Check S/4HANA compatibility of included "
                f"structure '{display_name}'. Run structure "
                f"assessment on it separately.",
                _build_component_snippet(f),
                fieldname=inc_name,
                obj_type="INCLUDE",
                extra_meta={
                    "include_name": display_name,
                    "parent_structure": struct_name,
                },
            ))

    # ─────────────────────────────────────
    # CHECK 11 — Component Count / Complexity
    # ─────────────────────────────────────
    comp_count = len(real_components)

    if comp_count > 200:
        findings.append(_make_finding(
            struct_name, 11,
            "ComponentCount",
            "warning",
            f"Structure has {comp_count} components. Excessive "
            f"complexity impacts maintainability and performance "
            f"of MOVE-CORRESPONDING and field-symbol operations.",
            f"Consider splitting '{struct_name}' into smaller, "
            f"focused structures with includes. Review if all "
            f"components are actively used.",
            struct_snippet,
            extra_meta={
                "component_count": comp_count,
                "threshold": 200,
                "severity_level": "high",
            },
        ))
    elif comp_count > 100:
        findings.append(_make_finding(
            struct_name, 11,
            "ComponentCount",
            "info",
            f"Structure has {comp_count} components. Review if "
            f"all are needed.",
            f"Review components in '{struct_name}'. Remove "
            f"unused components and consider modularization.",
            struct_snippet,
            extra_meta={
                "component_count": comp_count,
                "threshold": 100,
            },
        ))
    elif comp_count == 0:
        findings.append(_make_finding(
            struct_name, 11,
            "EmptyStructure",
            "warning",
            f"Structure '{struct_name}' has no components. "
            f"Empty structures should be removed.",
            f"Add components or delete structure '{struct_name}' "
            f"if unused.",
            struct_snippet,
            extra_meta={"component_count": 0},
        ))

    # ─────────────────────────────────────
    # CHECK 12 — Simplification Item References
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        rollname = (f.rollname or "").strip().upper()
        domname = (f.domname or "").strip().upper()

        # Check data element against simplification items
        if rollname in SIMPLIFICATION_DATAELEMENT:
            si_info = SIMPLIFICATION_DATAELEMENT[rollname]
            findings.append(_make_finding(
                struct_name, 12,
                "SimplificationItem",
                "high",
                f"Component '{fname}' uses data element "
                f"'{rollname}' which is related to S/4HANA "
                f"simplification: {si_info}. This component "
                f"may require adaptation after migration.",
                f"Review SAP Simplification Item list "
                f"(SAP Note 2313884). Verify '{fname}' usage "
                f"and adapt to S/4HANA equivalents.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "data_element": rollname,
                    "simplification_info": si_info,
                    "sap_note": "2313884",
                },
            ))

        # Check domain against simplification items
        if (domname in SIMPLIFICATION_DOMAINS
                and rollname not in SIMPLIFICATION_DATAELEMENT):
            si_info = SIMPLIFICATION_DOMAINS[domname]
            findings.append(_make_finding(
                struct_name, 12,
                "SimplificationDomain",
                "warning",
                f"Component '{fname}' uses domain '{domname}' "
                f"related to S/4HANA simplification: {si_info}.",
                f"Review domain '{domname}' for S/4HANA "
                f"compatibility. Check SAP Note 2313884.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "domain": domname,
                    "simplification_info": si_info,
                    "sap_note": "2313884",
                },
            ))

    # ─────────────────────────────────────
    # CHECK 13 — Unicode Compliance
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        inttype = (f.inttype or "").strip()
        intlen = f.intlen or 0
        leng = f.leng or 0

        if inttype in ("C", "N", "D", "T") and intlen > 0 and leng > 0:
            expected_unicode = leng * 2
            if intlen != expected_unicode and intlen != leng:
                findings.append(_make_finding(
                    struct_name, 13,
                    "UnicodeMismatch",
                    "warning",
                    f"Component '{fname}' internal length ({intlen}) "
                    f"may not match Unicode expectation "
                    f"({expected_unicode}) for type '{inttype}' "
                    f"with length {leng}. This can cause alignment "
                    f"issues in Unicode systems.",
                    f"Verify internal length of '{fname}'. In "
                    f"Unicode systems, character types use 2 bytes "
                    f"per character. Expected internal length: "
                    f"{expected_unicode}.",
                    _build_component_snippet(f),
                    fieldname=fname,
                    obj_type="COMPONENT",
                    extra_meta={
                        "component": fname,
                        "inttype": inttype,
                        "internal_length": intlen,
                        "field_length": leng,
                        "expected_unicode_length": expected_unicode,
                    },
                ))

    # ─────────────────────────────────────
    # CHECK 14 — Table Type Components
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        datatype = (f.datatype or "").strip().upper()

        if datatype in TABLE_TYPE_DATA_TYPES:
            rollname = (f.rollname or "").strip()
            findings.append(_make_finding(
                struct_name, 14,
                "TableTypeComponent",
                "high",
                f"Component '{fname}' is a table type "
                f"(DATATYPE='{datatype}', ROLLNAME='{rollname}'). "
                f"This makes the structure 'deep' — it cannot be "
                f"used directly in database tables, certain BAPI "
                f"interfaces, or as a flat structure target.",
                f"Review if table type component '{fname}' is "
                f"necessary. For DB usage, extract table type "
                f"into a separate table. For RFC/BAPI, use "
                f"separate table parameters.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "datatype": datatype,
                    "table_type": rollname,
                },
            ))

    # ─────────────────────────────────────
    # CHECK 15 — Field Description Missing
    # ─────────────────────────────────────
    missing_text_components = []
    for f in real_components:
        fname = f.fieldname.strip()
        fieldtext = (f.fieldtext or "").strip()
        rollname = (f.rollname or "").strip()

        if not fieldtext and not rollname:
            missing_text_components.append(fname)

    if missing_text_components:
        if len(missing_text_components) <= 5:
            comp_list = ", ".join(missing_text_components)
        else:
            comp_list = (
                ", ".join(missing_text_components[:5])
                + f" ... and {len(missing_text_components) - 5} more"
            )

        findings.append(_make_finding(
            struct_name, 15,
            "MissingFieldText",
            "info",
            f"{len(missing_text_components)} component(s) have no "
            f"field text and no data element: {comp_list}. "
            f"Undocumented components reduce maintainability.",
            f"Assign data elements or maintain field descriptions "
            f"for all components in '{struct_name}'.",
            struct_snippet,
            extra_meta={
                "missing_count": len(missing_text_components),
                "components": missing_text_components[:20],
            },
        ))

    # ─────────────────────────────────────
    # CHECK 16 — Redundant Field Patterns
    # ─────────────────────────────────────
    type_length_map: Dict[str, List[str]] = {}
    for f in real_components:
        fname = f.fieldname.strip()
        datatype = (f.datatype or "").strip().upper()
        leng = f.leng or 0

        if datatype in DEEP_DATA_TYPES:
            continue

        key = f"{datatype}_{leng}"
        if key not in type_length_map:
            type_length_map[key] = []
        type_length_map[key].append(fname)

    for type_key, comp_names in type_length_map.items():
        if len(comp_names) >= 5:
            if len(comp_names) > 5:
                display = ", ".join(comp_names[:5]) + "..."
            else:
                display = ", ".join(comp_names)
            findings.append(_make_finding(
                struct_name, 16,
                "RedundantPattern",
                "info",
                f"{len(comp_names)} components share type/length "
                f"'{type_key}': {display}. "
                f"This may indicate missing data elements or "
                f"design issues.",
                f"Review if these components should share a "
                f"common data element or domain. Consider "
                f"refactoring for reusability.",
                struct_snippet,
                extra_meta={
                    "type_length": type_key,
                    "count": len(comp_names),
                    "components": comp_names[:20],
                },
            ))

    # ─────────────────────────────────────
    # CHECK 17 — REFTABLE without REFFIELD
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        reftable = (f.reftable or "").strip()
        reffield = (f.reffield or "").strip()
        datatype = (f.datatype or "").strip().upper()

        # Already covered by Check07 for CURR/QUAN
        if datatype in ("CURR", "QUAN"):
            continue

        if reftable and not reffield:
            findings.append(_make_finding(
                struct_name, 17,
                "IncompleteReference",
                "warning",
                f"Component '{fname}' has REFTABLE='{reftable}' "
                f"but REFFIELD is empty. Incomplete reference "
                f"definition.",
                f"Assign REFFIELD for component '{fname}' in "
                f"structure '{struct_name}' to complete the "
                f"reference definition.",
                _build_component_snippet(f),
                fieldname=fname,
                obj_type="COMPONENT",
                extra_meta={
                    "component": fname,
                    "reftable": reftable,
                    "reffield": "",
                },
            ))

    # ─────────────────────────────────────
    # CHECK 18 — Obsolete Domain Reference
    # ─────────────────────────────────────
    for f in real_components:
        fname = f.fieldname.strip()
        domname = (f.domname or "").strip().upper()
        rollname = (f.rollname or "").strip().upper()

        if domname in DEPRECATED_DOMAINS:
            # Avoid duplicate with Check12 simplification
            if (rollname not in SIMPLIFICATION_DATAELEMENT
                    and domname not in SIMPLIFICATION_DOMAINS):
                dep_info = DEPRECATED_DOMAINS[domname]
                findings.append(_make_finding(
                    struct_name, 18,
                    "ObsoleteDomain",
                    "warning",
                    f"Component '{fname}' uses domain '{domname}' "
                    f"associated with deprecated functionality: "
                    f"{dep_info}.",
                    f"Review domain '{domname}' for S/4HANA "
                    f"compatibility. Consider migration to "
                    f"replacement domain.",
                    _build_component_snippet(f),
                    fieldname=fname,
                    obj_type="COMPONENT",
                    extra_meta={
                        "component": fname,
                        "domain": domname,
                        "deprecated_info": dep_info,
                    },
                ))

    return {
        "tabname": struct_name,
        "fields": [f.model_dump() for f in fields],
        "findings": findings,
    }


# ═══════════════════════════════════════════
# PUBLIC scan() — called by the orchestrator
# ═══════════════════════════════════════════
def scan(
    struct_fields: List[DDICField], **kwargs
) -> List[Dict[str, Any]]:
    """
    Entry point called by agent_registry / main.py orchestrator.
    Groups fields by structure name, assesses each, returns results.
    Only processes structures (TABCLASS = INTTAB).
    """
    if not struct_fields:
        return []

    # Group by structure name
    structures: Dict[str, List[DDICField]] = {}
    for f in struct_fields:
        tab = f.tabname
        if tab not in structures:
            structures[tab] = []
        structures[tab].append(f)

    results = []
    for struct_name, components in structures.items():
        result = _assess_structure(struct_name, components)
        results.append(result)

    return results


# ═══════════════════════════════════════════
# AGENT DEFINITION — picked up by registry
# ═══════════════════════════════════════════
AGENT_DEF = {
    "name": "struct_assess",
    "description": "SAP Structure (SE11) DDIC Assessment — "
                   "18 S/4HANA readiness checks",
    "version": "1.0",
    "input_key": "struct_fields",
    "scan": scan,
    "rules": RULES,
}
