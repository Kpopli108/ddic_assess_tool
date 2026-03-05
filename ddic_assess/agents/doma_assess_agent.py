"""
agents/doma_assess_agent.py
────────────────────────────
SAP Domain DDIC Assessment Agent — S/4HANA Readiness Checks.

Assesses ABAP Dictionary Domains against S/4HANA readiness rules covering:
  - Deprecated data types
  - S/4HANA field length changes
  - Naming conventions
  - Fixed value completeness
  - Value table validation
  - Conversion routine compatibility
  - Lowercase flag usage
  - Output length consistency
  - Sign flag usage
  - Reuse / where-used analysis
  - Simplification item references
  - Unicode compliance
  - Multi-language support
  - Decimal precision
  - Domain documentation

Exposes AGENT_DEF = {"name": ..., "scan": ..., "rules": ...}
so the registry can auto-discover it.
"""

from typing import List, Dict, Optional, Any
from enum import Enum
import re

from models import DTELProperty


# ═══════════════════════════════════════════
# CHECK CATEGORIES
# ═══════════════════════════════════════════
class CheckCategory(str, Enum):
    DEPRECATED_DATA_TYPE   = "Deprecated Data Type"
    FIELD_LENGTH_CHANGE    = "Field Length Change (S/4HANA)"
    NAMING_CONVENTION      = "Naming Convention Violation"
    FIXED_VALUE            = "Fixed Value Check"
    VALUE_TABLE            = "Value Table Check"
    CONVERSION_ROUTINE     = "Conversion Routine Compatibility"
    LOWERCASE_FLAG         = "Lowercase Flag Check"
    OUTPUT_LENGTH          = "Output Length Check"
    SIGN_FLAG              = "Sign Flag Check"
    REUSE_ANALYSIS         = "Reuse / Where-Used Analysis"
    SIMPLIFICATION_ITEM    = "Simplification Item"
    UNICODE_COMPLIANCE     = "Unicode Compliance"
    MULTI_LANGUAGE         = "Multi-Language Support"
    DECIMAL_PRECISION      = "Decimal Precision Check"
    DOCUMENTATION          = "Domain Documentation"


# ═══════════════════════════════════════════
# RULE CATALOGUE — 25 Domain-specific checks
# ═══════════════════════════════════════════
RULES: Dict[str, Dict[str, Any]] = {
    "DTYP_01": {
        "category": CheckCategory.DEPRECATED_DATA_TYPE,
        "description": "Data type ACCP (Accounting Period) is deprecated "
                       "in S/4HANA. Replace with NUMC(6) or DATS.",
    },
    "DTYP_02": {
        "category": CheckCategory.DEPRECATED_DATA_TYPE,
        "description": "Data type PREC (Precision) is deprecated. "
                       "Replace with DEC or INT.",
    },
    "DTYP_03": {
        "category": CheckCategory.DEPRECATED_DATA_TYPE,
        "description": "Data type DF16_SCL / DF34_SCL (Decimal Float Scaled) "
                       "is deprecated. Replace with D16R / D34R.",
    },
    "DTYP_04": {
        "category": CheckCategory.DEPRECATED_DATA_TYPE,
        "description": "LRAW (Long RAW) / LCHR (Long CHAR) types are "
                       "deprecated. Replace with RAWSTRING / STRING.",
    },
    "DTYP_05": {
        "category": CheckCategory.DEPRECATED_DATA_TYPE,
        "description": "Pool/Cluster data types (VARC) are deprecated "
                       "in S/4HANA.",
    },
    "FLEN_01": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Domain length incompatible with S/4HANA extended "
                       "field requirements (e.g., MATNR 18→40).",
    },
    "FLEN_02": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Domain associated with S/4HANA field length change. "
                       "Verify all dependent data elements and tables.",
    },
    "NAME_01": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Custom domain name is too short or lacks "
                       "descriptive structure.",
    },
    "NAME_02": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Custom domain name lacks underscores for "
                       "readability.",
    },
    "NAME_03": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Domain description is missing or too short.",
    },
    "FXVL_01": {
        "category": CheckCategory.FIXED_VALUE,
        "description": "Short code-type domain (CHAR/NUMC, len ≤ 4) has "
                       "no fixed values defined.",
    },
    "FXVL_02": {
        "category": CheckCategory.FIXED_VALUE,
        "description": "Fixed value key contains spaces — may cause "
                       "inconsistent data entry.",
    },
    "FXVL_03": {
        "category": CheckCategory.FIXED_VALUE,
        "description": "Fixed value key exceeds domain length — "
                       "data truncation risk.",
    },
    "FXVL_04": {
        "category": CheckCategory.FIXED_VALUE,
        "description": "Fixed values defined but no descriptions — "
                       "poor usability in F4 help.",
    },
    "VTAB_01": {
        "category": CheckCategory.VALUE_TABLE,
        "description": "Domain has no value table and no fixed values. "
                       "No validation mechanism exists.",
    },
    "VTAB_02": {
        "category": CheckCategory.VALUE_TABLE,
        "description": "Value table references a table affected by "
                       "S/4HANA simplification.",
    },
    "CONV_01": {
        "category": CheckCategory.CONVERSION_ROUTINE,
        "description": "Domain has a conversion routine. Verify "
                       "compatibility with S/4HANA.",
    },
    "CONV_02": {
        "category": CheckCategory.CONVERSION_ROUTINE,
        "description": "Custom conversion routine (Z*/Y*) — must be "
                       "tested and migrated for S/4HANA.",
    },
    "LCASE_01": {
        "category": CheckCategory.LOWERCASE_FLAG,
        "description": "Lowercase allowed on character-type domain — "
                       "may cause inconsistent data storage.",
    },
    "LCASE_02": {
        "category": CheckCategory.LOWERCASE_FLAG,
        "description": "Lowercase flag on non-character type is irrelevant.",
    },
    "OLEN_01": {
        "category": CheckCategory.OUTPUT_LENGTH,
        "description": "Output length is less than domain length — "
                       "display truncation risk.",
    },
    "OLEN_02": {
        "category": CheckCategory.OUTPUT_LENGTH,
        "description": "Output length is zero or not maintained.",
    },
    "SIGN_01": {
        "category": CheckCategory.SIGN_FLAG,
        "description": "Sign flag enabled on non-numeric domain — "
                       "irrelevant setting.",
    },
    "REUS_01": {
        "category": CheckCategory.REUSE_ANALYSIS,
        "description": "Domain has no where-used references — "
                       "may be obsolete.",
    },
    "REUS_02": {
        "category": CheckCategory.REUSE_ANALYSIS,
        "description": "Custom domain has very low reuse — "
                       "consider using standard domain.",
    },
    "SIMP_01": {
        "category": CheckCategory.SIMPLIFICATION_ITEM,
        "description": "Domain is related to a known S/4HANA "
                       "simplification item.",
    },
    "SIMP_02": {
        "category": CheckCategory.SIMPLIFICATION_ITEM,
        "description": "Domain is associated with deprecated S/4HANA "
                       "functionality.",
    },
    "UNIC_01": {
        "category": CheckCategory.UNICODE_COMPLIANCE,
        "description": "Character-type domain — verify internal length "
                       "alignment in Unicode systems.",
    },
    "LANG_01": {
        "category": CheckCategory.MULTI_LANGUAGE,
        "description": "Domain has translations in fewer than 2 languages.",
    },
    "DECP_01": {
        "category": CheckCategory.DECIMAL_PRECISION,
        "description": "Currency-related domain should support 5 decimal "
                       "places for S/4HANA.",
    },
    "DECP_02": {
        "category": CheckCategory.DECIMAL_PRECISION,
        "description": "Decimal precision may be insufficient for "
                       "S/4HANA requirements.",
    },
    "DOC_01": {
        "category": CheckCategory.DOCUMENTATION,
        "description": "Domain has no description — poor documentation.",
    },
}


# ═══════════════════════════════════════════
# REFERENCE DATA — S/4HANA Knowledge Base
# ═══════════════════════════════════════════
DEPRECATED_TYPES: Dict[str, Dict[str, str]] = {
    "ACCP":     {"replacement": "NUMC(6) or DATS",  "rule": "DTYP_01"},
    "PREC":     {"replacement": "DEC or INT",        "rule": "DTYP_02"},
    "DF16_SCL": {"replacement": "D16R",              "rule": "DTYP_03"},
    "DF34_SCL": {"replacement": "D34R",              "rule": "DTYP_03"},
    "LRAW":     {"replacement": "RAWSTRING",         "rule": "DTYP_04"},
    "LCHR":     {"replacement": "STRING",            "rule": "DTYP_04"},
    "VARC":     {"replacement": "STRING or SSTRING", "rule": "DTYP_05"},
}

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

S4_SIMPLIFIED_TABLES = {
    "BSEG", "BSID", "BSAD", "BSIK", "BSAK", "BSIS", "BSAS",
    "GLT0", "GLT3", "GLTO", "FAGLFLEXA", "FAGLFLEXT",
    "COEP", "COEJ", "COBK",
    "LIPS", "LIKP", "VBRP", "VBRK",
    "MBEW", "CKMLHD", "CKMLCR",
    "KNA1", "KNB1", "LFA1", "LFB1",
}

SIMPLIFICATION_MAP: Dict[str, str] = {
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
    "KOART":  "Account type — review for S/4HANA changes",
}

DEPRECATED_DOMAINS: Dict[str, str] = {
    "KUNNR": "Customer number domain → Business Partner",
    "LIFNR": "Vendor number domain → Business Partner",
    "SAKNR": "G/L Account domain → Universal Journal",
    "HKONT": "G/L Account domain → Universal Journal",
    "KSTAR": "Cost Element domain → G/L Account",
    "KOART": "Account type — review for S/4HANA changes",
}

NUMERIC_TYPES = {"DEC", "CURR", "QUAN", "FLTP", "INT1", "INT2", "INT4",
                 "INT8", "P", "F", "D16R", "D16S", "D34R", "D34S",
                 "DF16_RAW", "DF34_RAW"}

CHARACTER_TYPES = {"CHAR", "NUMC", "SSTRING", "STRING", "CLNT", "LANG",
                   "UNIT", "CUKY", "DATS", "TIMS"}

CURRENCY_TYPES = {"CURR"}
QUANTITY_TYPES = {"QUAN"}

DEPRECATED_CONVERSION_ROUTINES = {
    "ALPHA", "MATN1", "CUNIT", "ISOLA",
}

S4_SENSITIVE_CONVERSION_ROUTINES = {
    "ALPHA":  "Alpha conversion — verify behavior with extended field lengths",
    "MATN1":  "Material number conversion — must support 40-char MATNR",
    "MATN2":  "Material number conversion variant — review for S/4HANA",
    "CUNIT":  "Unit conversion — verify S/4HANA unit handling",
    "ISOLA":  "Language conversion — verify S/4HANA compatibility",
    "EXCRT":  "Exchange rate conversion — review for S/4HANA",
    "GJAHR":  "Fiscal year conversion — review for S/4HANA",
}


# ═══════════════════════════════════════════
# HELPER UTILITIES
# ═══════════════════════════════════════════
def _parse_domain_properties(
    properties: List[DTELProperty],
) -> Dict[str, Any]:
    """Parse flat property list into structured domain metadata."""
    result: Dict[str, Any] = {
        "general": {},
        "technical": {},
        "fixed_values": [],
        "languages": [],
        "where_used": [],
        "summary": {},
    }
    for p in properties:
        cat  = (p.category or "").strip().upper()
        prop = (p.property or "").strip()
        val  = (p.value or "").strip()

        if   cat == "GENERAL":      result["general"][prop] = val
        elif cat == "TECHNICAL":    result["technical"][prop] = val
        elif cat == "FIXED_VALUE":
            result["fixed_values"].append({"key": prop, "value": val})
        elif cat.startswith("LANG_"):
            lang_code = cat.replace("LANG_", "")
            result["languages"].append(
                {"language": lang_code, "property": prop, "text": val}
            )
        elif cat == "WHERE_USED":
            result["where_used"].append({"name": prop, "detail": val})
        elif cat == "SUMMARY":
            result["summary"][prop] = val

    return result


def _build_domain_snippet(parsed: Dict[str, Any]) -> str:
    """Build a concise snippet string for the domain."""
    gen  = parsed.get("general", {})
    tech = parsed.get("technical", {})
    return (
        f"DOMAIN={gen.get('Domain Name', '')} | "
        f"DESC={gen.get('Description', '')} | "
        f"TYPE={tech.get('Data Type', '')} | "
        f"LEN={tech.get('Length', '')} | "
        f"DEC={tech.get('Decimals', '')} | "
        f"OUTLEN={tech.get('Output Length', '')} | "
        f"VTAB={tech.get('Value Table', '')} | "
        f"CONV={tech.get('Conversion Routine', '')} | "
        f"PKG={gen.get('Package', '')}"
    )


def _parse_summary_counts(summary: Dict[str, str]) -> Dict[str, int]:
    """Extract numeric counts from summary string."""
    counts_str = summary.get("Counts", "")
    result = {"languages": 0, "fixed_values": 0, "where_used": 0}
    for key, pattern in [
        ("languages",    r"Languages:\s*(\d+)"),
        ("fixed_values", r"Fixed Values:\s*(\d+)"),
        ("where_used",   r"Where-Used(?:\s+\w+)?:\s*(\d+)"),
    ]:
        m = re.search(pattern, counts_str)
        if m:
            result[key] = int(m.group(1))
    return result


def _safe_int(val: str) -> int:
    """Safely convert string to int."""
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return 0


def _make_finding(
    domain_name: str,
    rule_id: str,
    severity: str,
    message: str,
    suggestion: str,
    snippet: str,
    extra_meta: Optional[Dict[str, Any]] = None,
    fieldname: str = "",
    obj_type: str = "DOMAIN",
    obj_name: str = "",
) -> Dict[str, Any]:
    """Create a standardized finding dict matching other agents' format."""
    rule_info = RULES.get(rule_id, {})
    meta: Dict[str, Any] = {
        "rule_id": rule_id,
        "category": (
            rule_info["category"].value
            if isinstance(rule_info.get("category"), CheckCategory)
            else str(rule_info.get("category", ""))
        ),
        "rule_description": rule_info.get("description", ""),
    }
    if extra_meta:
        meta.update(extra_meta)

    return {
        "object_name": domain_name,
        "fieldname": fieldname,
        "type": obj_type,
        "name": obj_name or domain_name,
        "start_line": None,
        "end_line": None,
        "issue_type": rule_id,
        "severity": severity,
        "line": None,
        "message": message,
        "suggestion": suggestion,
        "snippet": snippet,
        "meta": meta,
    }


# ═══════════════════════════════════════════
# CORE: assess one domain
# ═══════════════════════════════════════════
def _assess_domain(
    properties: List[DTELProperty],
) -> Dict[str, Any]:
    """
    Run all S/4HANA readiness checks against a single
    ABAP Dictionary domain.
    """
    findings: List[Dict[str, Any]] = []

    if not properties:
        return {
            "domain_name": "",
            "properties": [],
            "findings": [],
        }

    parsed      = _parse_domain_properties(properties)
    gen         = parsed.get("general", {})
    tech        = parsed.get("technical", {})
    fixed_vals  = parsed.get("fixed_values", [])
    languages   = parsed.get("languages", [])
    where_used  = parsed.get("where_used", [])
    summary     = parsed.get("summary", {})

    # ── Extract key values ──
    domain_name   = gen.get("Domain Name", "").strip().upper()
    description   = gen.get("Description", "").strip()
    package       = gen.get("Package", "").strip()
    data_type     = tech.get("Data Type", "").strip().upper()
    length        = _safe_int(tech.get("Length", "0"))
    decimals_v    = _safe_int(tech.get("Decimals", "0"))
    output_len    = _safe_int(tech.get("Output Length", "0"))
    lowercase     = tech.get("Lowercase Allowed", "").strip().upper()
    sign_flag     = tech.get("Sign Flag", "").strip().upper()
    value_table   = tech.get("Value Table", "").strip().upper()
    conv_routine  = tech.get("Conversion Routine", "").strip().upper()

    snippet     = _build_domain_snippet(parsed)
    counts      = _parse_summary_counts(summary)
    wu_count    = counts.get("where_used", len(where_used))
    fv_count    = counts.get("fixed_values", len(fixed_vals))
    lang_count  = counts.get("languages", len(languages))
    is_custom   = domain_name.startswith("Z") or domain_name.startswith("Y")

    is_numeric    = data_type in NUMERIC_TYPES
    is_character  = data_type in CHARACTER_TYPES
    is_currency   = data_type in CURRENCY_TYPES
    is_quantity   = data_type in QUANTITY_TYPES

    # ─────────────────────────────────────
    # CHECK: DEPRECATED DATA TYPE
    # ─────────────────────────────────────
    if data_type in DEPRECATED_TYPES:
        dep = DEPRECATED_TYPES[data_type]
        findings.append(_make_finding(
            domain_name, dep["rule"], "critical",
            f"Domain '{domain_name}' uses deprecated data type "
            f"'{data_type}'. Not supported in S/4HANA. "
            f"This will cause activation errors after migration.",
            f"Replace data type '{data_type}' with "
            f"'{dep['replacement']}' for domain '{domain_name}'.",
            snippet,
            extra_meta={
                "current_type": data_type,
                "replacement": dep["replacement"],
            },
        ))

    # ─────────────────────────────────────
    # CHECK: S/4HANA FIELD LENGTH CHANGE
    # ─────────────────────────────────────
    if domain_name in S4_FIELD_LENGTH_MAP:
        fl = S4_FIELD_LENGTH_MAP[domain_name]
        if length > 0 and length < fl["new_length"]:
            findings.append(_make_finding(
                domain_name, "FLEN_01", "critical",
                f"Domain '{domain_name}' ({fl['description']}) has "
                f"length {length} but S/4HANA requires "
                f"{fl['new_length']}. All dependent data elements, "
                f"structures, and tables will be affected.",
                f"Extend domain length from {length} to "
                f"{fl['new_length']}. Review all dependents. "
                f"Check SAP Note 2313884.",
                snippet,
                extra_meta={
                    "old_length": fl["old_length"],
                    "new_length": fl["new_length"],
                    "current_length": length,
                    "description": fl["description"],
                    "sap_note": "2313884",
                },
            ))
        else:
            findings.append(_make_finding(
                domain_name, "FLEN_02", "info",
                f"Domain '{domain_name}' is associated with "
                f"S/4HANA field length change ({fl['description']}). "
                f"Current length {length} meets requirement "
                f"{fl['new_length']}.",
                f"Verify all dependent data elements and tables "
                f"also meet S/4HANA length requirements.",
                snippet,
                extra_meta={
                    "current_length": length,
                    "required_length": fl["new_length"],
                    "description": fl["description"],
                },
            ))

    # ─────────────────────────────────────
    # CHECK: NAMING CONVENTION
    # ─────────────────────────────────────
    if is_custom:
        if len(domain_name) < 4:
            findings.append(_make_finding(
                domain_name, "NAME_01", "warning",
                f"Custom domain name '{domain_name}' is very short "
                f"({len(domain_name)} chars). Poor discoverability.",
                f"Rename to Z<namespace>_D_<description> or "
                f"ZD_<description>.",
                snippet,
                extra_meta={"name_length": len(domain_name)},
            ))

        name_body = domain_name[1:]
        if "_" not in name_body and len(name_body) > 5:
            findings.append(_make_finding(
                domain_name, "NAME_02", "info",
                f"Custom domain '{domain_name}' lacks underscores "
                f"for readability.",
                f"Use Z_<namespace>_<description> or "
                f"ZD_<description> pattern.",
                snippet,
            ))

    # ─────────────────────────────────────
    # CHECK: DESCRIPTION / DOCUMENTATION
    # ─────────────────────────────────────
    if not description:
        findings.append(_make_finding(
            domain_name, "DOC_01", "high",
            f"Domain '{domain_name}' has no description. "
            f"Poor documentation reduces maintainability and "
            f"impact analysis accuracy.",
            f"Maintain a meaningful description for domain "
            f"'{domain_name}'.",
            snippet,
        ))
    elif len(description) < 5:
        findings.append(_make_finding(
            domain_name, "NAME_03", "warning",
            f"Domain '{domain_name}' description is too short "
            f"({len(description)} chars): '{description}'.",
            f"Provide a descriptive text (minimum 10 characters).",
            snippet,
            extra_meta={"description_length": len(description)},
        ))

    # ─────────────────────────────────────
    # CHECK: FIXED VALUES
    # ─────────────────────────────────────
    if (not fixed_vals and fv_count == 0
            and data_type in ("CHAR", "NUMC")
            and 0 < length <= 4):
        findings.append(_make_finding(
            domain_name, "FXVL_01", "info",
            f"Domain '{domain_name}' ({data_type}, length {length}) "
            f"has no fixed values defined. Short code-type domains "
            f"should have fixed values for validation.",
            f"Consider adding fixed values to domain "
            f"'{domain_name}' for data integrity.",
            snippet,
            extra_meta={
                "data_type": data_type,
                "length": length,
            },
        ))

    if fixed_vals:
        # Check for spaces in fixed value keys
        for fv in fixed_vals:
            fv_key = fv.get("key", "")
            if " " in fv_key.strip():
                findings.append(_make_finding(
                    domain_name, "FXVL_02", "warning",
                    f"Fixed value key '{fv_key}' contains spaces. "
                    f"This may cause inconsistent data entry and "
                    f"comparison issues.",
                    f"Remove spaces from fixed value key '{fv_key}' "
                    f"in domain '{domain_name}'. Use underscores "
                    f"or concatenated text instead.",
                    snippet,
                    fieldname=fv_key,
                    extra_meta={
                        "fixed_value_key": fv_key,
                        "fixed_value_text": fv.get("value", ""),
                    },
                ))

        # Check key length vs domain length
        if length > 0:
            for fv in fixed_vals:
                fv_key = fv.get("key", "")
                if len(fv_key) > length:
                    findings.append(_make_finding(
                        domain_name, "FXVL_03", "critical",
                        f"Fixed value key '{fv_key}' "
                        f"(length {len(fv_key)}) exceeds domain "
                        f"length {length}. Data truncation will occur.",
                        f"Shorten fixed value key '{fv_key}' to fit "
                        f"within domain length {length}, or extend "
                        f"domain length.",
                        snippet,
                        fieldname=fv_key,
                        extra_meta={
                            "fixed_value_key": fv_key,
                            "key_length": len(fv_key),
                            "domain_length": length,
                        },
                    ))

        # Check for missing descriptions in fixed values
        fv_no_desc = []
        for fv in fixed_vals:
            fv_val = fv.get("value", "").strip()
            fv_key = fv.get("key", "").strip()
            # Format is typically: "KEY /  = DESCRIPTION"
            if "=" in fv_val:
                desc_part = fv_val.split("=", 1)[1].strip()
                if not desc_part:
                    fv_no_desc.append(fv_key)
            elif not fv_val:
                fv_no_desc.append(fv_key)

        if fv_no_desc:
            findings.append(_make_finding(
                domain_name, "FXVL_04", "info",
                f"{len(fv_no_desc)} fixed value(s) have no "
                f"description: {', '.join(fv_no_desc[:5])}"
                f"{'...' if len(fv_no_desc) > 5 else ''}. "
                f"Descriptions improve F4 help usability.",
                f"Maintain descriptions for all fixed values "
                f"in domain '{domain_name}'.",
                snippet,
                extra_meta={
                    "missing_desc_count": len(fv_no_desc),
                    "keys": fv_no_desc[:10],
                },
            ))

    # ─────────────────────────────────────
    # CHECK: VALUE TABLE
    # ─────────────────────────────────────
    if (not value_table and not fixed_vals and fv_count == 0
            and is_character and 0 < length <= 10):
        findings.append(_make_finding(
            domain_name, "VTAB_01", "info",
            f"Domain '{domain_name}' has no value table and no "
            f"fixed values. No validation mechanism exists for "
            f"data entry.",
            f"Assign a value table or define fixed values for "
            f"domain '{domain_name}'.",
            snippet,
            extra_meta={
                "data_type": data_type,
                "length": length,
            },
        ))

    if value_table and value_table in S4_SIMPLIFIED_TABLES:
        findings.append(_make_finding(
            domain_name, "VTAB_02", "high",
            f"Domain '{domain_name}' value table '{value_table}' "
            f"is affected by S/4HANA simplification. This table "
            f"may be deprecated or restructured.",
            f"Update value table for domain '{domain_name}' to "
            f"the S/4HANA replacement table. Check SAP "
            f"Simplification Item list.",
            snippet,
            extra_meta={
                "value_table": value_table,
                "simplified": True,
                "sap_note": "2313884",
            },
        ))

    # ─────────────────────────────────────
    # CHECK: CONVERSION ROUTINE
    # ─────────────────────────────────────
    if conv_routine:
        is_custom_conv = (
            conv_routine.startswith("Z")
            or conv_routine.startswith("Y")
        )

        if is_custom_conv:
            findings.append(_make_finding(
                domain_name, "CONV_02", "high",
                f"Domain '{domain_name}' uses custom conversion "
                f"routine '{conv_routine}'. Custom conversion "
                f"routines must be tested and potentially adapted "
                f"for S/4HANA.",
                f"Test conversion routine '{conv_routine}' in "
                f"S/4HANA environment. Verify input/output "
                f"behavior with extended field lengths.",
                snippet,
                extra_meta={
                    "conversion_routine": conv_routine,
                    "is_custom": True,
                },
            ))
        elif conv_routine in S4_SENSITIVE_CONVERSION_ROUTINES:
            info = S4_SENSITIVE_CONVERSION_ROUTINES[conv_routine]
            findings.append(_make_finding(
                domain_name, "CONV_01", "warning",
                f"Domain '{domain_name}' uses conversion routine "
                f"'{conv_routine}'. {info}.",
                f"Verify conversion routine '{conv_routine}' "
                f"behavior in S/4HANA. Check for extended field "
                f"length compatibility.",
                snippet,
                extra_meta={
                    "conversion_routine": conv_routine,
                    "s4_info": info,
                },
            ))
        else:
            findings.append(_make_finding(
                domain_name, "CONV_01", "info",
                f"Domain '{domain_name}' has conversion routine "
                f"'{conv_routine}'. Verify S/4HANA compatibility.",
                f"Test conversion routine '{conv_routine}' in "
                f"S/4HANA sandbox.",
                snippet,
                extra_meta={
                    "conversion_routine": conv_routine,
                },
            ))

    # ─────────────────────────────────────
    # CHECK: LOWERCASE FLAG
    # ─────────────────────────────────────
    if lowercase == "X":
        if is_character and data_type in ("CHAR", "SSTRING", "STRING"):
            findings.append(_make_finding(
                domain_name, "LCASE_01", "info",
                f"Domain '{domain_name}' allows lowercase. This "
                f"may cause inconsistent data storage and "
                f"comparison issues.",
                f"Disable lowercase unless explicitly required "
                f"for domain '{domain_name}'.",
                snippet,
            ))
        elif data_type in ("NUMC", "DATS", "TIMS", "DEC", "INT4",
                           "INT1", "INT2", "INT8"):
            findings.append(_make_finding(
                domain_name, "LCASE_02", "warning",
                f"Domain '{domain_name}' has lowercase flag on "
                f"'{data_type}' — irrelevant for non-character "
                f"types.",
                f"Remove lowercase flag from domain "
                f"'{domain_name}'.",
                snippet,
                extra_meta={"data_type": data_type},
            ))

    # ─────────────────────────────────────
    # CHECK: OUTPUT LENGTH
    # ─────────────────────────────────────
    if output_len == 0:
        findings.append(_make_finding(
            domain_name, "OLEN_02", "warning",
            f"Domain '{domain_name}' output length is zero or "
            f"not maintained.",
            f"Set output length for domain '{domain_name}'. "
            f"Recommended: equal to or greater than field length.",
            snippet,
            extra_meta={
                "output_length": output_len,
                "field_length": length,
            },
        ))
    elif (output_len > 0 and length > 0
          and output_len < length
          and data_type not in ("DEC", "CURR", "QUAN", "FLTP")):
        findings.append(_make_finding(
            domain_name, "OLEN_01", "warning",
            f"Domain '{domain_name}' output length ({output_len}) "
            f"is less than domain length ({length}). Display "
            f"truncation may occur.",
            f"Set output length >= domain length for "
            f"'{domain_name}'.",
            snippet,
            extra_meta={
                "output_length": output_len,
                "field_length": length,
            },
        ))

    # ─────────────────────────────────────
    # CHECK: SIGN FLAG
    # ─────────────────────────────────────
    if sign_flag == "X" and not is_numeric:
        findings.append(_make_finding(
            domain_name, "SIGN_01", "warning",
            f"Domain '{domain_name}' has sign flag enabled on "
            f"non-numeric type '{data_type}'. Sign flag is only "
            f"relevant for numeric types.",
            f"Remove sign flag from domain '{domain_name}'.",
            snippet,
            extra_meta={"data_type": data_type},
        ))

    # ─────────────────────────────────────
    # CHECK: REUSE / WHERE-USED
    # ─────────────────────────────────────
    if wu_count == 0:
        findings.append(_make_finding(
            domain_name, "REUS_01", "warning",
            f"Domain '{domain_name}' has no where-used references. "
            f"It may be obsolete.",
            f"Delete domain '{domain_name}' if unused, or assign "
            f"to data elements.",
            snippet,
            extra_meta={"where_used_count": 0},
        ))
    elif is_custom and wu_count == 1:
        findings.append(_make_finding(
            domain_name, "REUS_02", "info",
            f"Custom domain '{domain_name}' is used in only "
            f"{wu_count} data element(s). Low reuse.",
            f"Review if a standard SAP domain can be used "
            f"instead of custom domain '{domain_name}'.",
            snippet,
            extra_meta={"where_used_count": wu_count},
        ))

    # ─────────────────────────────────────
    # CHECK: SIMPLIFICATION ITEM
    # ─────────────────────────────────────
    if domain_name in SIMPLIFICATION_MAP:
        findings.append(_make_finding(
            domain_name, "SIMP_01", "high",
            f"Domain '{domain_name}' is related to S/4HANA "
            f"simplification: "
            f"{SIMPLIFICATION_MAP[domain_name]}.",
            f"Review Simplification Item list. SAP Note 2313884. "
            f"Verify all dependent data elements and tables.",
            snippet,
            extra_meta={
                "simplification_item": SIMPLIFICATION_MAP[domain_name],
                "sap_note": "2313884",
            },
        ))

    if (domain_name in DEPRECATED_DOMAINS
            and domain_name not in SIMPLIFICATION_MAP):
        findings.append(_make_finding(
            domain_name, "SIMP_02", "warning",
            f"Domain '{domain_name}' is associated with "
            f"deprecated functionality: "
            f"{DEPRECATED_DOMAINS[domain_name]}.",
            f"Review for S/4HANA compatibility. Consider "
            f"migration to replacement domain.",
            snippet,
            extra_meta={
                "deprecated_info": DEPRECATED_DOMAINS[domain_name],
            },
        ))

    # ─────────────────────────────────────
    # CHECK: UNICODE COMPLIANCE
    # ─────────────────────────────────────
    if is_character and length > 0:
        expected_unicode = length * 2
        findings.append(_make_finding(
            domain_name, "UNIC_01", "info",
            f"Domain '{domain_name}' is character-type "
            f"'{data_type}' with length {length}. In Unicode "
            f"systems, internal length should be {expected_unicode} "
            f"bytes (2 bytes per character).",
            f"Verify internal length alignment for domain "
            f"'{domain_name}' in Unicode environments.",
            snippet,
            extra_meta={
                "data_type": data_type,
                "field_length": length,
                "expected_unicode_length": expected_unicode,
            },
        ))

    # ─────────────────────────────────────
    # CHECK: MULTI-LANGUAGE
    # ─────────────────────────────────────
    if lang_count < 2:
        findings.append(_make_finding(
            domain_name, "LANG_01", "info",
            f"Domain '{domain_name}' has only {lang_count} "
            f"language(s). Multi-language support recommended "
            f"for global deployments.",
            f"Translate domain '{domain_name}' into all required "
            f"languages.",
            snippet,
            extra_meta={
                "language_count": lang_count,
                "languages": [
                    l.get("language", "") for l in languages
                ],
            },
        ))

    # ─────────────────────────────────────
    # CHECK: DECIMAL PRECISION
    # ─────────────────────────────────────
    if is_currency:
        if decimals_v < 5:
            findings.append(_make_finding(
                domain_name, "DECP_01", "warning",
                f"Currency domain '{domain_name}' has "
                f"{decimals_v} decimal places. S/4HANA supports "
                f"up to 5 decimal places for currency amounts.",
                f"Review decimal precision for domain "
                f"'{domain_name}'. S/4HANA may require up to "
                f"5 decimal places.",
                snippet,
                extra_meta={
                    "current_decimals": decimals_v,
                    "s4_max_decimals": 5,
                },
            ))

    if is_numeric and not is_currency and not is_quantity:
        if data_type == "DEC" and length > 0 and decimals_v == 0:
            findings.append(_make_finding(
                domain_name, "DECP_02", "info",
                f"Numeric domain '{domain_name}' (DEC, "
                f"length {length}) has 0 decimal places. "
                f"Verify if decimals are needed.",
                f"Review if domain '{domain_name}' requires "
                f"decimal precision.",
                snippet,
                extra_meta={
                    "data_type": data_type,
                    "length": length,
                    "decimals": decimals_v,
                },
            ))

    return {
        "domain_name": domain_name,
        "properties": [p.model_dump() for p in properties],
        "findings": findings,
    }


# ═══════════════════════════════════════════
# PUBLIC scan() — called by the orchestrator
# ═══════════════════════════════════════════
def scan(
    doma_properties: List[DTELProperty], **kwargs
) -> List[Dict[str, Any]]:
    """
    Entry point called by agent_registry / main.py orchestrator.
    Groups properties by domain name, assesses each, returns results.
    """
    if not doma_properties:
        return []

    # Group by domain name
    domains: Dict[str, List[DTELProperty]] = {}
    current_domain = ""

    for p in doma_properties:
        cat  = (p.category or "").strip().upper()
        prop = (p.property or "").strip()
        val  = (p.value or "").strip()

        if cat == "GENERAL" and prop == "Domain Name":
            current_domain = val

        if current_domain:
            if current_domain not in domains:
                domains[current_domain] = []
            domains[current_domain].append(p)

    results = []
    for domain_name, domain_props in domains.items():
        result = _assess_domain(domain_props)
        results.append(result)

    return results


# ═══════════════════════════════════════════
# AGENT DEFINITION — picked up by registry
# ═══════════════════════════════════════════
AGENT_DEF = {
    "name": "doma_assess",
    "description": "SAP Domain DDIC Assessment — "
                   "25 S/4HANA readiness checks",
    "version": "1.0",
    "input_key": "doma_properties",
    "scan": scan,
    "rules": RULES,
}
