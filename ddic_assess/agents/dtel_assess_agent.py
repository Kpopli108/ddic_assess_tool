"""
agents/dtel_assess_agent.py
────────────────────────────
SAP Data Element DDIC Assessment Agent — S/4HANA Readiness Checks.

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
    DEPRECATED_DATA_TYPE  = "Deprecated Data Type"
    FIELD_LENGTH_CHANGE   = "Field Length Change (S/4HANA)"
    NAMING_CONVENTION     = "Naming Convention Violation"
    DOMAIN_COMPATIBILITY  = "Domain Compatibility"
    CURRENCY_QUANTITY     = "Currency/Quantity Field Check"
    CUSTOM_CODE           = "Custom Code Adaptation"
    UNICODE_COMPLIANCE    = "Unicode Compliance"
    TABLE_FIELD_MAPPING   = "Table/Field Mapping Change"
    SIMPLIFICATION_ITEM   = "Simplification Item"


# ═══════════════════════════════════════════
# RULE CATALOGUE
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
        "description": "Material number (MATNR) extended from 18 to 40 "
                       "characters in S/4HANA.",
    },
    "FLEN_02": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "G/L Account (SAKNR/HKONT) format changed in S/4HANA.",
    },
    "FLEN_03": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Cost Center (KOSTL) must align with new finance.",
    },
    "FLEN_04": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Profit Center (PRCTR) must align with S/4HANA "
                       "finance model.",
    },
    "FLEN_05": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Customer/Vendor number fields changed due to "
                       "Business Partner migration.",
    },
    "FLEN_06": {
        "category": CheckCategory.FIELD_LENGTH_CHANGE,
        "description": "Custom field length may be incompatible with "
                       "S/4HANA extended fields.",
    },
    "NAME_01": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Custom data element name is too short or lacks "
                       "descriptive structure.",
    },
    "NAME_02": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Custom data element name lacks underscores "
                       "for readability.",
    },
    "NAME_03": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Field labels are missing or incomplete.",
    },
    "NAME_04": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Field labels have incorrect length hierarchy "
                       "(short > medium > long).",
    },
    "NAME_05": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Description is missing or too short for "
                       "data element.",
    },
    "NAME_06": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "All field labels are identical — should be "
                       "progressively descriptive.",
    },
    "NAME_07": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Label text exceeds defined max output length.",
    },
    "NAME_08": {
        "category": CheckCategory.NAMING_CONVENTION,
        "description": "Data element has no language translations — "
                       "multi-language recommended.",
    },
    "DOMN_01": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Data element is not domain-based. Domain provides "
                       "reusability and consistency.",
    },
    "DOMN_02": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Domain has no description maintained.",
    },
    "DOMN_03": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Domain has no fixed values for short code-type "
                       "fields.",
    },
    "DOMN_04": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Domain has no value table and no fixed values "
                       "for validation.",
    },
    "DOMN_05": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Lowercase flag enabled — may cause inconsistent "
                       "data storage.",
    },
    "DOMN_06": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Lowercase flag on non-character type is irrelevant.",
    },
    "DOMN_07": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Custom domain has low reuse — may indicate "
                       "poor design.",
    },
    "DOMN_08": {
        "category": CheckCategory.DOMAIN_COMPATIBILITY,
        "description": "Conversion routine present — verify S/4HANA "
                       "compatibility.",
    },
    "CURQ_01": {
        "category": CheckCategory.CURRENCY_QUANTITY,
        "description": "Currency amount field (CURR) must reference "
                       "a currency key field.",
    },
    "CURQ_02": {
        "category": CheckCategory.CURRENCY_QUANTITY,
        "description": "Quantity field (QUAN) must reference a unit "
                       "of measure field.",
    },
    "CURQ_03": {
        "category": CheckCategory.CURRENCY_QUANTITY,
        "description": "Currency amount decimal handling changed in "
                       "S/4HANA (5 decimal places).",
    },
    "CUST_01": {
        "category": CheckCategory.CUSTOM_CODE,
        "description": "Data element not used in any table — may "
                       "be obsolete.",
    },
    "CUST_02": {
        "category": CheckCategory.CUSTOM_CODE,
        "description": "No search help assigned for user-facing field.",
    },
    "CUST_03": {
        "category": CheckCategory.CUSTOM_CODE,
        "description": "No parameter ID (SPA/GPA) assigned.",
    },
    "CUST_04": {
        "category": CheckCategory.CUSTOM_CODE,
        "description": "Reference kind set but reference type is missing.",
    },
    "CUST_05": {
        "category": CheckCategory.CUSTOM_CODE,
        "description": "Output length less than field length — display "
                       "truncation risk.",
    },
    "UNIC_01": {
        "category": CheckCategory.UNICODE_COMPLIANCE,
        "description": "Internal length mismatch in Unicode — byte vs "
                       "character length differs.",
    },
    "UNIC_02": {
        "category": CheckCategory.UNICODE_COMPLIANCE,
        "description": "RAW/LRAW type field — verify byte alignment "
                       "in Unicode systems.",
    },
    "TMAP_01": {
        "category": CheckCategory.TABLE_FIELD_MAPPING,
        "description": "Data element used in tables targeted for "
                       "S/4HANA simplification.",
    },
    "TMAP_02": {
        "category": CheckCategory.TABLE_FIELD_MAPPING,
        "description": "Data element references deprecated/removed "
                       "SAP table.",
    },
    "SIMP_01": {
        "category": CheckCategory.SIMPLIFICATION_ITEM,
        "description": "Data element related to a known S/4HANA "
                       "simplification item.",
    },
    "SIMP_02": {
        "category": CheckCategory.SIMPLIFICATION_ITEM,
        "description": "Domain/data element associated with deprecated "
                       "functionality.",
    },
}


# ═══════════════════════════════════════════
# REFERENCE DATA
# ═══════════════════════════════════════════
S4_FIELD_LENGTH_MAP = {
    "MATNR":      {"old_length": 18, "new_length": 40,
                   "description": "Material Number"},
    "MATNR_LONG": {"old_length": 18, "new_length": 40,
                   "description": "Material Number (Long)"},
    "BISMT":      {"old_length": 18, "new_length": 40,
                   "description": "Old Material Number"},
}

S4_SIMPLIFIED_TABLES = {
    "BSEG", "BSID", "BSAD", "BSIK", "BSAK", "BSIS", "BSAS",
    "GLT0", "GLT3", "GLTO", "FAGLFLEXA", "FAGLFLEXT",
    "COEP", "COEJ", "COBK",
    "LIPS", "LIKP", "VBRP", "VBRK",
    "MBEW", "CKMLHD", "CKMLCR",
    "KNA1", "KNB1", "LFA1", "LFB1",
}

DEPRECATED_TYPES = {
    "ACCP":    {"replacement": "NUMC(6) or DATS",  "rule": "DTYP_01"},
    "PREC":    {"replacement": "DEC or INT",        "rule": "DTYP_02"},
    "DF16_SCL":{"replacement": "D16R",              "rule": "DTYP_03"},
    "DF34_SCL":{"replacement": "D34R",              "rule": "DTYP_03"},
    "LRAW":    {"replacement": "RAWSTRING",         "rule": "DTYP_04"},
    "LCHR":    {"replacement": "STRING",            "rule": "DTYP_04"},
    "VARC":    {"replacement": "STRING or SSTRING", "rule": "DTYP_05"},
}

CURRENCY_TYPES = {"CURR"}
QUANTITY_TYPES = {"QUAN"}

SIMPLIFICATION_MAP = {
    "KUNNR": "Customer master → Business Partner (SI #28)",
    "LIFNR": "Vendor master → Business Partner (SI #28)",
    "SAKNR": "G/L Account → Universal Journal ACDOCA (SI #2)",
    "HKONT": "G/L Account → Universal Journal ACDOCA (SI #2)",
    "KSTAR": "Cost Element → G/L Account (SI #7)",
    "MATNR": "Material Number extended to 40 chars (SI #18)",
    "BELNR": "Document Number — BSEG replaced by ACDOCA (SI #2)",
    "VBELN": "Sales Document — review for S/4 simplifications",
    "EBELN": "Purchase Document — review for S/4 simplifications",
    "RSNUM": "Reservation Number — material document changes (SI #22)",
    "AUFNR": "Order Number — review for S/4HANA",
}

DEPRECATED_DOMAINS = {
    "KUNNR": "Customer number domain → Business Partner",
    "LIFNR": "Vendor number domain → Business Partner",
    "SAKNR": "GL Account domain → Universal Journal",
    "HKONT": "GL Account domain → Universal Journal",
    "KSTAR": "Cost Element domain → GL Account",
    "BSEG":  "BSEG domain → ACDOCA",
    "KOART": "Account type — review for S/4HANA changes",
}


# ═══════════════════════════════════════════
# HELPER UTILITIES
# ═══════════════════════════════════════════
def _parse_dtel_properties(
    properties: List[DTELProperty],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "general": {}, "technical": {}, "field_label": {},
        "search_help": {}, "parameter_id": {}, "domain": {},
        "fixed_values": [], "languages": [], "where_used": [],
        "summary": {},
    }
    for p in properties:
        cat  = (p.category or "").strip().upper()
        prop = (p.property or "").strip()
        val  = (p.value or "").strip()

        if   cat == "GENERAL":      result["general"][prop] = val
        elif cat == "TECHNICAL":    result["technical"][prop] = val
        elif cat == "FIELD_LABEL":  result["field_label"][prop] = val
        elif cat == "SEARCH_HELP":  result["search_help"][prop] = val
        elif cat == "PARAMETER_ID": result["parameter_id"][prop] = val
        elif cat == "DOMAIN":       result["domain"][prop] = val
        elif cat == "FIXED_VALUE":
            result["fixed_values"].append({"key": prop, "value": val})
        elif cat.startswith("LANG_"):
            lang_code = cat.replace("LANG_", "")
            result["languages"].append(
                {"language": lang_code, "text": val}
            )
        elif cat == "WHERE_USED":
            result["where_used"].append({"table": prop, "detail": val})
        elif cat == "SUMMARY":
            result["summary"][prop] = val

    return result


def _build_dtel_snippet(parsed: Dict[str, Any]) -> str:
    gen  = parsed.get("general", {})
    tech = parsed.get("technical", {})
    return (
        f"DTEL={gen.get('Data Element Name', '')} | "
        f"DESC={gen.get('Description', '')} | "
        f"TYPE={tech.get('Data Type', '')} | "
        f"LEN={tech.get('Length', '')} | "
        f"DOMAIN={tech.get('Domain Name', '')} | "
        f"PKG={gen.get('Package', '')}"
    )


def _parse_label(label_value: str):
    match = re.match(
        r"^(.*?)\s*\(Max Length:\s*(\d+)\)\s*$", label_value
    )
    if match:
        return match.group(1).strip(), int(match.group(2))
    return label_value.strip(), 0


def _parse_summary_counts(summary: Dict[str, str]) -> Dict[str, int]:
    counts_str = summary.get("Counts", "")
    result = {"languages": 0, "fixed_values": 0, "where_used": 0}
    for key, pattern in [
        ("languages",   r"Languages:\s*(\d+)"),
        ("fixed_values", r"Fixed Values:\s*(\d+)"),
        ("where_used",  r"Where-Used:\s*(\d+)"),
    ]:
        m = re.search(pattern, counts_str)
        if m:
            result[key] = int(m.group(1))
    return result


def _safe_int(val: str) -> int:
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return 0


def _make_finding(
    rollname: str,
    rule_id: str,
    severity: str,
    message: str,
    suggestion: str,
    snippet: str,
    extra_meta: Optional[Dict[str, Any]] = None,
    fieldname: str = "",
    obj_type: str = "DATA_ELEMENT",
    obj_name: str = "",
) -> Dict[str, Any]:
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
        "object_name": rollname,
        "fieldname": fieldname,
        "type": obj_type,
        "name": obj_name or rollname,
        "start_line": None, "end_line": None,
        "issue_type": rule_id,
        "severity": severity,
        "line": None,
        "message": message,
        "suggestion": suggestion,
        "snippet": snippet,
        "meta": meta,
    }


# ═══════════════════════════════════════════
# CORE: assess one data element
# ═══════════════════════════════════════════
def _assess_data_element(
    properties: List[DTELProperty],
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    if not properties:
        return {
            "rollname": "",
            "properties": [],
            "findings": [],
        }

    parsed     = _parse_dtel_properties(properties)
    gen        = parsed.get("general", {})
    tech       = parsed.get("technical", {})
    labels     = parsed.get("field_label", {})
    sh         = parsed.get("search_help", {})
    pid        = parsed.get("parameter_id", {})
    dom        = parsed.get("domain", {})
    fixed_vals = parsed.get("fixed_values", [])
    languages  = parsed.get("languages", [])
    where_used = parsed.get("where_used", [])
    summary    = parsed.get("summary", {})

    # Extract key values
    rollname    = gen.get("Data Element Name", "").strip().upper()
    description = gen.get("Description", "").strip()
    type_def    = gen.get("Type Definition", "").strip()
    data_type   = tech.get("Data Type", "").strip().upper()
    length      = _safe_int(tech.get("Length", "0"))
    decimals_v  = _safe_int(tech.get("Decimals", "0"))
    output_len  = _safe_int(tech.get("Output Length", "0"))
    domain_name = tech.get("Domain Name", "").strip()
    ref_kind    = tech.get("Reference Kind", "").strip()
    ref_type    = tech.get("Reference Type", "").strip()
    int_type    = tech.get("Internal Type", "").strip()
    int_len     = _safe_int(tech.get("Internal Length", "0"))

    snippet   = _build_dtel_snippet(parsed)
    counts    = _parse_summary_counts(summary)
    wu_count  = counts.get("where_used", len(where_used))
    is_custom = rollname.startswith("Z") or rollname.startswith("Y")

    short_text,  short_max  = _parse_label(
        labels.get("Short Text", "")
    )
    medium_text, medium_max = _parse_label(
        labels.get("Medium Text", "")
    )
    long_text,   long_max   = _parse_label(
        labels.get("Long Text", "")
    )
    heading = labels.get("Heading", "").strip()

    # ─── DEPRECATED DATA TYPE ───
    if data_type in DEPRECATED_TYPES:
        dep = DEPRECATED_TYPES[data_type]
        findings.append(_make_finding(
            rollname, dep["rule"], "critical",
            f"Data element '{rollname}' uses deprecated data type "
            f"'{data_type}'. Not supported in S/4HANA.",
            f"Replace '{data_type}' with '{dep['replacement']}'.",
            snippet,
            extra_meta={
                "current_type": data_type,
                "replacement": dep["replacement"],
            },
        ))

    # ─── FIELD LENGTH CHANGE ───
    if rollname in S4_FIELD_LENGTH_MAP:
        fl = S4_FIELD_LENGTH_MAP[rollname]
        if length < fl["new_length"]:
            findings.append(_make_finding(
                rollname, "FLEN_01", "critical",
                f"'{rollname}' ({fl['description']}) length {length} "
                f"but S/4HANA requires {fl['new_length']}.",
                f"Extend to {fl['new_length']}. Review dependents.",
                snippet,
                extra_meta={
                    "old_length": fl["old_length"],
                    "new_length": fl["new_length"],
                    "current_length": length,
                },
            ))

    extended_domains = {"MATNR", "BISMT"}
    if domain_name.upper() in extended_domains and is_custom:
        dom_info = S4_FIELD_LENGTH_MAP.get(domain_name.upper(), {})
        if dom_info and length < dom_info.get("new_length", 0):
            findings.append(_make_finding(
                rollname, "FLEN_06", "high",
                f"Custom '{rollname}' uses domain '{domain_name}' "
                f"extended to {dom_info['new_length']} in S/4HANA, "
                f"current length {length}.",
                f"Align length with S/4HANA domain.",
                snippet,
                extra_meta={
                    "domain": domain_name,
                    "current_length": length,
                    "required_length": dom_info["new_length"],
                },
            ))

    # ─── NAMING CONVENTION ───
    if is_custom:
        if len(rollname) < 3:
            findings.append(_make_finding(
                rollname, "NAME_01", "warning",
                f"Custom '{rollname}' is very short ({len(rollname)} chars).",
                f"Rename to Z<namespace>_<description>.",
                snippet,
                extra_meta={"name_length": len(rollname)},
            ))

        name_body = rollname[1:]
        if "_" not in name_body and len(name_body) > 5:
            findings.append(_make_finding(
                rollname, "NAME_02", "info",
                f"Custom '{rollname}' lacks underscores for readability.",
                f"Use Z_<namespace>_<description>.",
                snippet,
            ))

    if not description:
        findings.append(_make_finding(
            rollname, "NAME_05", "high",
            f"'{rollname}' has no description.",
            f"Maintain a meaningful description.", snippet,
        ))
    elif len(description) < 5:
        findings.append(_make_finding(
            rollname, "NAME_05", "warning",
            f"'{rollname}' description too short ({len(description)} chars).",
            f"Provide descriptive text (min 10 chars).", snippet,
            extra_meta={"description_length": len(description)},
        ))

    missing_labels = []
    if not short_text:  missing_labels.append("Short")
    if not medium_text: missing_labels.append("Medium")
    if not long_text:   missing_labels.append("Long")
    if not heading:     missing_labels.append("Heading")
    if missing_labels:
        findings.append(_make_finding(
            rollname, "NAME_03", "high",
            f"'{rollname}' missing labels: {', '.join(missing_labels)}.",
            f"Maintain all field labels.", snippet,
            extra_meta={"missing_labels": missing_labels},
        ))

    label_texts = [t for t in
                   [short_text, medium_text, long_text, heading] if t]
    if len(label_texts) >= 3 and len(set(label_texts)) == 1:
        findings.append(_make_finding(
            rollname, "NAME_06", "info",
            f"All labels for '{rollname}' are identical: "
            f"'{label_texts[0]}'.",
            f"Short=abbreviated, Medium=concise, Long=descriptive.",
            snippet,
            extra_meta={
                "short": short_text, "medium": medium_text,
                "long": long_text, "heading": heading,
            },
        ))

    if (short_text and medium_text
            and len(short_text) > len(medium_text)):
        findings.append(_make_finding(
            rollname, "NAME_04", "warning",
            f"Short text longer than medium text.",
            f"Short text should be shorter than medium.", snippet,
            extra_meta={
                "short_len": len(short_text),
                "medium_len": len(medium_text),
            },
        ))

    for lbl_name, lbl_text, lbl_max in [
        ("Short", short_text, short_max),
        ("Medium", medium_text, medium_max),
        ("Long", long_text, long_max),
    ]:
        if lbl_text and lbl_max > 0 and len(lbl_text) > lbl_max:
            findings.append(_make_finding(
                rollname, "NAME_07", "warning",
                f"{lbl_name} text exceeds max length {lbl_max}.",
                f"Shorten to fit {lbl_max} characters.", snippet,
                extra_meta={
                    "label_type": lbl_name,
                    "text_length": len(lbl_text),
                    "max_length": lbl_max,
                },
            ))

    lang_count = counts.get("languages", len(languages))
    if lang_count < 2:
        findings.append(_make_finding(
            rollname, "NAME_08", "info",
            f"'{rollname}' has only {lang_count} language(s).",
            f"Translate into all required languages.", snippet,
            extra_meta={
                "language_count": lang_count,
                "languages": [l.get("language", "") for l in languages],
            },
        ))

    # ─── DOMAIN COMPATIBILITY ───
    if type_def != "Domain-Based" or not domain_name:
        findings.append(_make_finding(
            rollname, "DOMN_01", "warning",
            f"'{rollname}' is not domain-based (Type: '{type_def}').",
            f"Create and assign a domain.", snippet,
            extra_meta={"type_definition": type_def},
        ))

    if domain_name:
        dom_desc    = dom.get("Domain Description", "").strip()
        lowercase   = dom.get("Lowercase Allowed", "").strip().upper()
        convexit    = dom.get("Conversion Routine", "").strip()
        value_table = dom.get("Value Table", "").strip()
        is_custom_domain = (
            domain_name.startswith("Z") or domain_name.startswith("Y")
        )

        if not dom_desc:
            findings.append(_make_finding(
                rollname, "DOMN_02", "warning",
                f"Domain '{domain_name}' has no description.",
                f"Maintain description.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
            ))

        if (not fixed_vals
                and data_type in ("CHAR", "NUMC")
                and 0 < length <= 4):
            findings.append(_make_finding(
                rollname, "DOMN_03", "info",
                f"Domain '{domain_name}' ({data_type}, len {length}) "
                f"has no fixed values.",
                f"Consider adding fixed values.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
            ))

        if (not value_table and not fixed_vals
                and data_type in ("CHAR", "NUMC")
                and 0 < length <= 10):
            findings.append(_make_finding(
                rollname, "DOMN_04", "info",
                f"Domain '{domain_name}' has no value table and "
                f"no fixed values.",
                f"Assign value table or fixed values.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
            ))

        if lowercase == "X" and data_type in (
            "CHAR", "SSTRING", "STRING"
        ):
            findings.append(_make_finding(
                rollname, "DOMN_05", "info",
                f"Domain '{domain_name}' allows lowercase.",
                f"Disable unless explicitly required.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
            ))

        if lowercase == "X" and data_type in (
            "NUMC", "DATS", "TIMS", "DEC", "INT4"
        ):
            findings.append(_make_finding(
                rollname, "DOMN_06", "warning",
                f"Domain '{domain_name}' lowercase on '{data_type}' "
                f"is irrelevant.",
                f"Remove lowercase flag.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
            ))

        if is_custom_domain and wu_count <= 1:
            findings.append(_make_finding(
                rollname, "DOMN_07", "info",
                f"Custom domain '{domain_name}' used in only "
                f"{wu_count} table(s).",
                f"Review if reusable or replace with standard.",
                snippet,
                obj_type="DOMAIN", obj_name=domain_name,
                extra_meta={"where_used_count": wu_count},
            ))

        if convexit:
            findings.append(_make_finding(
                rollname, "DOMN_08", "info",
                f"Domain '{domain_name}' has conversion routine "
                f"'{convexit}'.",
                f"Test in S/4HANA. Custom routines may need migration.",
                snippet,
                obj_type="DOMAIN", obj_name=domain_name,
                extra_meta={"conversion_routine": convexit},
            ))

    # ─── CURRENCY / QUANTITY ───
    if data_type in CURRENCY_TYPES:
        findings.append(_make_finding(
            rollname, "CURQ_01", "high",
            f"'{rollname}' is CURR. Must reference currency key.",
            f"Ensure CUKY reference via REFTABLE/REFFIELD.", snippet,
            extra_meta={"data_type": data_type},
        ))
        if decimals_v < 5:
            findings.append(_make_finding(
                rollname, "CURQ_03", "warning",
                f"Currency '{rollname}' has {decimals_v} decimals. "
                f"S/4HANA uses 5.",
                f"Review decimal handling.", snippet,
                extra_meta={
                    "current_decimals": decimals_v, "s4_decimals": 5,
                },
            ))

    if data_type in QUANTITY_TYPES:
        findings.append(_make_finding(
            rollname, "CURQ_02", "high",
            f"'{rollname}' is QUAN. Must reference unit of measure.",
            f"Ensure UNIT reference via REFTABLE/REFFIELD.", snippet,
            extra_meta={"data_type": data_type},
        ))

    # ─── CUSTOM CODE ADAPTATION ───
    if wu_count == 0:
        findings.append(_make_finding(
            rollname, "CUST_01", "warning",
            f"'{rollname}' not used in any table. May be obsolete.",
            f"Delete if unused.", snippet,
            extra_meta={"where_used_count": 0},
        ))

    sh_name   = sh.get("Search Help Name", "").strip()
    sh_status = sh.get("Search Help", "").strip()
    if (sh_status == "Not Assigned" or not sh_name):
        if data_type in ("CHAR", "NUMC", "SSTRING") and length >= 3:
            findings.append(_make_finding(
                rollname, "CUST_02", "info",
                f"'{rollname}' has no search help.",
                f"Assign if user-facing.", snippet,
            ))

    pid_value  = pid.get("Parameter ID (SPA/GPA)", "").strip()
    pid_status = pid.get("Parameter ID", "").strip()
    if pid_status == "Not Assigned" or not pid_value:
        findings.append(_make_finding(
            rollname, "CUST_03", "info",
            f"'{rollname}' has no parameter ID.",
            f"Assign if used in selection screens.", snippet,
        ))

    if ref_kind and not ref_type:
        findings.append(_make_finding(
            rollname, "CUST_04", "warning",
            f"'{rollname}' has ref kind '{ref_kind}' but no ref type.",
            f"Assign reference type.", snippet,
            extra_meta={"ref_kind": ref_kind},
        ))

    if (output_len > 0 and length > 0
            and output_len < length
            and data_type not in ("DEC", "CURR", "QUAN", "FLTP")):
        findings.append(_make_finding(
            rollname, "CUST_05", "warning",
            f"'{rollname}' output length ({output_len}) < field "
            f"length ({length}). Truncation risk.",
            f"Set output length >= field length.", snippet,
            extra_meta={
                "output_length": output_len, "field_length": length,
            },
        ))

    # ─── UNICODE COMPLIANCE ───
    if int_type in ("C", "N", "D", "T") and int_len > 0 and length > 0:
        expected = length * 2
        if int_len != expected and int_len != length:
            findings.append(_make_finding(
                rollname, "UNIC_01", "warning",
                f"'{rollname}' internal length ({int_len}) may not "
                f"match Unicode expectation ({expected}).",
                f"Verify internal length alignment.", snippet,
                extra_meta={
                    "internal_type": int_type,
                    "internal_length": int_len,
                    "field_length": length,
                    "expected_unicode_length": expected,
                },
            ))

    if data_type in ("RAW", "LRAW", "RAWSTRING"):
        findings.append(_make_finding(
            rollname, "UNIC_02", "info",
            f"'{rollname}' uses RAW type '{data_type}'. "
            f"Verify byte alignment.",
            f"Review byte handling in structures.", snippet,
            extra_meta={"data_type": data_type},
        ))

    # ─── TABLE/FIELD MAPPING CHANGE ───
    simplified_hits = [
        w.get("table", "").strip().upper()
        for w in where_used
        if w.get("table", "").strip().upper() in S4_SIMPLIFIED_TABLES
    ]
    if simplified_hits:
        findings.append(_make_finding(
            rollname, "TMAP_01", "high",
            f"'{rollname}' used in simplified table(s): "
            f"{', '.join(simplified_hits)}.",
            f"Map to new S/4HANA structures (ACDOCA, MATDOC, etc.).",
            snippet,
            extra_meta={
                "simplified_tables": simplified_hits,
                "total_simplified_hits": len(simplified_hits),
            },
        ))

    if domain_name:
        dom_vt = dom.get("Value Table", "").strip().upper()
        if dom_vt in S4_SIMPLIFIED_TABLES:
            findings.append(_make_finding(
                rollname, "TMAP_02", "high",
                f"Domain '{domain_name}' value table '{dom_vt}' is "
                f"deprecated in S/4HANA.",
                f"Update value table to S/4HANA replacement.", snippet,
                obj_type="DOMAIN", obj_name=domain_name,
                extra_meta={"value_table": dom_vt, "deprecated": True},
            ))

    # ─── SIMPLIFICATION ITEM ───
    if rollname in SIMPLIFICATION_MAP:
        findings.append(_make_finding(
            rollname, "SIMP_01", "high",
            f"'{rollname}' is related to: "
            f"{SIMPLIFICATION_MAP[rollname]}.",
            f"Review Simplification Item list. SAP Note 2313884.",
            snippet,
            extra_meta={
                "simplification_item": SIMPLIFICATION_MAP[rollname],
                "sap_note": "2313884",
            },
        ))

    if (domain_name.upper() in DEPRECATED_DOMAINS
            and rollname not in SIMPLIFICATION_MAP):
        findings.append(_make_finding(
            rollname, "SIMP_02", "warning",
            f"Domain '{domain_name}' associated with deprecated "
            f"functionality: "
            f"{DEPRECATED_DOMAINS[domain_name.upper()]}.",
            f"Review for S/4HANA compatibility.", snippet,
            obj_type="DOMAIN", obj_name=domain_name,
            extra_meta={
                "deprecated_info":
                    DEPRECATED_DOMAINS[domain_name.upper()],
            },
        ))

    return {
        "rollname": rollname,
        "properties": [p.model_dump() for p in properties],
        "findings": findings,
    }


# ═══════════════════════════════════════════
# PUBLIC scan() — called by the orchestrator
# ═══════════════════════════════════════════
def scan(
    dtel_properties: List[DTELProperty], **kwargs
) -> List[Dict[str, Any]]:
    """
    Entry point called by agent_registry / main.py orchestrator.
    Groups properties by data element name, assesses each, returns results.
    """
    if not dtel_properties:
        return []

    # Group by data element name
    dtels: Dict[str, List[DTELProperty]] = {}
    current_dtel = ""

    for p in dtel_properties:
        cat  = (p.category or "").strip().upper()
        prop = (p.property or "").strip()
        val  = (p.value or "").strip()

        if cat == "GENERAL" and prop == "Data Element Name":
            current_dtel = val

        if current_dtel:
            if current_dtel not in dtels:
                dtels[current_dtel] = []
            dtels[current_dtel].append(p)

    results = []
    for dtel_name, dtel_props in dtels.items():
        result = _assess_data_element(dtel_props)
        results.append(result)

    return results


# ═══════════════════════════════════════════
# AGENT DEFINITION — picked up by registry
# ═══════════════════════════════════════════
AGENT_DEF = {
    "name": "dtel_assess",
    "description": "SAP Data Element DDIC Assessment — "
                   "S/4HANA readiness checks",
    "version": "2.1",
    "input_key": "dtel_properties",     # which ScanRequest field to read
    "scan": scan,
    "rules": RULES,
}