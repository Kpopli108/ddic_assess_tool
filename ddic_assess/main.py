"""
main.py — SAP DDIC Assessment Orchestrator
"""

from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any
import traceback

from models import (
    DDICField,
    DTELProperty,
    ScanRequest,
    ScanResponse,
    AgentResult,
)
from agent_registry import AGENTS

app = FastAPI(
    title="SAP DDIC Assessment Orchestrator",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_agents(request, agent_names=None):
    if agent_names:
        agents_to_run = [a for a in AGENTS if a["name"] in agent_names]
    else:
        agents_to_run = AGENTS

    agent_results = []
    all_findings = []
    total = 0
    succeeded = 0
    failed = 0

    for agent in agents_to_run:
        try:
            input_key = agent.get("input_key", "")
            input_data = getattr(request, input_key, None)

            if not input_data:
                agent_results.append(AgentResult(
                    agent_name=agent["name"],
                    status="skipped",
                    finding_count=0,
                    results=[],
                ))
                continue

            results = agent["scan"](**{input_key: input_data})

            count = 0
            for r in results:
                for f in r.get("findings", []):
                    count += 1
                    entry = dict(f)
                    entry["_agent"] = agent["name"]
                    all_findings.append(entry)

            total += count
            succeeded += 1
            agent_results.append(AgentResult(
                agent_name=agent["name"],
                status="success",
                finding_count=count,
                results=results,
            ))
        except Exception:
            failed += 1
            agent_results.append(AgentResult(
                agent_name=agent["name"],
                status="error",
                error_message=traceback.format_exc(),
            ))

    return ScanResponse(
        total_findings=total,
        agents_called=len(agents_to_run),
        agents_succeeded=succeeded,
        agents_failed=failed,
        agent_results=agent_results,
        all_findings=all_findings,
    )


# ══════════════════════════════════════
# 1) POST /scan-all
# ══════════════════════════════════════
@app.post("/scan-all", response_model=ScanResponse)
def scan_all(request: ScanRequest = Body(...)):
    return run_agents(request, request.agents)


# ══════════════════════════════════════
# 2) POST /assess-table
# ══════════════════════════════════════
@app.post("/assess-table")
def assess_single_table(fields: List[DDICField] = Body(...)):
    request = ScanRequest(table_fields=fields, agents=["table_assess"])
    response = run_agents(request, ["table_assess"])
    for ar in response.agent_results:
        if ar.results:
            return ar.results[0]
    return {"tabname": "", "fields": [], "findings": []}


# ══════════════════════════════════════
# 3) POST /assess-tables
# ══════════════════════════════════════
@app.post("/assess-tables")
def assess_multiple_tables(fields: List[DDICField] = Body(...)):
    request = ScanRequest(table_fields=fields, agents=["table_assess"])
    response = run_agents(request, ["table_assess"])
    results = []
    for ar in response.agent_results:
        if ar.results:
            for r in ar.results:
                if r.get("findings"):
                    results.append(r)
    return results


# ══════════════════════════════════════
# 4) POST /assess-dtel   <-- THIS IS THE ONE YOU NEED
# ══════════════════════════════════════
@app.post("/assess-dtel")
def assess_single_dtel(properties: List[DTELProperty] = Body(...)):
    """Assess a single data element from DTELProperty list."""
    print(">>> /assess-dtel called with", len(properties), "properties")
    request = ScanRequest(dtel_properties=properties, agents=["dtel_assess"])
    response = run_agents(request, ["dtel_assess"])
    for ar in response.agent_results:
        if ar.results:
            return ar.results[0]
    return {"rollname": "", "properties": [], "findings": []}


# ══════════════════════════════════════
# 5) POST /assess-dtels
# ══════════════════════════════════════
@app.post("/assess-dtels")
def assess_multiple_dtels(properties: List[DTELProperty] = Body(...)):
    """Assess multiple data elements from DTELProperty list."""
    print(">>> /assess-dtels called with", len(properties), "properties")
    request = ScanRequest(dtel_properties=properties, agents=["dtel_assess"])
    response = run_agents(request, ["dtel_assess"])
    results = []
    for ar in response.agent_results:
        if ar.results:
            for r in ar.results:
                if r.get("findings"):
                    results.append(r)
    return results


# ══════════════════════════════════════
# 6) GET /agents
# ══════════════════════════════════════
@app.get("/agents")
def list_agents():
    return {
        "count": len(AGENTS),
        "agents": [
            {
                "name": a["name"],
                "description": a.get("description", ""),
                "version": a.get("version", ""),
                "input_key": a.get("input_key", ""),
            }
            for a in AGENTS
        ],
    }


# ══════════════════════════════════════
# 7) GET /health
# ══════════════════════════════════════
@app.get("/health")
def health():
    return {
        "ok": True,
        "agents_loaded": len(AGENTS),
        "agent_names": [a["name"] for a in AGENTS],
    }


# ══════════════════════════════════════
# DEBUG: Print all routes on startup
# ══════════════════════════════════════
@app.on_event("startup")
def show_routes():
    print("")
    print("=" * 50)
    print("  REGISTERED ENDPOINTS")
    print("=" * 50)
    for route in app.routes:
        if hasattr(route, "methods"):
            for method in route.methods:
                print(f"  {method:6s} {route.path}")
    print("=" * 50)
    print("")
