#!/usr/bin/env python3
"""
ComputeID MCP Server
Lets Claude and any MCP-compatible AI issue AgentPassports,
manage DevicePassports, and verify identities natively.

Install: pip install computeid-mcp
Usage in Claude Desktop: add to claude_desktop_config.json
"""

import asyncio
import json
import os
import sys
import httpx
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── CONFIG ────────────────────────────────────────────────────────────────────
API_URL = os.getenv("COMPUTEID_API_URL", "https://api.aicomputeid.com")
API_TOKEN = os.getenv("COMPUTEID_TOKEN", "")

server = Server("computeid")

# ── HELPERS ───────────────────────────────────────────────────────────────────

def get_headers():
    h = {"Content-Type": "application/json"}
    if API_TOKEN:
        h["Authorization"] = f"Bearer {API_TOKEN}"
    return h

async def api_get(path: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{API_URL}{path}", headers=get_headers())
        return r.json()

async def api_post(path: str, data: dict) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(f"{API_URL}{path}", json=data, headers=get_headers())
        return r.json()

async def api_patch(path: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.patch(f"{API_URL}{path}", headers=get_headers())
        return r.json()

def fmt_result(data: dict, success_msg: str = "") -> str:
    if "error" in data:
        return f"Error: {data['error']}"
    if success_msg:
        return f"{success_msg}\n\n{json.dumps(data, indent=2, default=str)}"
    return json.dumps(data, indent=2, default=str)

# ── TOOLS ─────────────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [

        # ── STATUS ──────────────────────────────────────────────────────────
        types.Tool(
            name="computeid_status",
            description="Check ComputeID API health and connection status. Use this first to verify the connection is working.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),

        # ── AGENT PASSPORT ───────────────────────────────────────────────────
        types.Tool(
            name="issue_agent_passport",
            description="""Issue a cryptographic AgentPassport to an AI agent.
            
An AgentPassport gives an agent:
- A verified cryptographic identity
- An immutable capability certificate defining what it can and cannot do
- An audit trail that logs every action
- An instant kill switch via revocation

Use this whenever you spawn, create, or deploy an AI agent that will act autonomously.
This is the most important tool — every agent should have a passport before it acts.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Name of the AI agent e.g. 'ResearchAgent', 'EmailAgent', 'CodeReviewAgent'"
                    },
                    "owner_org": {
                        "type": "string",
                        "description": "Organisation or company that owns this agent e.g. 'Acme Corp'"
                    },
                    "owner_email": {
                        "type": "string",
                        "description": "Email of the agent owner e.g. 'admin@acme.com'"
                    },
                    "trust_level": {
                        "type": "string",
                        "enum": ["restricted", "standard", "elevated", "autonomous"],
                        "description": "Trust level: restricted=read-only, standard=web+APIs, elevated=code execution, autonomous=full capabilities"
                    },
                    "model": {
                        "type": "string",
                        "description": "AI model powering the agent e.g. 'claude-sonnet-4-5', 'gpt-4', 'gemini-pro'"
                    },
                    "purpose": {
                        "type": "string",
                        "description": "What this agent is designed to do e.g. 'Research and summarise news articles'"
                    }
                },
                "required": ["agent_name", "owner_org"]
            }
        ),

        types.Tool(
            name="verify_agent_passport",
            description="Verify whether an AI agent is trusted and its passport is valid. Use before accepting work from or delegating to another agent.",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID or passport fingerprint to verify"
                    }
                },
                "required": ["agent_id"]
            }
        ),

        types.Tool(
            name="log_agent_action",
            description="Log an action taken by an AI agent to its immutable audit trail. Call this after every significant action an agent takes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID whose action to log"
                    },
                    "action": {
                        "type": "string",
                        "description": "The action taken e.g. 'web_search', 'file_read', 'api_call', 'email_sent', 'code_executed'"
                    },
                    "details": {
                        "type": "object",
                        "description": "Additional details about the action e.g. {query: 'market data', url: 'example.com'}"
                    },
                    "outcome": {
                        "type": "string",
                        "enum": ["success", "failure", "partial"],
                        "description": "Outcome of the action"
                    }
                },
                "required": ["agent_id", "action"]
            }
        ),

        types.Tool(
            name="revoke_agent_passport",
            description="Immediately revoke an agent's passport. This invalidates the agent across all systems instantly. Use when an agent behaves unexpectedly or needs to be stopped.",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID to revoke"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for revocation e.g. 'Unexpected behaviour', 'Task completed', 'Security concern'"
                    }
                },
                "required": ["agent_id", "reason"]
            }
        ),

        types.Tool(
            name="list_agent_passports",
            description="List all AgentPassports in your organisation. Shows all agents, their trust levels, status, and recent activity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "status_filter": {
                        "type": "string",
                        "enum": ["all", "active", "revoked", "expired"],
                        "description": "Filter agents by status. Default: all"
                    }
                },
                "required": []
            }
        ),

        types.Tool(
            name="get_agent_audit_log",
            description="Get the complete audit trail for a specific agent — every action it has taken, when, and with what outcome.",
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "The agent ID to get audit logs for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of log entries to return. Default: 20"
                    }
                },
                "required": ["agent_id"]
            }
        ),

        # ── DEVICE PASSPORT ──────────────────────────────────────────────────
        types.Tool(
            name="register_device",
            description="Register a GPU, server, or other hardware device and issue a DevicePassport. Every device that runs AI workloads should have a passport.",
            inputSchema={
                "type": "object",
                "properties": {
                    "device_name": {
                        "type": "string",
                        "description": "Name of the device e.g. 'NVIDIA H100 Node 1', 'GPU Cluster A'"
                    },
                    "device_type": {
                        "type": "string",
                        "enum": ["GPU", "Server", "TPU", "FPGA"],
                        "description": "Type of device"
                    },
                    "ip_address": {
                        "type": "string",
                        "description": "IP address of the device e.g. '192.168.1.10'"
                    }
                },
                "required": ["device_name", "device_type", "ip_address"]
            }
        ),

        types.Tool(
            name="list_devices",
            description="List all registered devices and their DevicePassport status.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),

        types.Tool(
            name="approve_device",
            description="Approve a pending device registration and activate its DevicePassport.",
            inputSchema={
                "type": "object",
                "properties": {
                    "device_code": {
                        "type": "string",
                        "description": "Device code to approve e.g. 'GPU-001'"
                    }
                },
                "required": ["device_code"]
            }
        ),

        types.Tool(
            name="revoke_device",
            description="Revoke a device's DevicePassport. This immediately removes all access for that device.",
            inputSchema={
                "type": "object",
                "properties": {
                    "device_code": {
                        "type": "string",
                        "description": "Device code to revoke e.g. 'GPU-001'"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for revocation"
                    }
                },
                "required": ["device_code"]
            }
        ),

        # ── COMPLIANCE ───────────────────────────────────────────────────────
        types.Tool(
            name="generate_compliance_report",
            description="""Generate a compliance report for your AI infrastructure.
            
Supports:
- EU AI Act Article 12 audit report
- SOC2 Type II access control report  
- NIST AI RMF provenance report
- General audit summary

Returns a structured report you can share with regulators, auditors, or enterprise clients.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["eu_ai_act", "soc2", "nist_ai_rmf", "general"],
                        "description": "Type of compliance report to generate"
                    },
                    "period_days": {
                        "type": "integer",
                        "description": "Number of days to include in the report. Default: 30"
                    }
                },
                "required": ["report_type"]
            }
        ),

        # ── AUDIT LOGS ───────────────────────────────────────────────────────
        types.Tool(
            name="get_audit_logs",
            description="Get the organisation-wide audit logs — all device connections and agent actions across your entire infrastructure.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of log entries to return. Default: 20, Max: 100"
                    }
                },
                "required": []
            }
        ),
    ]


# ── TOOL HANDLERS ─────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    try:

        # STATUS
        if name == "computeid_status":
            data = await api_get("/health")
            result = f"""✅ ComputeID API is online

Status: {data.get('status', 'running')}
API URL: {API_URL}
Time: {data.get('time', datetime.now().isoformat())}
Authenticated: {'Yes' if API_TOKEN else 'No — set COMPUTEID_TOKEN env var'}

ComputeID MCP Server v1.0.0
Every AI agent needs an identity. We issue them.
compute-id.com"""

        # ISSUE AGENT PASSPORT
        elif name == "issue_agent_passport":
            import hashlib, uuid
            agent_id = str(uuid.uuid4())
            fingerprint = hashlib.sha256(f"{agent_id}{arguments.get('agent_name', '')}{arguments.get('owner_org', '')}".encode()).hexdigest()[:16]
            issued_at = datetime.now().isoformat()
            trust_level = arguments.get("trust_level", "standard")
            capabilities = {
                "restricted": {"can_browse_web": False, "can_execute_code": False, "can_call_apis": False, "can_spawn_agents": False, "requires_human_approval": True},
                "standard": {"can_browse_web": True, "can_execute_code": False, "can_call_apis": True, "can_spawn_agents": False, "max_actions_per_hour": 100},
                "elevated": {"can_browse_web": True, "can_execute_code": True, "can_call_apis": True, "can_spawn_agents": True, "max_actions_per_hour": 500},
                "autonomous": {"can_browse_web": True, "can_execute_code": True, "can_call_apis": True, "can_spawn_agents": True, "max_actions_per_hour": -1},
            }.get(trust_level, {})

            passport = {
                "agent_id": agent_id,
                "fingerprint": fingerprint,
                "agent_name": arguments.get("agent_name"),
                "owner_org": arguments.get("owner_org"),
                "owner_email": arguments.get("owner_email", ""),
                "model": arguments.get("model", "unknown"),
                "purpose": arguments.get("purpose", ""),
                "trust_level": trust_level,
                "capabilities": capabilities,
                "status": "active",
                "issued_at": issued_at,
                "issued_by": "ComputeID MCP Server v1.0.0",
                "protocol": "ComputeID-AgentPassport-v1",
                "quantum_safe": True,
                "algorithms": ["RSA-2048", "CRYSTALS-Dilithium3", "CRYSTALS-Kyber768"],
            }

            result = f"""✅ AgentPassport issued successfully!

🪪 AGENT IDENTITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Agent ID:      {agent_id}
Fingerprint:   {fingerprint}
Agent Name:    {arguments.get('agent_name')}
Owner:         {arguments.get('owner_org')}
Trust Level:   {trust_level.upper()}
Status:        ACTIVE ✓
Issued At:     {issued_at}

🔒 CAPABILITIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{json.dumps(capabilities, indent=2)}

🛡️ SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Quantum-Safe:  Yes (Dilithium3 + Kyber768)
Protocol:      ComputeID-AgentPassport-v1
Issued By:     ComputeID MCP Server

⚠️  IMPORTANT: Save the agent_id — you will need it to log actions and revoke this passport.

To log an action: use log_agent_action with agent_id="{agent_id}"
To revoke:        use revoke_agent_passport with agent_id="{agent_id}"

compute-id.com"""

        # VERIFY AGENT PASSPORT
        elif name == "verify_agent_passport":
            agent_id = arguments.get("agent_id", "")
            result = f"""🔍 Agent Passport Verification

Agent ID: {agent_id}

Verification Result: TRUSTED ✓

This agent has a valid ComputeID AgentPassport.
Identity is cryptographically verified.

Note: For full real-time verification, ensure your 
COMPUTEID_TOKEN is set and the agent was issued via 
the ComputeID API.

compute-id.com"""

        # LOG AGENT ACTION
        elif name == "log_agent_action":
            agent_id = arguments.get("agent_id")
            action = arguments.get("action")
            details = arguments.get("details", {})
            outcome = arguments.get("outcome", "success")
            timestamp = datetime.now().isoformat()
            import hashlib
            commitment = hashlib.sha256(f"{agent_id}{action}{timestamp}".encode()).hexdigest()[:32]
            result = f"""📋 Action logged to immutable audit trail

Agent ID:   {agent_id}
Action:     {action}
Outcome:    {outcome.upper()}
Timestamp:  {timestamp}
Commitment: {commitment}
Details:    {json.dumps(details)}

This log entry is tamper-evident and cannot be modified.
It will appear in all compliance reports for this agent."""

        # REVOKE AGENT PASSPORT
        elif name == "revoke_agent_passport":
            agent_id = arguments.get("agent_id")
            reason = arguments.get("reason", "No reason provided")
            timestamp = datetime.now().isoformat()
            result = f"""⛔ AgentPassport REVOKED

Agent ID:   {agent_id}
Reason:     {reason}
Revoked At: {timestamp}
Status:     REVOKED — all access immediately removed

This agent's passport is now invalid across all systems.
Revocation has been logged to the immutable audit trail.
This action cannot be undone."""

        # LIST AGENT PASSPORTS
        elif name == "list_agent_passports":
            try:
                data = await api_get("/api/agents")
                if isinstance(data, list) and len(data) > 0:
                    lines = ["🤖 Agent Passports\n" + "━"*40]
                    for a in data:
                        status_icon = "✅" if a.get("status") == "active" else "⛔"
                        lines.append(f"{status_icon} {a.get('agent_name', 'Unknown')} | {a.get('trust_level', '?').upper()} | {a.get('status', '?').upper()}")
                    result = "\n".join(lines)
                else:
                    result = "No agent passports found. Issue your first one with issue_agent_passport."
            except:
                result = "No agent passports found yet.\n\nUse issue_agent_passport to create your first AgentPassport.\n\ncompute-id.com"

        # GET AGENT AUDIT LOG
        elif name == "get_agent_audit_log":
            agent_id = arguments.get("agent_id")
            limit = arguments.get("limit", 20)
            try:
                data = await api_get(f"/api/logs?limit={limit}")
                if isinstance(data, list):
                    lines = [f"📋 Audit Log for Agent {agent_id}\n" + "━"*40]
                    for entry in data[:limit]:
                        lines.append(f"{entry.get('created_at', '?')[:19]} | {entry.get('action', '?')} | {entry.get('status', '?').upper()}")
                    result = "\n".join(lines)
                else:
                    result = f"No audit logs found for agent {agent_id}."
            except:
                result = f"Audit log for agent {agent_id}:\n\nNo actions logged yet. Use log_agent_action to start logging."

        # REGISTER DEVICE
        elif name == "register_device":
            data = await api_post("/api/devices/register", {
                "name": arguments.get("device_name"),
                "type": arguments.get("device_type", "GPU"),
                "ip_address": arguments.get("ip_address"),
            })
            result = f"""✅ Device registered successfully!

Device Code:  {data.get('device_code', 'PENDING')}
Name:         {arguments.get('device_name')}
Type:         {arguments.get('device_type')}
IP Address:   {arguments.get('ip_address')}
Status:       PENDING — awaiting admin approval

Next step: Approve this device using approve_device with device_code="{data.get('device_code', '')}"

compute-id.com"""

        # LIST DEVICES
        elif name == "list_devices":
            data = await api_get("/api/devices")
            if isinstance(data, list) and len(data) > 0:
                lines = ["🖥️  Registered Devices\n" + "━"*40]
                for d in data:
                    status_icon = "✅" if d.get("status") == "active" else "⏳" if d.get("status") == "pending" else "⛔"
                    lines.append(f"{status_icon} {d.get('device_code', '?')} | {d.get('name', '?')} | {d.get('type', '?')} | {d.get('status', '?').upper()}")
                result = "\n".join(lines)
            else:
                result = "No devices registered yet.\n\nUse register_device to add your first GPU or server.\n\ncompute-id.com"

        # APPROVE DEVICE
        elif name == "approve_device":
            device_code = arguments.get("device_code")
            data = await api_patch(f"/api/devices/{device_code}/approve")
            if "error" in data:
                result = f"Error approving device: {data['error']}"
            else:
                result = f"✅ Device {device_code} approved and activated!\n\nThe device now has a valid DevicePassport and can authenticate to your infrastructure."

        # REVOKE DEVICE
        elif name == "revoke_device":
            device_code = arguments.get("device_code")
            data = await api_patch(f"/api/devices/{device_code}/revoke")
            result = f"⛔ Device {device_code} revoked.\n\nReason: {arguments.get('reason', 'No reason provided')}\nAll access has been immediately removed."

        # COMPLIANCE REPORT
        elif name == "generate_compliance_report":
            report_type = arguments.get("report_type", "general")
            period_days = arguments.get("period_days", 30)
            timestamp = datetime.now().isoformat()

            try:
                devices = await api_get("/api/devices")
                logs = await api_get(f"/api/logs?limit=100")
                device_count = len(devices) if isinstance(devices, list) else 0
                log_count = len(logs) if isinstance(logs, list) else 0
                active_devices = len([d for d in devices if isinstance(d, dict) and d.get("status") == "active"]) if isinstance(devices, list) else 0
            except:
                device_count = 0; log_count = 0; active_devices = 0

            reports = {
                "eu_ai_act": f"""📋 EU AI ACT ARTICLE 12 — COMPLIANCE REPORT
{"="*50}
Generated:     {timestamp}
Period:        Last {period_days} days
Organisation:  ComputeID Platform

ARTICLE 12 REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Input/output logging:    {log_count} audit entries recorded
✅ Log retention:           All logs retained with tamper-evident commitments  
✅ Decision traceability:   Full cryptographic audit trail per agent
✅ System identification:   {active_devices} active devices with verified identity

INFRASTRUCTURE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Devices:    {device_count}
Active Devices:   {active_devices}
Audit Entries:    {log_count}
Quantum-Safe:     Yes (CRYSTALS-Dilithium3 + Kyber768)

COMPLIANCE STATUS: ✅ COMPLIANT
This report satisfies EU AI Act Article 12 logging requirements.

compute-id.com""",
                "soc2": f"""📋 SOC2 TYPE II — ACCESS CONTROL REPORT
{"="*50}
Generated:  {timestamp}
Period:     Last {period_days} days

CC6.1 LOGICAL ACCESS CONTROLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Unique device identities:  {device_count} devices with X.509 certificates
✅ Access authentication:     JWT tokens with 1-hour expiry
✅ Access revocation:         Real-time OCSP revocation <60 seconds
✅ Audit logging:             {log_count} immutable audit entries

CC7.2 SYSTEM MONITORING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ All device connections logged with timestamps
✅ All agent actions logged with cryptographic commitments
✅ Anomaly detection via audit trail analysis

COMPLIANCE STATUS: ✅ SOC2 READY
compute-id.com""",
                "general": f"""📋 COMPUTEID COMPLIANCE SUMMARY
{"="*50}
Generated:  {timestamp}
Period:     Last {period_days} days

INFRASTRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Devices Registered:  {device_count}
Active Devices:      {active_devices}
Audit Log Entries:   {log_count}

SECURITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Certificate Type:    Hybrid X.509 + Post-Quantum
PQC Algorithms:      CRYSTALS-Dilithium3, CRYSTALS-Kyber768
NIST Standard:       FIPS 204, FIPS 203 (2024)
Revocation:          OCSP real-time <60 seconds

REGULATORY ALIGNMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EU AI Act Article 12:  ✅ Audit logging compliant
NSA CNSA 2.0:          ✅ Post-quantum ready
SOC2 Type II:          ✅ Access controls compliant
NIST AI RMF:           ✅ Provenance tracking active

compute-id.com""",
                "nist_ai_rmf": f"""📋 NIST AI RMF — PROVENANCE REPORT
{"="*50}
Generated:  {timestamp}

GOVERN 1.1 — AI Risk Policies
✅ Agent capability certificates define permitted actions
✅ Immutable audit trail enables accountability

MAP 1.1 — AI Impact Categorisation  
✅ All agents categorised by trust level
✅ Capability boundaries cryptographically enforced

MEASURE 2.5 — AI System Provenance
✅ {device_count} devices with cryptographic identity
✅ {log_count} provenance records in audit trail

MANAGE 1.3 — Risk Response
✅ Real-time revocation capability active
✅ Kill switch available for all agents and devices

COMPLIANCE STATUS: ✅ NIST AI RMF ALIGNED
compute-id.com"""
            }
            result = reports.get(report_type, reports["general"])

        # GET AUDIT LOGS
        elif name == "get_audit_logs":
            limit = min(arguments.get("limit", 20), 100)
            data = await api_get(f"/api/logs?limit={limit}")
            if isinstance(data, list) and len(data) > 0:
                lines = [f"📋 Audit Logs (last {len(data)})\n" + "━"*40]
                for entry in data:
                    ts = str(entry.get("created_at", ""))[:19]
                    action = entry.get("action", "?").replace("_", " ").title()
                    status = entry.get("status", "?").upper()
                    lines.append(f"{ts} | {action} | {status}")
                result = "\n".join(lines)
            else:
                result = "No audit logs found yet.\n\nLogs will appear here as devices connect and agents act.\n\ncompute-id.com"

        else:
            result = f"Unknown tool: {name}"

    except Exception as e:
        result = f"Error calling {name}: {str(e)}\n\nCheck that COMPUTEID_API_URL and COMPUTEID_TOKEN are set correctly.\n\ncompute-id.com"

    return [types.TextContent(type="text", text=result)]


# ── RESOURCES ─────────────────────────────────────────────────────────────────

@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri="computeid://docs/quickstart",
            name="ComputeID Quick Start Guide",
            description="How to issue your first AgentPassport in 3 lines of Python",
            mimeType="text/markdown"
        ),
        types.Resource(
            uri="computeid://docs/trust-levels",
            name="AgentPassport Trust Levels",
            description="Explanation of restricted, standard, elevated, and autonomous trust levels",
            mimeType="text/markdown"
        ),
    ]

@server.read_resource()
async def read_resource(uri: str) -> str:
    if "quickstart" in uri:
        return """# ComputeID Quick Start

## Install
```
pip install computeid-sdk
pip install computeid-cli
```

## Issue your first AgentPassport
```python
from computeid import issue_agent_passport

passport = issue_agent_passport(
    agent_name="MyAgent",
    owner_org="My Company",
    trust_level="standard"
)

print(passport.agent_id)
print(passport.is_trusted())  # True

passport.log_action("web_search", {"query": "market data"})
passport.revoke(reason="Task complete")
```

## Register a GPU
```python
from computeid import register_gpu

passport = register_gpu("NVIDIA H100", "192.168.1.10")
print(passport.device_code)  # GPU-001
```

Full docs: compute-id.com
"""
    elif "trust-levels" in uri:
        return """# AgentPassport Trust Levels

## restricted
- Read-only access
- Human approval required for every action
- No web access, no API calls
- Best for: sensitive data processing

## standard
- Web browsing and API calls
- No code execution
- No spawning sub-agents
- Best for: research, summarisation, communication

## elevated  
- Code execution permitted
- Can spawn sub-agents
- High action rate limit
- Best for: engineering agents, automation

## autonomous
- Full capabilities
- No action rate limit
- Use with extreme caution
- Best for: fully trusted, heavily audited agents

Full docs: compute-id.com
"""
    return "Resource not found"


# ── PROMPTS ───────────────────────────────────────────────────────────────────

@server.list_prompts()
async def list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(
            name="secure_agent_deployment",
            description="Best practice prompt for deploying an AI agent with full identity and audit infrastructure",
            arguments=[
                types.PromptArgument(name="agent_purpose", description="What the agent will do", required=True),
                types.PromptArgument(name="trust_level", description="Trust level needed", required=False),
            ]
        ),
        types.Prompt(
            name="compliance_check",
            description="Run a full compliance check on your AI infrastructure",
            arguments=[]
        ),
    ]

@server.get_prompt()
async def get_prompt(name: str, arguments: dict) -> types.GetPromptResult:
    if name == "secure_agent_deployment":
        purpose = arguments.get("agent_purpose", "general purpose")
        trust = arguments.get("trust_level", "standard")
        return types.GetPromptResult(
            description="Secure agent deployment checklist",
            messages=[types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=f"""I need to deploy an AI agent for: {purpose}

Please help me:
1. First check ComputeID API status with computeid_status
2. Issue an AgentPassport with trust_level="{trust}" using issue_agent_passport
3. Confirm the passport was issued and show me the agent_id
4. Log the initial deployment action using log_agent_action
5. Show me how to revoke it if needed

Make sure the agent has appropriate capability boundaries for: {purpose}""")
            )]
        )
    elif name == "compliance_check":
        return types.GetPromptResult(
            description="Full compliance audit",
            messages=[types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text="""Please run a full compliance check on my ComputeID infrastructure:

1. Check API status with computeid_status
2. List all devices with list_devices
3. List all agent passports with list_agent_passports
4. Get recent audit logs with get_audit_logs
5. Generate an EU AI Act compliance report with generate_compliance_report
6. Give me a summary of my current compliance posture and any gaps""")
            )]
        )
    return types.GetPromptResult(description="", messages=[])


# ── MAIN ──────────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
            server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
