"""MCP server for Aegis — Agentic Intrusion Detection System.

Exposes analyze, generate, and rules commands as MCP tools.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from .config import AegisConfig
from .llm import HybridLLMClient
from .capture.flows import FlowTracker
from .capture.reader import PcapReader
from .detection.cadence import CadenceAnalyzer, CadenceClassification
from .detection.rules import RuleEngine
from .detection.analyzer import ThreatAnalyzer
from .alerting.pipeline import AlertPipeline

server = Server("aegis")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="analyze",
            description="Analyze a PCAP file for agentic traffic patterns using cadence analysis, rule evaluation, and optional LLM threat analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {
                        "type": "string",
                        "description": "Path to PCAP file to analyze.",
                    },
                    "skip_llm": {
                        "type": "boolean",
                        "description": "Skip LLM threat analysis (cadence + rules only).",
                        "default": False,
                    },
                },
                "required": ["pcap_path"],
            },
        ),
        types.Tool(
            name="generate",
            description="Generate synthetic PCAP for testing cadence detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "enum": ["agent", "human", "mixed"],
                        "description": "Traffic pattern to simulate.",
                        "default": "agent",
                    },
                    "output": {
                        "type": "string",
                        "description": "Output PCAP file path.",
                        "default": "./aegis-data/test.pcap",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="rules",
            description="List all loaded Aegis detection rules.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "analyze":
        result = await asyncio.to_thread(_run_analyze, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "generate":
        result = await asyncio.to_thread(_run_generate, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "rules":
        result = await asyncio.to_thread(_run_rules, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    raise ValueError(f"Unknown tool: {name}")


def _run_analyze(arguments: dict) -> dict:
    pcap_file = Path(arguments["pcap_path"]).resolve()
    if not pcap_file.exists():
        return {"error": f"PCAP file not found: {pcap_file}"}

    cfg = AegisConfig()
    cfg.ensure_dirs()
    skip_llm = arguments.get("skip_llm", False)

    analysis_start = time.time()

    # Phase 1: Extract flows
    tracker = FlowTracker(flow_timeout=cfg.capture.flow_timeout)
    reader = PcapReader(tracker)
    flows = reader.read_pcap(pcap_file)

    if not flows:
        return {"status": "completed", "message": "No flows found in PCAP.", "flows": 0}

    total_pkts = sum(f.packet_count for f in flows)

    # Phase 2: Cadence analysis
    cadence_analyzer = CadenceAnalyzer(cfg.cadence)
    cadence_results = cadence_analyzer.analyze_flows(flows)

    cadence_summary: dict[str, int] = {}
    for r in cadence_results:
        key = r.classification.value
        cadence_summary[key] = cadence_summary.get(key, 0) + 1

    suspicious = [
        r
        for r in cadence_results
        if r.classification
        in (CadenceClassification.AGENT, CadenceClassification.MIXED)
    ]

    # Phase 3: Rule evaluation
    engine = RuleEngine(
        rules_dir=cfg.rules.rules_dir, builtin_enabled=cfg.rules.builtin_enabled
    )
    rule_matches = engine.evaluate_all(cadence_results, flows)

    rule_match_data = [
        {
            "rule_name": m.rule.name,
            "severity": m.severity,
            "flow_key": m.flow_key[:60],
            "conditions": m.matched_conditions[:3],
        }
        for m in rule_matches
    ]

    # Phase 4: LLM threat analysis
    threat_data = None
    if not skip_llm and suspicious:
        llm = HybridLLMClient(cfg.llm)
        if llm.is_available():
            analyzer = ThreatAnalyzer(cfg, llm)
            verdict = analyzer.analyze(cadence_results, flows)
            threat_data = {
                "classification": verdict.classification,
                "severity": verdict.severity,
                "confidence": verdict.confidence,
                "summary": verdict.summary,
                "recommended_actions": verdict.recommended_actions[:5],
            }
            llm.close()

    # Phase 5: Alerts
    pipeline = AlertPipeline(cfg.alerts)
    alerts = pipeline.process(
        cadence_results, rule_matches, verdict if threat_data else None
    )

    analysis_time = time.time() - analysis_start

    return {
        "status": "completed",
        "flows_extracted": len(flows),
        "total_packets": total_pkts,
        "cadence_classification": cadence_summary,
        "suspicious_flows": len(suspicious),
        "rule_matches": rule_match_data,
        "threat_verdict": threat_data,
        "alerts_generated": len(alerts),
        "analysis_time_seconds": round(analysis_time, 1),
    }


def _run_generate(arguments: dict) -> dict:
    pattern = arguments.get("pattern", "agent")
    output_path = Path(arguments.get("output", "./aegis-data/test.pcap"))

    try:
        result = PcapReader.generate_test_pcap(output_path, pattern=pattern)
        return {
            "status": "completed",
            "pattern": pattern,
            "output_path": str(result),
        }
    except RuntimeError as e:
        return {"error": str(e)}


def _run_rules(arguments: dict) -> dict:
    cfg = AegisConfig()
    engine = RuleEngine(
        rules_dir=cfg.rules.rules_dir, builtin_enabled=cfg.rules.builtin_enabled
    )

    rules_list = [
        {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "tags": rule.tags,
            "enabled": rule.enabled,
        }
        for rule in engine.rules
    ]

    return {"rules": rules_list, "total": len(rules_list)}


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
