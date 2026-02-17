import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import AegisConfig

_ALERTS: list[dict] = []
_RULES: list[dict] = []
_ANALYSES: list[dict] = []


def create_app(config: AegisConfig | None = None) -> FastAPI:
    cfg = config or AegisConfig()

    app = FastAPI(
        title="Aegis",
        description="Behavioral IDS for Agentic Attacks",
        version="0.2.0b1",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def index() -> HTMLResponse:
    return HTMLResponse(_WEB_UI)


@router.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": "aegis", "version": "0.2.0b1"}


@router.get("/api/alerts")
def get_alerts(limit: int = 50) -> dict:
    return {"alerts": _ALERTS[-limit:], "count": len(_ALERTS)}


@router.get("/api/rules")
def get_rules() -> dict:
    return {"rules": _RULES, "count": len(_RULES)}


@router.get("/api/analyses")
def get_analyses() -> dict:
    return {"analyses": _ANALYSES, "count": len(_ANALYSES)}


@router.get("/api/stats")
def get_stats() -> dict:
    if not _ALERTS:
        return {
            "total_alerts": 0,
            "by_type": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    by_type = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for a in _ALERTS:
        atype = a.get("type", "unknown")
        by_type[atype] = by_type.get(atype, 0) + 1

        sev = a.get("severity", "low")
        if sev in by_severity:
            by_severity[sev] += 1

    return {
        "total_alerts": len(_ALERTS),
        "by_type": by_type,
        "by_severity": by_severity,
        "total_analyses": len(_ANALYSES),
    }


_WEB_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis — Behavioral IDS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a12;--surface:#12121f;--border:#1e1e35;--text:#e0e0f0;--dim:#666;--accent:#ef4444;--accent2:#dc2626;--danger:#ff4466;--warning:#ffaa00;--safe:#00cc66;--cyan:#00ccff}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
.container{max-width:1400px;margin:0 auto;padding:2rem}
header{text-align:center;margin-bottom:2rem}
header h1{font-size:3rem;background:linear-gradient(135deg,var(--accent),#fbbf24);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:800;letter-spacing:4px;animation:glow 2s ease-in-out infinite alternate}
@keyframes glow{from{filter:drop-shadow(0 0 10px rgba(239,68,68,0.3))}to{filter:drop-shadow(0 0 20px rgba(251,191,36,0.5))}}
header p{color:var(--dim);margin-top:0.5rem;font-size:1.1rem}
.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;text-align:center;transition:all 0.3s}
.stat-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.stat-card .value{font-size:2.5rem;font-weight:700}
.stat-card .label{color:var(--dim);font-size:0.85rem;text-transform:uppercase;letter-spacing:1px}
.stat-card.critical .value{color:var(--danger)}
.stat-card.high .value{color:#f97316}
.stat-card.medium .value{color:var(--warning)}
.tabs{display:flex;gap:0.5rem;margin-bottom:1.5rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem}
.tab{padding:0.5rem 1rem;background:transparent;border:none;color:var(--dim);cursor:pointer;border-radius:8px 8px 0 0;transition:all 0.2s}
.tab:hover{color:var(--text)}
.tab.active{background:var(--surface);color:var(--accent)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
.card h2{color:var(--accent);margin-bottom:1rem;font-size:1.2rem}
.alerts-list{max-height:500px;overflow-y:auto}
.alert{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:0.8rem;border-left:4px solid var(--border)}
.alert.critical{border-left-color:var(--danger)}
.alert.high{border-left-color:#f97316}
.alert.medium{border-left-color:var(--warning)}
.alert.low{border-left-color:var(--cyan)}
.alert .header{display:flex;justify-content:space-between;align-items:center}
.alert .type{font-weight:600;color:var(--text)}
.alert .severity{font-size:0.75rem;padding:0.2rem 0.5rem;border-radius:4px;font-weight:600}
.alert .severity.critical{background:rgba(255,68,102,0.2);color:var(--danger)}
.alert .severity.high{background:rgba(249,115,22,0.2);color:#f97316}
.alert .severity.medium{background:rgba(255,170,0,0.2);color:var(--warning)}
.alert .severity.low{background:rgba(0,204,255,0.2);color:var(--cyan)}
.alert .detail{color:var(--dim);font-size:0.85rem;margin-top:0.5rem}
.alert .time{color:var(--dim);font-size:0.75rem;margin-top:0.3rem}
.rule-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:0.5rem}
.rule-card .name{font-weight:600;color:var(--accent)}
.rule-card .desc{color:var(--dim);font-size:0.85rem;margin-top:0.3rem}
.rule-card .meta{font-size:0.75rem;color:var(--dim);margin-top:0.5rem}
.hidden{display:none}
.type-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:0.8rem}
.type-card{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}
.type-card .type{font-weight:600;color:var(--accent)}
.type-card .count{font-size:1.5rem;font-weight:700}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>AEGIS</h1>
        <p>Behavioral IDS for Agentic Attacks</p>
    </header>

    <div class="dashboard">
        <div class="stat-card">
            <div class="value" id="totalAlerts">0</div>
            <div class="label">Total Alerts</div>
        </div>
        <div class="stat-card critical">
            <div class="value" id="criticalCount">0</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="value" id="highCount">0</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="value" id="analysesCount">0</div>
            <div class="label">Analyses</div>
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" data-tab="alerts">Alerts</button>
        <button class="tab" data-tab="rules">Detection Rules</button>
        <button class="tab" data-tab="analyses">Analyses</button>
        <button class="tab" data-tab="types">By Type</button>
    </div>

    <div id="tab-alerts" class="tab-content">
        <div class="card">
            <h2>Recent Alerts</h2>
            <div class="alerts-list" id="alertsList">
                <p style="color:var(--dim)">No alerts detected</p>
            </div>
        </div>
    </div>

    <div id="tab-rules" class="tab-content hidden">
        <div class="card">
            <h2>Detection Rules</h2>
            <div class="alerts-list" id="rulesList">
                <p style="color:var(--dim)">Loading rules...</p>
            </div>
        </div>
    </div>

    <div id="tab-analyses" class="tab-content hidden">
        <div class="card">
            <h2>Analysis History</h2>
            <div class="alerts-list" id="analysesList">
                <p style="color:var(--dim)">No analyses yet</p>
            </div>
        </div>
    </div>

    <div id="tab-types" class="tab-content hidden">
        <div class="card">
            <h2>Alerts by Type</h2>
            <div class="type-grid" id="typeGrid">
                <p style="color:var(--dim)">No data</p>
            </div>
        </div>
    </div>
</div>

<script>
const API = '';

async function loadStats() {
    try {
        const d = await fetch(API + '/api/stats').then(r => r.json());
        document.getElementById('totalAlerts').textContent = d.total_alerts;
        document.getElementById('criticalCount').textContent = d.by_severity.critical;
        document.getElementById('highCount').textContent = d.by_severity.high;
        document.getElementById('analysesCount').textContent = d.total_analyses;
        
        const types = d.by_type;
        const grid = document.getElementById('typeGrid');
        if (Object.keys(types).length) {
            grid.innerHTML = Object.entries(types).map(([type, count]) => `
                <div class="type-card">
                    <div class="type">${type}</div>
                    <div class="count">${count}</div>
                </div>
            `).join('');
        }
    } catch(e) {
        console.error(e);
    }
}

async function loadAlerts() {
    try {
        const d = await fetch(API + '/api/alerts?limit=20').then(r => r.json());
        const list = document.getElementById('alertsList');
        if (!d.alerts.length) {
            list.innerHTML = '<p style="color:var(--dim)">No alerts detected</p>';
            return;
        }
        list.innerHTML = d.alerts.map(a => `
            <div class="alert ${a.severity || 'low'}">
                <div class="header">
                    <span class="type">${a.type || 'Unknown Alert'}</span>
                    <span class="severity ${a.severity || 'low'}">${(a.severity || 'low').toUpperCase()}</span>
                </div>
                <div class="detail">${a.description || ''}</div>
                <div class="time">${a.timestamp || ''}</div>
            </div>
        `).join('');
    } catch(e) {
        console.error(e);
    }
}

async function loadRules() {
    try {
        const d = await fetch(API + '/api/rules').then(r => r.json());
        const list = document.getElementById('rulesList');
        if (!d.rules.length) {
            list.innerHTML = '<p style="color:var(--dim)">No rules loaded</p>';
            return;
        }
        list.innerHTML = d.rules.map(r => `
            <div class="rule-card">
                <div class="name">${r.name}</div>
                <div class="desc">${r.description || ''}</div>
                <div class="meta">Severity: ${r.severity || 'low'} | Type: ${r.type || 'unknown'}</div>
            </div>
        `).join('');
    } catch(e) {
        console.error(e);
    }
}

async function loadAnalyses() {
    try {
        const d = await fetch(API + '/api/analyses').then(r => r.json());
        const list = document.getElementById('analysesList');
        if (!d.analyses.length) {
            list.innerHTML = '<p style="color:var(--dim)">No analyses yet</p>';
            return;
        }
        list.innerHTML = d.analyses.slice().reverse().map(a => `
            <div class="alert">
                <div class="header">
                    <span class="type">${a.target || 'Unknown'}</span>
                    <span class="severity low">${a.status || 'pending'}</span>
                </div>
                <div class="time">${a.timestamp || ''}</div>
            </div>
        `).join('');
    } catch(e) {
        console.error(e);
    }
}

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
    });
});

loadStats();
loadAlerts();
loadRules();
loadAnalyses();
setInterval(() => { loadStats(); loadAlerts(); }, 5000);
</script>
</body>
</html>"""
