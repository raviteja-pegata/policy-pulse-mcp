# PolicyPulse MCP

**The first MCP server to unify OPA/Gatekeeper, Kyverno, and Azure Policy behind one compliance-aware interface.**

Built by Ravi Pegata (LUMIO LLC) — Principal Cloud Platform & AI Platform Engineer.

[![CI](https://github.com/lumiodigital/policy-pulse-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/lumiodigital/policy-pulse-mcp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

Modern Kubernetes environments often run two or three policy engines simultaneously:
- **OPA Gatekeeper** — admission control for on-prem and hybrid clusters
- **Kyverno** — policy-as-code for GKE, EKS, and AKS clusters
- **Azure Policy** — compliance scanning for AKS workloads in Azure

Each engine has its own API, its own violation format, and its own compliance framework mapping. Platform engineers must context-switch between three dashboards, two CLIs, and Azure Portal — just to answer: *"Are we compliant?"*

## The Solution

PolicyPulse MCP normalizes all three engines into a single MCP server with 7 tools. Ask Claude:

> *"What are my most critical policy violations across all engines?"*
> *"Check this deployment manifest before I push it."*
> *"Which Azure Policy findings map to PCI-DSS requirements?"*

## Architecture

```
MCP Client (Claude, Cursor, CI agent)
        ↓ MCP protocol (stdio)
┌─────────────────────────────┐
│   Intelligence Layer        │  build_risk_summary · explain · prioritize
├─────────────────────────────┤
│   Normalized Schema         │  Violation · Policy · FrameworkRef · Severity
├──────┬──────────┬───────────┤
│ Gate │ Kyverno  │  Azure    │
│keeper│ Adapter  │  Policy   │
└──────┴──────────┴───────────┘
              ↕
     Control Catalog (9 controls × CIS/PCI-DSS/NIST/SOC2)
     = single source of truth for runtime enrichment + static gate
```

## Quick Start

### Try it now (no cluster needed)

```bash
pip install policy-pulse-mcp

# Run in demo mode — mock violations, no cluster required
POLICYPULSE_DEMO=true policy-pulse-mcp
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "policy-pulse": {
      "command": "policy-pulse-mcp",
      "env": {
        "POLICYPULSE_DEMO": "true"
      }
    }
  }
}
```

Config file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

## The 7 MCP Tools

| Tool | Description |
|---|---|
| `cluster_status` | Which engines are connected; DEMO mode banner |
| `list_policies` | All policies across engines; filter by engine |
| `get_violations` | Violations enriched with framework refs; filter by namespace/engine/severity |
| `get_compliance_risk_summary` | **The headline tool** — cross-engine risk summary with regulatory impact |
| `explain_violation` | Plain English + framework mapping + remediation for one violation |
| `check_manifest_compliance` | Pre-deploy static gate — no cluster required |
| `list_controls` | The full 9-control catalog |

## Installation

```bash
# Core (MCP + demo mode)
pip install policy-pulse-mcp

# With Kubernetes engine support
pip install "policy-pulse-mcp[kubernetes]"

# With Azure Policy support
pip install "policy-pulse-mcp[azure]"

# Everything
pip install "policy-pulse-mcp[all]"
```

## Live Cluster Setup

```bash
# 1. Install with all engine adapters
pip install "policy-pulse-mcp[all]"

# 2. Start with real cluster + Azure
AZURE_SUBSCRIPTION_ID=your-sub-id policy-pulse-mcp

# Or try with a local Kind cluster
make cluster-up   # sets up Kind + Gatekeeper + Kyverno + demo workloads
make live-server
```

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `POLICYPULSE_DEMO` | `false` | `true` = mock data, no cluster needed |
| `AZURE_SUBSCRIPTION_ID` | — | Subscription to query for Azure Policy |
| `KUBECONFIG` | `~/.kube/config` | Override kubeconfig path |
| `POLICYPULSE_LOG` | `INFO` | Log level |

## Development

```bash
git clone https://github.com/lumiodigital/policy-pulse-mcp
cd policy-pulse-mcp
python -m venv .venv && source .venv/bin/activate
make install

make test          # 87 tests, fully offline (~0.6s)
make demo-server   # run locally in demo mode
make lint          # ruff check
```

## Extending the Catalog

Add a control in `frameworks.py`:

```python
ControlRule(
    id="your-control-id",
    title="Human readable title",
    severity=Severity.HIGH,
    frameworks=(
        _f("CIS Kubernetes", "5.x.x", "Control title"),
        _f("PCI-DSS", "x.x", "Requirement title"),
    ),
    remediation="Plain English: what to change.",
    keywords=("keyword1", "keyword2"),
    manifest_check=checks.your_function,
),
```

Then add the predicate to `checks.py` and tests to `tests/test_core.py`.

## Roadmap

### v0.2
- `get_violation_history` — compliance drift over time
- `check_resource_compliance` — point query for specific Azure resource
- Multi-subscription Azure support
- Helm chart

### v0.3
- YAML-driven catalog extensions
- `search_catalog` tool
- GitHub Actions pre-deploy gate example

### v1.0 — Remediation Layer
- `generate_remediation_manifest`
- `create_exemption_request`
- `trigger_azure_remediation_task`

## License

MIT — see [LICENSE](LICENSE).

---

*Built with [FastMCP](https://github.com/anthropics/mcp) · Powered by [Claude](https://claude.ai)*
