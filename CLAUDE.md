# PolicyPulse MCP — Claude Code Context

## What This Project Is

PolicyPulse MCP is an open-source Python MCP (Model Context Protocol) server that
unifies OPA/Gatekeeper, Kyverno, and Azure Policy behind one compliance-aware
interface. It is the **first MCP server** to combine all three engines.

Built by Ravi Pegata — Principal Cloud Platform & AI Platform Engineer.

---

## Repository Structure

```
policy-pulse-mcp/
├── CLAUDE.md                          ← you are here
├── README.md                          ← public-facing docs + Medium article seed
├── pyproject.toml                     ← packaging, deps, entry point
├── Makefile                           ← all dev commands (make test, make demo-server, etc.)
├── Dockerfile                         ← in-cluster production deployment
├── .github/workflows/ci.yml           ← GitHub Actions: test on push, publish on release tag
│
├── src/policy_pulse_mcp/
│   ├── __init__.py                    ← version = "0.1.0"
│   ├── models.py                      ← Violation, Policy, FrameworkRef, Severity, Engine
│   ├── checks.py                      ← pure pod-spec predicates (no imports from this pkg)
│   ├── frameworks.py                  ← control catalog: 9 controls × CIS/PCI-DSS/NIST/SOC2
│   ├── evaluator.py                   ← static manifest gate (no cluster needed)
│   ├── intelligence.py                ← risk summary, prioritize, explain
│   ├── cache.py                       ← dependency-free TTL cache decorator
│   ├── cluster.py                     ← auto-detect in-cluster vs kubeconfig
│   ├── demo.py                        ← mock adapters for POLICYPULSE_DEMO=true mode
│   ├── server.py                      ← FastMCP server, 7 MCP tools
│   └── adapters/
│       ├── base.py                    ← EngineAdapter protocol
│       ├── gatekeeper.py              ← reads ConstraintTemplates + status.violations
│       ├── kyverno.py                 ← reads ClusterPolicies + PolicyReports
│       └── azure_policy.py           ← PolicyInsightsClient + DefaultAzureCredential
│
├── tests/
│   ├── test_core.py                   ← 47 tests: checks, catalog, evaluator, intelligence
│   └── test_integration.py            ← 40 tests: all 7 MCP tools via demo mode
│
├── demo-cluster/
│   ├── gatekeeper-policies.yaml       ← real ConstraintTemplates + Constraints
│   ├── kyverno-policies.yaml          ← real ClusterPolicies
│   └── non-compliant-workloads.yaml   ← intentionally broken workloads for testing
│
└── scripts/
    └── setup-demo-cluster.sh          ← Kind + Gatekeeper + Kyverno + workloads
```

---

## Architecture (the design thesis)

Three concentric layers. The key insight: **one control catalog powers both
runtime violation enrichment AND the pre-deployment static gate.**

```
MCP Client (Claude, Cursor, CI agent)
        ↓ MCP protocol (stdio)
┌─────────────────────────────┐
│   Intelligence Layer        │  build_risk_summary · explain · prioritize
│   (pure Python, no I/O)     │
├─────────────────────────────┤
│   Normalized Schema         │  Violation · Policy · FrameworkRef · Severity
├──────┬──────────┬───────────┤
│ Gate │ Kyverno  │  Azure    │  Each adapter translates native engine output
│keeper│ Adapter  │  Policy   │  into Violation objects. Nothing downstream
│      │          │  Adapter  │  touches raw engine APIs.
└──────┴──────────┴───────────┘
              ↕
     Control Catalog (frameworks.py)
     9 controls × frameworks mappings
     + manifest_check predicates
     = one source of truth for both
       runtime enrichment (live violations)
       and static gate (pre-deploy CI)
```

---

## The 7 MCP Tools

| Tool | Description |
|---|---|
| `cluster_status` | Which engines are connected; shows DEMO mode banner |
| `list_policies` | All policies across engines; filter by engine |
| `get_violations` | All violations, framework-enriched, severity-ranked; filter by namespace/engine/min_severity |
| `get_compliance_risk_summary` | **The headline tool** — prioritized cross-engine risk summary |
| `explain_violation` | Plain English + framework mapping + remediation for one violation |
| `check_manifest_compliance` | Pre-deploy static gate — no cluster required |
| `list_controls` | The full control catalog |

---

## Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `POLICYPULSE_DEMO` | No | false | `true` = mock data, no cluster needed |
| `AZURE_SUBSCRIPTION_ID` | For Azure engine | — | Subscription to query |
| `KUBECONFIG` | For k8s engines | `~/.kube/config` | Override kubeconfig path |
| `POLICYPULSE_LOG` | No | INFO | Log level (DEBUG for troubleshooting) |

---

## Development Commands

```bash
# Install (dev mode with all deps)
pip install -e ".[dev]"
pip install -e ".[all,dev]"    # includes azure + kubernetes SDKs

# Test
make test                       # all 87 tests
make test-core                  # 47 core tests (pure logic, offline)
make test-integration           # 40 integration tests (demo mode)
make test-cov                   # with coverage report

# Run
make demo-server                # POLICYPULSE_DEMO=true, no cluster needed
make live-server                # real cluster + Azure

# Local k8s cluster
make cluster-up                 # Kind + Gatekeeper + Kyverno + non-compliant workloads
make cluster-down               # delete the Kind cluster

# Code quality
make lint                       # ruff check
make fmt                        # ruff format

# Package
make build                      # builds dist/ wheel + sdist
make publish-test               # upload to TestPyPI
make publish                    # upload to PyPI
```

---

## Current Status (v0.1.0)

### ✅ Done
- [x] Gatekeeper adapter (reads ConstraintTemplates + audit violations)
- [x] Kyverno adapter (reads ClusterPolicies + PolicyReports)
- [x] Azure Policy adapter (Policy Insights API, DefaultAzureCredential)
- [x] Control catalog: 9 controls × CIS Kubernetes / PCI-DSS / NIST 800-53 / SOC 2
- [x] Cross-engine risk summary with regulatory escalation
- [x] Plain-language violation explanation
- [x] Pre-deployment static manifest gate (offline, no cluster)
- [x] TTL caching (5–10 min, mirrors Azure's ~24h refresh cycle)
- [x] Auto-detect in-cluster vs kubeconfig connection
- [x] Demo mode (POLICYPULSE_DEMO=true)
- [x] 87 tests, fully offline (0.61s)
- [x] Dockerfile
- [x] GitHub Actions CI + PyPI publish on release

### 🔲 v0.2 (next)
- [ ] `get_violation_history` — compliance drift over time
- [ ] `check_resource_compliance` — point query for specific Azure resource
- [ ] Multi-subscription Azure support
- [ ] Helm chart for in-cluster deployment
- [ ] PyPI publish (`pip install policy-pulse-mcp`)

### 🔲 v0.3
- [ ] YAML-driven catalog extensions (no Python to add controls)
- [ ] `search_catalog` tool
- [ ] GitHub Actions pre-deploy gate example

### 🔲 v1.0 (Remediation Layer)
- [ ] `generate_remediation_manifest`
- [ ] `create_exemption_request`
- [ ] `trigger_azure_remediation_task`

---

## Key Design Decisions (understand these before changing anything)

### 1. Normalization-first
Adapters ONLY produce `Violation` / `Policy` objects. They never pass raw dicts
upstream. This is what makes the 87 offline tests possible — the intelligence
layer has zero knowledge of engine APIs.

### 2. Lazy imports in adapters
`kubernetes` and `azure-*` packages are imported inside methods, never at module
level. This means the package imports cleanly with only `mcp` installed.
Breaking this will break offline tests and the evaluator in CI.

### 3. The control catalog is a single source of truth
`frameworks.py` CATALOG powers:
  (a) `frameworks.enrich()` — keyword matching live violations → framework refs
  (b) `evaluator.gate()` — manifest_check predicates for static analysis
Never add framework mappings in two places. Always add to CATALOG.

### 4. Demo mode swaps at import time
`server.py` calls `_build_adapters()` at module load. Setting
`POLICYPULSE_DEMO=true` BEFORE importing server.py switches to MockAdapters.
The integration tests do this with `os.environ["POLICYPULSE_DEMO"] = "true"`
before the import. Do not reorder that.

### 5. TTL cache is instance-bound
The `@ttl_cache` decorator stores cache state in the closure. Each adapter
instance has its own cache. If you create a new adapter instance (e.g. in tests),
you get a fresh cache — which is correct behaviour.

---

## Adding a New Control to the Catalog

Edit `src/policy_pulse_mcp/frameworks.py`:

```python
ControlRule(
    id="your-control-id",           # kebab-case, stable identifier
    title="Human readable title",
    severity=Severity.HIGH,
    frameworks=(
        _f("CIS Kubernetes", "5.x.x", "Control title from benchmark"),
        _f("PCI-DSS", "x.x", "Requirement title"),
    ),
    remediation="Plain English: what to change and where.",
    keywords=("keyword1", "keyword2"),    # lowercased substrings from policy names/messages
    manifest_check=checks.your_function, # add predicate to checks.py first
),
```

Then add the predicate in `checks.py`:
```python
def your_function(spec: Spec) -> bool:
    # returns True when the pod spec VIOLATES the control
    ...
```

Then add tests in `tests/test_core.py` under `TestChecks` and `TestFrameworks`.

---

## Adding a New Engine Adapter

1. Create `src/policy_pulse_mcp/adapters/your_engine.py`
2. Implement `is_available()`, `list_policies()`, `get_violations()` — return
   `list[Policy]` and `list[Violation]` respectively
3. Add to `adapters/__init__.py`
4. Add to `_build_adapters()` in `server.py`
5. Add to `Engine` enum in `models.py`
6. Add mock data in `demo.py` (`MOCK_VIOLATIONS` and `MOCK_POLICIES`)
7. Add `intelligence.engine_label()` entry

---

## MCP Client Configuration (Claude Desktop)

```json
{
  "mcpServers": {
    "policy-pulse": {
      "command": "policy-pulse-mcp",
      "env": {
        "POLICYPULSE_DEMO": "true",
        "AZURE_SUBSCRIPTION_ID": "your-subscription-id"
      }
    }
  }
}
```

Config file location:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

---

## PyPI Publish Checklist (before `make publish`)

- [ ] Bump version in `pyproject.toml` AND `src/policy_pulse_mcp/__init__.py`
- [ ] Update CHANGELOG or README roadmap checkboxes
- [ ] All tests passing: `make test`
- [ ] Lint clean: `make lint`
- [ ] Build succeeds: `make build`
- [ ] Test on TestPyPI first: `make publish-test`
- [ ] Create GitHub Release with tag `v0.x.x` (CI triggers publish automatically)

---

## GitHub Setup (one-time)

```bash
git init
git add .
git commit -m "feat: initial release v0.1.0"

# Create repo at github.com/lumiodigital/policy-pulse-mcp first, then:
git remote add origin https://github.com/raviteja-pegata/policy-pulse-mcp.git
git branch -M main
git push -u origin main
```

For PyPI publish via GitHub Actions, create a PyPI API token and add it as
`PYPI_API_TOKEN` in the repo's Settings → Secrets → Actions.
(The CI workflow uses OIDC trusted publishing — no secret needed if you configure
PyPI trusted publisher for the repo.)
