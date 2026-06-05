# PolicyPulse MCP

**One MCP server. Three policy engines. Zero context-switching.**

PolicyPulse unifies OPA/Gatekeeper, Kyverno, and Azure Policy behind a single interface — so you can ask your AI assistant about your real compliance posture in plain English, from any MCP-compatible client.

[![CI](https://github.com/raviteja-pegata/policy-pulse-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/raviteja-pegata/policy-pulse-mcp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

Modern Kubernetes environments run multiple policy engines simultaneously:

- **OPA Gatekeeper** — admission control, on-prem and hybrid
- **Kyverno** — policy-as-code for AKS, EKS, and GKE
- **Azure Policy** — compliance scanning across your entire Azure subscription

Each engine has its own API, its own violation format, and its own compliance framework mapping. Platform engineers switch between three dashboards, two CLIs, and the Azure Portal just to answer: *"Are we compliant?"*

## The Solution

PolicyPulse normalizes all three engines into 7 MCP tools. Ask your AI assistant:

> *"What are my most critical violations across all engines?"*
> *"Check this deployment manifest before I push it."*
> *"Which violations map to PCI-DSS requirements?"*
> *"Explain this violation and tell me how to fix it."*

---

## Architecture

```
MCP Clients (Claude, Cursor, GitHub Copilot, Cline, Windsurf, Continue.dev, Zed)
        │
        │  stdio (local)  ──or──  SSE over HTTPS (enterprise / Container Apps)
        ▼
┌───────────────────────────────────────┐
│           PolicyPulse MCP             │
│                                       │
│  ┌─────────────────────────────────┐  │
│  │      Intelligence Layer         │  │
│  │  risk summary · explain ·       │  │
│  │  prioritize · framework enrich  │  │
│  └──────────┬──────────────────────┘  │
│             │  Violation / Policy     │
│  ┌──────────┴──────────────────────┐  │
│  │       Normalized Schema         │  │
│  └──┬───────────┬──────────────┬───┘  │
│     │           │              │      │
│  ┌──┴──┐  ┌─────┴──┐  ┌───────┴──┐   │
│  │ GK  │  │Kyverno │  │  Azure   │   │
│  │     │  │        │  │  Policy  │   │
│  └──┬──┘  └────┬───┘  └────┬─────┘   │
└─────┼──────────┼───────────┼─────────┘
      │          │           │
   AKS/k8s    AKS/k8s    Azure Subscription
  Constraints PolicyReports  PolicyInsights API
```

The control catalog is the single source of truth — it powers both **runtime enrichment** of live violations with CIS/PCI-DSS/NIST/SOC 2 references, and the **pre-deployment static gate** that checks YAML manifests with no cluster required.

---

## The 7 MCP Tools

| Tool | What it does |
|---|---|
| `cluster_status` | Which engines are connected; fleet overview; credential type |
| `list_policies` | All policies across engines; filter by engine |
| `get_violations` | All violations enriched with framework refs; filter by namespace / engine / severity / cluster |
| `get_compliance_risk_summary` | Cross-engine risk summary with regulatory impact |
| `explain_violation` | Plain English explanation + framework mapping + remediation steps for one violation |
| `check_manifest_compliance` | Pre-deploy static gate — paste YAML, get violations, no cluster needed |
| `list_controls` | Full 9-control catalog with CIS / PCI-DSS / NIST 800-53 / SOC 2 mappings |

---

## Quick Start — Demo Mode

No cluster or Azure credentials needed:

```bash
git clone https://github.com/raviteja-pegata/policy-pulse-mcp
cd policy-pulse-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

POLICYPULSE_DEMO=true policy-pulse-mcp
```

---

## Connecting to AKS

### Install policy engines on your cluster

```bash
# Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace

# OPA Gatekeeper
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper --name-template=gatekeeper \
  -n gatekeeper-system --create-namespace

# Apply demo policies and workloads (wait 2-3 min for audit reports)
kubectl apply -f demo-cluster/kyverno-policies.yaml
kubectl apply -f demo-cluster/gatekeeper-policies.yaml
kubectl apply -f demo-cluster/non-compliant-workloads.yaml
```

### Run against your cluster

```bash
pip install -e ".[all]"
az aks get-credentials --resource-group <rg> --name <cluster>

AZURE_SUBSCRIPTION_ID=<sub-id> \
AZURE_CREDENTIAL_TYPE=cli \
policy-pulse-mcp
```

### Multi-cluster fleet

```bash
POLICYPULSE_CLUSTERS=prod:aks-prod-eastus,staging:aks-staging-westus,dev:aks-dev \
AZURE_SUBSCRIPTION_ID=<sub-id> \
policy-pulse-mcp
```

Each violation includes a `cluster` field. You can filter by cluster when querying.

---

## Hosting on Azure Container Apps

For enterprise deployments, run PolicyPulse as an SSE server. This lets multiple teams and tools connect to one centrally managed compliance server.

### stdio vs SSE

| | stdio | SSE |
|---|---|---|
| Transport | Local pipe | HTTP / HTTPS |
| Clients | One (local process only) | Many (concurrent) |
| Auth | None | Bearer token / Azure AD |
| Hosting | Developer laptop only | Container Apps, AKS, any cloud |
| Best for | Local dev, Claude Desktop | Enterprise, CI/CD, multi-team |

### Step 1 — Build and push the container

```bash
docker build -t policypulse-mcp:latest .

az acr login --name <your-acr>
docker tag policypulse-mcp:latest <your-acr>.azurecr.io/policypulse-mcp:latest
docker push <your-acr>.azurecr.io/policypulse-mcp:latest
```

### Step 2 — Create the Container App

```bash
az containerapp create \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --environment <your-aca-environment> \
  --image <your-acr>.azurecr.io/policypulse-mcp:latest \
  --target-port 8000 \
  --ingress external \
  --env-vars \
    POLICYPULSE_TRANSPORT=sse \
    AZURE_SUBSCRIPTION_ID=<sub-id> \
    AZURE_CREDENTIAL_TYPE=managed_identity \
    POLICYPULSE_CLUSTERS=prod:aks-prod,staging:aks-staging
```

### Step 3 — Assign managed identity

```bash
# Enable system-assigned managed identity
az containerapp identity assign \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --system-assigned

PRINCIPAL_ID=$(az containerapp identity show \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --query principalId -o tsv)

# Grant Policy Insights Reader on your subscription
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Policy Insights Data Reader (Preview)" \
  --scope /subscriptions/<sub-id>
```

### Step 4 — Connect AKS to the Container App

```bash
# Option A: VNet integration (recommended for production)
az containerapp env create \
  --name policy-pulse-env \
  --resource-group <your-rg> \
  --location eastus \
  --infrastructure-subnet-resource-id <subnet-id>

# Option B: Public AKS — whitelist the Container App outbound IP
ACA_IP=$(az containerapp show \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --query properties.outboundIpAddresses[0] -o tsv)

az aks update \
  --name <cluster> \
  --resource-group <your-rg> \
  --api-server-authorized-ip-ranges $ACA_IP
```

Your SSE endpoint will be:
```
https://policy-pulse-mcp.<unique-id>.eastus.azurecontainerapps.io/sse
```

---

## MCP Client Configuration

### Claude Desktop — local (stdio)

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "policy-pulse": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "policy_pulse_mcp.server"],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "your-sub-id",
        "AZURE_CREDENTIAL_TYPE": "cli"
      }
    }
  }
}
```

### Claude Desktop — enterprise (SSE)

```json
{
  "mcpServers": {
    "policy-pulse": {
      "url": "https://policy-pulse-mcp.<unique-id>.eastus.azurecontainerapps.io/sse"
    }
  }
}
```

### Cursor

Open **Settings → MCP → Add Server**:

```json
{
  "policy-pulse": {
    "command": "python",
    "args": ["-m", "policy_pulse_mcp.server"],
    "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
  }
}
```

For enterprise SSE: `{ "url": "https://..." }`

### GitHub Copilot (VS Code)

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "policy-pulse": {
      "type": "sse",
      "url": "https://policy-pulse-mcp.<unique-id>.eastus.azurecontainerapps.io/sse"
    }
  }
}
```

For local stdio:
```json
{
  "servers": {
    "policy-pulse": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "policy_pulse_mcp.server"],
      "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
    }
  }
}
```

### Continue.dev

`~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "policy-pulse",
      "command": "python",
      "args": ["-m", "policy_pulse_mcp.server"],
      "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
    }
  ]
}
```

### Cline (VS Code)

Cline extension → **MCP Servers → Add**:

```json
{
  "policy-pulse": {
    "command": "python",
    "args": ["-m", "policy_pulse_mcp.server"],
    "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
  }
}
```

### Windsurf (Codeium)

**Windsurf Settings → MCP → Add server**:

```json
{
  "policy-pulse": {
    "serverType": "stdio",
    "command": "python",
    "args": ["-m", "policy_pulse_mcp.server"],
    "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
  }
}
```

### Zed Editor

`~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "policy-pulse": {
      "command": {
        "path": "python",
        "args": ["-m", "policy_pulse_mcp.server"],
        "env": { "AZURE_SUBSCRIPTION_ID": "your-sub-id" }
      }
    }
  }
}
```

---

## Environment Variables

### Core

| Variable | Default | Description |
|---|---|---|
| `POLICYPULSE_DEMO` | `false` | `true` = mock data, no cluster or Azure needed |
| `POLICYPULSE_TRANSPORT` | `stdio` | `stdio` for local clients, `sse` for hosted deployments |
| `POLICYPULSE_HOST` | `0.0.0.0` | SSE server bind address |
| `PORT` | `8000` | SSE server port (also accepts `POLICYPULSE_PORT`) |
| `POLICYPULSE_LOG` | `INFO` | Log level |

### Kubernetes

| Variable | Default | Description |
|---|---|---|
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig file |
| `POLICYPULSE_CLUSTERS` | *(single cluster)* | Multi-cluster: `label1:context1,label2:context2` |

### Azure

| Variable | Required | Description |
|---|---|---|
| `AZURE_SUBSCRIPTION_ID` | For Azure engine | Subscription to query |
| `AZURE_CREDENTIAL_TYPE` | No | `auto` \| `cli` \| `managed_identity` \| `service_principal` |
| `AZURE_TENANT_ID` | For service_principal | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | For service_principal / user-assigned MI | Client or identity ID |
| `AZURE_CLIENT_SECRET` | For service_principal | Client secret |

---

## Azure Credential Types

**Local development:**
```bash
az login
AZURE_CREDENTIAL_TYPE=cli policy-pulse-mcp
```

**CI/CD — service principal:**
```bash
AZURE_CREDENTIAL_TYPE=service_principal \
AZURE_TENANT_ID=<tenant-id> \
AZURE_CLIENT_ID=<client-id> \
AZURE_CLIENT_SECRET=<secret> \
policy-pulse-mcp
```

**Production on AKS / Container Apps — managed identity:**
```bash
AZURE_CREDENTIAL_TYPE=managed_identity policy-pulse-mcp
```

The identity needs **Policy Insights Data Reader (Preview)** on your subscription.

---

## Installation

```bash
pip install policy-pulse-mcp                    # core only (demo + static gate)
pip install "policy-pulse-mcp[kubernetes]"      # + Gatekeeper + Kyverno
pip install "policy-pulse-mcp[azure]"           # + Azure Policy
pip install "policy-pulse-mcp[all]"             # everything
```

---

## Development

```bash
git clone https://github.com/raviteja-pegata/policy-pulse-mcp
cd policy-pulse-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all,dev]"

make test          # 87 tests, fully offline, ~0.3s
make demo-server   # POLICYPULSE_DEMO=true
make lint
make fmt
```

---

## Roadmap

### v0.2
- [ ] `get_violation_history` — compliance drift over time
- [ ] `check_resource_compliance` — point query for a specific Azure resource
- [ ] Multi-subscription Azure support
- [ ] Helm chart for in-cluster deployment
- [ ] PyPI publish

### v0.3
- [ ] YAML-driven catalog extensions — add controls without writing Python
- [ ] `search_catalog` tool
- [ ] GitHub Actions pre-deploy gate example

### v1.0
- [ ] `generate_remediation_manifest`
- [ ] `create_exemption_request`
- [ ] `trigger_azure_remediation_task`

---

## License

MIT — see [LICENSE](LICENSE).
