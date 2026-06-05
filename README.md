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
| `cluster_status` | Which engines are connected; fleet overview with auth mode per cluster; credential type |
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

---

## Multi-Cluster Fleet

PolicyPulse can query multiple clusters in a single session. Every violation includes a `cluster` field so you can filter by cluster when querying.

There are two ways to specify clusters depending on where you're hosting PolicyPulse:

| Mode | Context format | When to use |
|---|---|---|
| **Kubeconfig** | `label:context-name` | Local dev, or kubeconfig mounted into the pod |
| **Workload Identity** | `label:resourceGroup/clusterName` | Hosted on Container Apps or AKS — no kubeconfig file needed |

### Kubeconfig mode (local development)

Pull credentials for each cluster, then point PolicyPulse at multiple contexts in a single kubeconfig:

```bash
az aks get-credentials --resource-group rg-prod --name aks-prod
az aks get-credentials --resource-group rg-staging --name aks-staging

POLICYPULSE_CLUSTERS=prod:aks-prod,staging:aks-staging \
AZURE_SUBSCRIPTION_ID=<sub-id> \
policy-pulse-mcp
```

The context name (`aks-prod`, `aks-staging`) must match a context in your `~/.kube/config`.

### Workload Identity mode (hosted deployments)

Use the `resourceGroup/clusterName` format. PolicyPulse calls the Azure management API to fetch each cluster's API server URL and CA certificate, then authenticates using a managed identity token — no kubeconfig file is needed anywhere.

```bash
POLICYPULSE_CLUSTERS=prod:rg-prod/aks-prod,staging:rg-staging/aks-staging \
AZURE_SUBSCRIPTION_ID=<sub-id> \
AZURE_CREDENTIAL_TYPE=managed_identity \
policy-pulse-mcp
```

Full setup for this is in the [Workload Identity Setup](#workload-identity-setup) section below.

---

## Hosting on Azure Container Apps

For enterprise deployments, run PolicyPulse as an SSE server on Azure Container Apps. This lets multiple teams and tools connect to one centrally managed compliance server over HTTPS.

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
    POLICYPULSE_CLUSTERS=prod:rg-prod/aks-prod,staging:rg-staging/aks-staging
```

> Using `resourceGroup/clusterName` format for `POLICYPULSE_CLUSTERS` activates Workload Identity mode — no kubeconfig file is needed in the container.

### Step 3 — Assign a managed identity

```bash
az containerapp identity assign \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --system-assigned

PRINCIPAL_ID=$(az containerapp identity show \
  --name policy-pulse-mcp \
  --resource-group <your-rg> \
  --query principalId -o tsv)
```

Then follow the [Workload Identity Setup](#workload-identity-setup) section to grant the identity access to each AKS cluster.

### Step 4 — Network connectivity

PolicyPulse needs to reach each AKS API server from Container Apps:

```bash
# Option A: VNet integration (recommended for production)
# Create the Container Apps environment on the same VNet as your AKS clusters.
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
  --name aks-prod \
  --resource-group rg-prod \
  --api-server-authorized-ip-ranges $ACA_IP
```

Your SSE endpoint will be:
```
https://policy-pulse-mcp.<unique-id>.eastus.azurecontainerapps.io/sse
```

---

## Workload Identity Setup

This section covers everything needed for the `resourceGroup/clusterName` cluster format — the recommended approach for Container Apps and AKS-hosted deployments.

### How it works

When PolicyPulse sees `POLICYPULSE_CLUSTERS=prod:rg-prod/aks-prod`, it:

1. Calls the Azure management API with a management-plane token to fetch the cluster's API server URL and CA certificate.
2. Gets a second token scoped to the AKS AAD server application (audience `6dae42f8-4368-4678-94ff-3960e28e3630`).
3. Builds the Kubernetes client from those two pieces — no kubeconfig file anywhere.

```
PolicyPulse (Container App or AKS pod)
        │
        │  managed identity token
        ▼
Azure AD
        │
        ├──► management.azure.com  →  listClusterUserCredential
        │                             (gets API server URL + CA cert)
        │
        └──► AKS API server (each cluster)
             "I am identity X — is my token valid?"
             "Yes — you have view access — here are your violations"
```

### Prerequisites

- Each target AKS cluster must have **AAD integration enabled**. This is the default for clusters created from 2021 onwards. To verify:

  ```bash
  az aks show --resource-group rg-prod --name aks-prod \
    --query "aadProfile" -o json
  # Should return a non-null object
  ```

- The managed identity needs permissions at **two levels**: the Azure management plane (to fetch cluster credentials) and inside each Kubernetes cluster (to read policy resources).

### Step 1 — Grant management-plane permissions

The identity needs to be able to call `listClusterUserCredential` on each target cluster, and to read Azure Policy compliance state.

```bash
PRINCIPAL_ID=<principal-id-of-your-managed-identity>
SUB_ID=<your-subscription-id>

# Azure Policy — read compliance state across the subscription
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Policy Insights Data Reader (Preview)" \
  --scope /subscriptions/$SUB_ID

# AKS — fetch cluster credentials (repeat for each target cluster)
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Azure Kubernetes Service Cluster User Role" \
  --scope /subscriptions/$SUB_ID/resourceGroups/rg-prod/providers/Microsoft.ContainerService/managedClusters/aks-prod

az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Azure Kubernetes Service Cluster User Role" \
  --scope /subscriptions/$SUB_ID/resourceGroups/rg-staging/providers/Microsoft.ContainerService/managedClusters/aks-staging
```

### Step 2 — Grant Kubernetes RBAC on each cluster

Once the management-plane token gets PolicyPulse into the API server, Kubernetes still checks its own RBAC. The approach depends on whether your cluster uses **Azure RBAC** or **local RBAC**.

**Check which mode your cluster uses:**
```bash
az aks show --resource-group rg-prod --name aks-prod \
  --query "aadProfile.enableAzureRbac" -o tsv
# true = Azure RBAC mode, false/null = local RBAC mode
```

**Azure RBAC mode (recommended for new clusters):**

Azure RBAC roles map directly to Kubernetes RBAC — no `kubectl` commands needed inside the cluster.

```bash
# Grant read access to Gatekeeper and Kyverno resources (repeat per cluster)
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Azure Kubernetes Service RBAC Reader" \
  --scope /subscriptions/$SUB_ID/resourceGroups/rg-prod/providers/Microsoft.ContainerService/managedClusters/aks-prod

az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Azure Kubernetes Service RBAC Reader" \
  --scope /subscriptions/$SUB_ID/resourceGroups/rg-staging/providers/Microsoft.ContainerService/managedClusters/aks-staging
```

**Local RBAC mode (older clusters):**

You need to create a `ClusterRoleBinding` inside each cluster using the identity's **client ID** (not the principal/object ID).

```bash
# Get the client ID of the managed identity
CLIENT_ID=$(az identity show \
  --name <your-managed-identity-name> \
  --resource-group <your-rg> \
  --query clientId -o tsv)

# Run this for each target cluster
az aks get-credentials --resource-group rg-prod --name aks-prod

kubectl create clusterrolebinding policypulse-reader \
  --clusterrole=view \
  --user="$CLIENT_ID"
```

> The `view` ClusterRole gives read-only access to most resources including the custom resources that Gatekeeper and Kyverno write their violations to.

### Step 3 — Configure PolicyPulse

Set these environment variables on your Container App or pod:

```
AZURE_SUBSCRIPTION_ID    = <your-subscription-id>
AZURE_CREDENTIAL_TYPE    = managed_identity
POLICYPULSE_CLUSTERS     = prod:rg-prod/aks-prod,staging:rg-staging/aks-staging
```

For a user-assigned managed identity, also set:
```
AZURE_CLIENT_ID          = <client-id-of-the-user-assigned-identity>
```

### Step 4 — Verify the connection

Once the server is running, call `cluster_status`. The response shows the auth mode for each cluster:

```json
{
  "fleet": [
    { "label": "prod",    "context": "rg-prod/aks-prod",       "auth": "workload_identity" },
    { "label": "staging", "context": "rg-staging/aks-staging", "auth": "workload_identity" }
  ]
}
```

If `"auth"` shows `"workload_identity"` and the cluster appears in `connected_engines`, the setup is complete.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `AZURE_SUBSCRIPTION_ID must be set` | Missing env var | Set `AZURE_SUBSCRIPTION_ID` |
| `403` from management API | Missing `Cluster User Role` | Run Step 1 role assignments |
| `401 Unauthorized` from k8s API | Missing k8s RBAC | Run Step 2 for the cluster |
| `aadProfile is null` | AAD integration not enabled | Enable with `az aks update --enable-aad` |
| `No CA certificate found` | Kubeconfig returned no CA | Check cluster health; fallback uses unverified TLS |

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
| `POLICYPULSE_DEMO` | `false` | `true` = mock data, no cluster or Azure credentials needed |
| `POLICYPULSE_TRANSPORT` | `stdio` | `stdio` for local clients, `sse` for hosted deployments |
| `POLICYPULSE_HOST` | `0.0.0.0` | SSE server bind address |
| `PORT` | `8000` | SSE server port (also accepts `POLICYPULSE_PORT`) |
| `POLICYPULSE_LOG` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`) |

### Kubernetes

| Variable | Default | Description |
|---|---|---|
| `KUBECONFIG` | `~/.kube/config` | Path to kubeconfig file (used in kubeconfig mode only) |
| `POLICYPULSE_CLUSTERS` | *(single cluster)* | Comma-separated list. Two formats supported: `label:context-name` (kubeconfig mode) or `label:resourceGroup/clusterName` (workload identity mode). Example: `prod:rg-prod/aks-prod,dev:aks-dev-context` |

### Azure

| Variable | Required | Description |
|---|---|---|
| `AZURE_SUBSCRIPTION_ID` | For Azure Policy and workload identity | Subscription to query for policy compliance |
| `AZURE_CREDENTIAL_TYPE` | No (default: `auto`) | `auto` \| `cli` \| `managed_identity` \| `service_principal` |
| `AZURE_TENANT_ID` | For `service_principal` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | For `service_principal` or user-assigned MI | Client or identity ID |
| `AZURE_CLIENT_SECRET` | For `service_principal` | Client secret |

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

**Production on Container Apps / AKS — managed identity:**
```bash
AZURE_CREDENTIAL_TYPE=managed_identity policy-pulse-mcp
```

Required Azure roles for the managed identity:

| Role | Scope | Purpose |
|---|---|---|
| `Policy Insights Data Reader (Preview)` | Subscription | Read Azure Policy compliance state |
| `Azure Kubernetes Service Cluster User Role` | Each AKS cluster | Fetch cluster credentials via management API |
| `Azure Kubernetes Service RBAC Reader` | Each AKS cluster | Read Gatekeeper/Kyverno resources (Azure RBAC clusters) |

For clusters using local RBAC instead of Azure RBAC, see [Step 2 of Workload Identity Setup](#step-2--grant-kubernetes-rbac-on-each-cluster).

---

## Installation

**From source (current):**

```bash
git clone https://github.com/raviteja-pegata/policy-pulse-mcp
cd policy-pulse-mcp
python -m venv .venv && source .venv/bin/activate

pip install -e "."          # core only (demo + static gate)
pip install -e ".[kubernetes]"  # + Gatekeeper + Kyverno
pip install -e ".[azure]"       # + Azure Policy
pip install -e ".[all]"         # everything
```

**From PyPI (coming in v0.2):**

```bash
pip install policy-pulse-mcp
pip install "policy-pulse-mcp[kubernetes]"
pip install "policy-pulse-mcp[azure]"
pip install "policy-pulse-mcp[all]"
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
