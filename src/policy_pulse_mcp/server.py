import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from . import frameworks, intelligence
from .evaluator import gate
from .models import Severity

logging.basicConfig(
    level=os.environ.get("POLICYPULSE_LOG", "INFO"),
    stream=sys.stderr,
)
logging.getLogger("azure.identity").setLevel(logging.WARNING)
logging.getLogger("azure.core").setLevel(logging.WARNING)
logging.getLogger("azure.mgmt").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

mcp = FastMCP("PolicyPulse")

DEMO_MODE = os.environ.get("POLICYPULSE_DEMO", "").lower() == "true"
_severity_order = {s: i for i, s in enumerate(Severity)}


def _parse_clusters() -> list[tuple[str, str]]:
    """Parse POLICYPULSE_CLUSTERS=label1:context1,label2:context2 into [(label, context), ...]."""
    raw = os.environ.get("POLICYPULSE_CLUSTERS", "").strip()
    if not raw:
        return []
    clusters = []
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" in entry:
            label, _, context = entry.partition(":")
            clusters.append((label.strip(), context.strip()))
        else:
            clusters.append((entry, entry))
    return clusters


def _build_adapters() -> list:
    if DEMO_MODE:
        from .demo import MockAzurePolicyAdapter, MockGatekeeperAdapter, MockKyvernoAdapter
        return [MockGatekeeperAdapter(), MockKyvernoAdapter(), MockAzurePolicyAdapter()]

    adapters = []
    clusters = _parse_clusters()

    if clusters:
        from .adapters.gatekeeper import GatekeeperAdapter
        from .adapters.kyverno import KyvernoAdapter
        for label, context in clusters:
            for cls in (GatekeeperAdapter, KyvernoAdapter):
                try:
                    a = cls(cluster_label=label, context=context)
                    if a.is_available():
                        adapters.append(a)
                except Exception as exc:
                    logger.debug("%s unavailable for cluster %s: %s", cls.__name__, label, exc)
    else:
        try:
            from .adapters.gatekeeper import GatekeeperAdapter
            a = GatekeeperAdapter()
            if a.is_available():
                adapters.append(a)
        except Exception as exc:
            logger.debug("Gatekeeper unavailable: %s", exc)

        try:
            from .adapters.kyverno import KyvernoAdapter
            a = KyvernoAdapter()
            if a.is_available():
                adapters.append(a)
        except Exception as exc:
            logger.debug("Kyverno unavailable: %s", exc)

    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if sub_id:
        try:
            from .adapters.azure_policy import AzurePolicyAdapter
            a = AzurePolicyAdapter(sub_id)
            if a.is_available():
                adapters.append(a)
        except Exception as exc:
            logger.debug("Azure Policy unavailable: %s", exc)

    return adapters


_ADAPTERS = _build_adapters()


def _connection_hints(connected: set[str]) -> list[str]:
    hints = []
    if "gatekeeper" not in connected and "kyverno" not in connected:
        kube = os.path.expanduser(os.environ.get("KUBECONFIG", "~/.kube/config"))
        if not os.path.exists(kube):
            hints.append("No kubeconfig found — run 'az aks get-credentials' or set KUBECONFIG.")
        else:
            hints.append(
                "Cluster reachable but no Gatekeeper or Kyverno found — "
                "are they installed? Kyverno PolicyReports may also need a few minutes after install."
            )
    if "azure_policy" not in connected:
        if not os.environ.get("AZURE_SUBSCRIPTION_ID"):
            hints.append("AZURE_SUBSCRIPTION_ID not set — Azure Policy engine skipped.")
        else:
            cred_type = os.environ.get("AZURE_CREDENTIAL_TYPE", "auto")
            if cred_type == "service_principal":
                missing = [v for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET") if not os.environ.get(v)]
                if missing:
                    hints.append(f"service_principal auth missing: {', '.join(missing)}")
            else:
                hints.append("Azure Policy failed to connect — check credentials with 'az login'.")
    return hints


@mcp.tool()
async def cluster_status() -> dict:
    """Which policy engines are connected and whether demo mode is active."""
    engines = [
        {
            "engine": a.engine.value,
            "label": intelligence.engine_label(a.engine),
            "available": a.is_available(),
        }
        for a in _ADAPTERS
    ]
    connected = {e["engine"] for e in engines}
    hints = [] if DEMO_MODE else _connection_hints(connected)

    clusters = _parse_clusters()
    fleet = None
    if clusters:
        fleet = [{"label": label, "context": context} for label, context in clusters]

    return {
        "demo_mode": DEMO_MODE,
        "demo_banner": "DEMO MODE — using mock data, no cluster required." if DEMO_MODE else None,
        "connected_engines": engines,
        "engine_count": len(engines),
        "azure_credential_type": os.environ.get("AZURE_CREDENTIAL_TYPE", "auto"),
        "fleet": fleet,
        "hints": hints or None,
    }


@mcp.tool()
async def list_policies(engine: str | None = None) -> dict:
    """List all policies across connected engines, optionally filtered by engine name."""
    policies = []
    for adapter in _ADAPTERS:
        if engine and adapter.engine.value != engine:
            continue
        policies.extend(await adapter.list_policies())

    return {
        "policies": [
            {
                "name": p.name,
                "engine": p.engine.value,
                "kind": p.kind,
                "enforcement": p.enforcement,
                "description": p.description,
            }
            for p in policies
        ],
        "total": len(policies),
    }


@mcp.tool()
async def get_violations(
    namespace: str | None = None,
    engine: str | None = None,
    min_severity: str | None = None,
    cluster: str | None = None,
) -> dict:
    """All active violations enriched with compliance framework refs.

    namespace: restrict to a specific Kubernetes namespace.
    engine: one of gatekeeper, kyverno, azure_policy.
    min_severity: only return violations at or above this level (critical → info).
    cluster: restrict to a specific cluster label (multi-cluster mode only).
    """
    violations = []
    for adapter in _ADAPTERS:
        if engine and adapter.engine.value != engine:
            continue
        violations.extend(await adapter.get_violations())

    for v in violations:
        if not v.framework_refs:
            v.framework_refs = frameworks.enrich(v)

    if namespace:
        violations = [v for v in violations if v.namespace == namespace]

    if cluster:
        violations = [v for v in violations if v.cluster == cluster]

    if min_severity:
        try:
            threshold = _severity_order[Severity(min_severity)]
            violations = [v for v in violations if _severity_order.get(v.severity, 99) <= threshold]
        except ValueError:
            pass

    violations = intelligence.prioritize(violations)

    return {
        "violations": [
            {
                "id": v.id,
                "engine": v.engine.value,
                "policy": v.policy_name,
                "resource": f"{v.resource_kind}/{v.resource_name}",
                "namespace": v.namespace,
                "cluster": v.cluster,
                "severity": v.severity.value,
                "message": v.message,
                "framework_refs": [
                    {"framework": r.framework, "control_id": r.control_id}
                    for r in v.framework_refs
                ],
            }
            for v in violations
        ],
        "total": len(violations),
    }


@mcp.tool()
async def get_compliance_risk_summary() -> dict:
    """Cross-engine risk summary: severity breakdown, top risks, and regulatory impact."""
    violations = []
    for adapter in _ADAPTERS:
        violations.extend(await adapter.get_violations())

    for v in violations:
        if not v.framework_refs:
            v.framework_refs = frameworks.enrich(v)

    return intelligence.build_risk_summary(violations)


@mcp.tool()
async def explain_violation(violation_id: str) -> dict:
    """Plain-English explanation of one violation with framework mapping and remediation."""
    for adapter in _ADAPTERS:
        for v in await adapter.get_violations():
            if v.id == violation_id:
                if not v.framework_refs:
                    v.framework_refs = frameworks.enrich(v)
                return intelligence.explain(v)

    return {"error": f"Violation not found: {violation_id}"}


@mcp.tool()
async def check_manifest_compliance(manifest: str) -> dict:
    """Static policy check for a Kubernetes manifest (YAML or JSON) — no cluster needed."""
    try:
        violations = gate(manifest)
    except Exception as exc:
        return {"error": f"Failed to parse manifest: {exc}"}

    _remediation = {c.id: c.remediation for c in frameworks.CATALOG}

    return {
        "violations": [
            {
                "control_id": v.policy_name,
                "severity": v.severity.value,
                "message": v.message,
                "remediation": _remediation.get(v.policy_name, "See policy documentation."),
                "framework_refs": [
                    {"framework": r.framework, "control_id": r.control_id}
                    for r in v.framework_refs
                ],
            }
            for v in intelligence.prioritize(violations)
        ],
        "total_violations": len(violations),
        "compliant": len(violations) == 0,
    }


@mcp.tool()
async def list_controls() -> dict:
    """The full compliance control catalog with framework mappings and remediation guidance."""
    return {
        "controls": [
            {
                "id": c.id,
                "title": c.title,
                "severity": c.severity.value,
                "frameworks": [
                    {
                        "framework": ref.framework,
                        "control_id": ref.control_id,
                        "control_title": ref.control_title,
                    }
                    for ref in c.frameworks
                ],
                "remediation": c.remediation,
                "keywords": list(c.keywords),
            }
            for c in frameworks.CATALOG
        ],
        "total": len(frameworks.CATALOG),
    }


def main() -> None:
    transport = os.environ.get("POLICYPULSE_TRANSPORT", "stdio").lower()
    if transport == "sse":
        host = os.environ.get("POLICYPULSE_HOST", "0.0.0.0")
        port = int(os.environ.get("PORT", os.environ.get("POLICYPULSE_PORT", "8000")))
        mcp.run(transport="sse", host=host, port=port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
