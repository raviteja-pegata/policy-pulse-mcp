"""Kyverno adapter — reads ClusterPolicies + PolicyReports."""
import logging

from ..cache import ttl_cache
from ..cluster import load_kube_config
from ..models import Engine, Policy, Severity, Violation

logger = logging.getLogger(__name__)

_RESULT_MAP = {
    "fail": Severity.HIGH,
    "error": Severity.CRITICAL,
    "warn": Severity.MEDIUM,
    "pass": None,
    "skip": None,
}


class KyvernoAdapter:
    engine = Engine.KYVERNO

    def __init__(self) -> None:
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            try:
                load_kube_config()
                self._available = True
            except Exception:
                self._available = False
        return self._available

    @ttl_cache(ttl_seconds=300)
    async def list_policies(self) -> list[Policy]:
        from kubernetes import client  # type: ignore[import-untyped]

        load_kube_config()
        api = client.CustomObjectsApi()
        items = api.list_cluster_custom_object(
            group="kyverno.io",
            version="v1",
            plural="clusterpolicies",
        )
        policies = []
        for item in items.get("items", []):
            name = item["metadata"]["name"]
            spec = item.get("spec", {})
            enforcement = "enforce" if spec.get("validationFailureAction") == "enforce" else "audit"
            policies.append(
                Policy(
                    name=name,
                    engine=self.engine,
                    kind="ClusterPolicy",
                    enforcement=enforcement,
                    description=item.get("metadata", {}).get("annotations", {}).get(
                        "policies.kyverno.io/description", ""
                    ),
                    raw=item,
                )
            )
        return policies

    @ttl_cache(ttl_seconds=300)
    async def get_violations(self) -> list[Violation]:
        from kubernetes import client  # type: ignore[import-untyped]

        load_kube_config()
        api = client.CustomObjectsApi()
        violations: list[Violation] = []

        reports = None
        for version in ("v1", "v1alpha2"):
            try:
                reports = api.list_cluster_custom_object(
                    group="wgpolicyk8s.io",
                    version=version,
                    plural="clusterpolicyreports",
                )
                break
            except Exception as exc:
                if version == "v1alpha2":
                    logger.warning("ClusterPolicyReport CRD not available — Kyverno audit may not have run yet: %s", exc)
                    return violations

        if not reports:
            return violations

        for report in reports.get("items", []):
            for result in report.get("results", []):
                if result.get("result") not in ("fail", "error"):
                    continue
                sev = _RESULT_MAP.get(result.get("result", ""), Severity.HIGH) or Severity.HIGH
                res = result.get("resources", [{}])[0] if result.get("resources") else {}
                violations.append(
                    Violation(
                        id=f"kyverno-{result.get('policy', 'unknown')}-{res.get('namespace', 'cluster')}-{res.get('name', 'unknown')}",
                        engine=self.engine,
                        policy_name=result.get("policy", "unknown"),
                        resource_name=res.get("name", "unknown"),
                        resource_kind=res.get("kind", "unknown"),
                        namespace=res.get("namespace") or None,
                        message=result.get("message", ""),
                        severity=sev,
                        raw=result,
                    )
                )

        return violations
