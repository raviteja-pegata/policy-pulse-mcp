"""OPA Gatekeeper adapter — reads ConstraintTemplates + status.violations."""
import logging

from ..cache import ttl_cache
from ..cluster import load_kube_config, load_kube_config_for_context
from ..models import Engine, Policy, Severity, Violation

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class GatekeeperAdapter:
    engine = Engine.GATEKEEPER

    def __init__(self, cluster_label: str | None = None, context: str | None = None) -> None:
        self.cluster_label = cluster_label
        self.context = context
        self._available: bool | None = None

    def _load_config(self) -> None:
        if self.context:
            load_kube_config_for_context(self.context)
        else:
            load_kube_config()

    def is_available(self) -> bool:
        if self._available is None:
            try:
                self._load_config()
                self._available = True
            except Exception:
                self._available = False
        return self._available

    @ttl_cache(ttl_seconds=300)
    async def list_policies(self) -> list[Policy]:
        from kubernetes import client  # type: ignore[import-untyped]

        self._load_config()
        api = client.CustomObjectsApi()
        templates = api.list_cluster_custom_object(
            group="templates.gatekeeper.sh",
            version="v1",
            plural="constrainttemplates",
        )
        policies = []
        for item in templates.get("items", []):
            name = item["metadata"]["name"]
            policies.append(
                Policy(
                    name=name,
                    engine=self.engine,
                    kind="ConstraintTemplate",
                    enforcement="deny",
                    description=item.get("spec", {}).get("crd", {}).get("spec", {}).get("names", {}).get("kind", ""),
                    raw=item,
                )
            )
        return policies

    @ttl_cache(ttl_seconds=300)
    async def get_violations(self) -> list[Violation]:
        from kubernetes import client  # type: ignore[import-untyped]

        self._load_config()
        api = client.CustomObjectsApi()
        violations: list[Violation] = []

        try:
            templates = api.list_cluster_custom_object(
                group="templates.gatekeeper.sh",
                version="v1",
                plural="constrainttemplates",
            )
        except Exception as exc:
            logger.debug("Could not list ConstraintTemplates: %s", exc)
            return violations

        for template in templates.get("items", []):
            plural = template["metadata"]["name"]
            try:
                items = api.list_cluster_custom_object(
                    group="constraints.gatekeeper.sh",
                    version="v1beta1",
                    plural=plural,
                )
            except Exception:
                continue

            for item in items.get("items", []):
                policy_name = item["metadata"]["name"]
                sev_str = item.get("spec", {}).get("parameters", {}).get("severity", "high").lower()
                severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)

                for v in item.get("status", {}).get("violations", []):
                    ns = v.get("namespace", "")
                    violations.append(
                        Violation(
                            id=f"gk-{policy_name}-{ns or 'cluster'}-{v.get('name', 'unknown')}",
                            engine=self.engine,
                            policy_name=policy_name,
                            resource_name=v.get("name", "unknown"),
                            resource_kind=v.get("kind", "unknown"),
                            namespace=ns or None,
                            message=v.get("message", ""),
                            severity=severity,
                            raw=v,
                            cluster=self.cluster_label,
                        )
                    )

        return violations
