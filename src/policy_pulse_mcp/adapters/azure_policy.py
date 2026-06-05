"""Azure Policy adapter — PolicyInsightsClient + credential from credentials.py."""
import logging

from ..cache import ttl_cache
from ..credentials import build_azure_credential
from ..models import Engine, Policy, Severity, Violation

logger = logging.getLogger(__name__)

_COMPLIANCE_MAP = {
    "NonCompliant": Severity.HIGH,
    "Conflict": Severity.CRITICAL,
    "Unknown": Severity.MEDIUM,
}


def _fetch_display_names(credential, names: set[str]) -> dict[str, str]:
    import json
    import urllib.request

    try:
        token = credential.get_token("https://management.azure.com/.default").token
    except Exception:
        return {}

    headers = {"Authorization": f"Bearer {token}"}
    result = {}
    for name in names:
        url = (
            f"https://management.azure.com/providers/Microsoft.Authorization"
            f"/policyDefinitions/{name}?api-version=2021-06-01"
        )
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                result[name] = data.get("properties", {}).get("displayName", name)
        except Exception:
            result[name] = name
    return result


class AzurePolicyAdapter:
    engine = Engine.AZURE_POLICY

    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            try:
                build_azure_credential()
                self._available = True
            except Exception:
                self._available = False
        return self._available

    @ttl_cache(ttl_seconds=600)
    async def list_policies(self) -> list[Policy]:
        from azure.mgmt.policy import PolicyClient  # type: ignore[import-untyped]

        cred = build_azure_credential()
        client = PolicyClient(cred, self.subscription_id)
        policies = []
        for defn in client.policy_definitions.list():
            policies.append(
                Policy(
                    name=defn.name or "unknown",
                    engine=self.engine,
                    kind="PolicyDefinition",
                    enforcement=defn.enforcement_mode or "Default",
                    description=defn.description or "",
                )
            )
        return policies

    @ttl_cache(ttl_seconds=600)
    async def get_violations(self) -> list[Violation]:
        from azure.mgmt.policyinsights import PolicyInsightsClient  # type: ignore[import-untyped]

        cred = build_azure_credential()
        insights = PolicyInsightsClient(cred, self.subscription_id)

        raw_states = [
            s for s in insights.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self.subscription_id,
                query_options=None,
            )
            if s.compliance_state != "Compliant"
        ]

        unique_names = {s.policy_definition_name for s in raw_states if s.policy_definition_name}
        display_names = _fetch_display_names(cred, unique_names)

        violations: list[Violation] = []
        for state in raw_states:
            sev = _COMPLIANCE_MAP.get(state.compliance_state or "", Severity.MEDIUM)
            raw_name = state.policy_definition_name or "unknown"
            display = display_names.get(raw_name, raw_name)
            policy_name = display.lower().replace(" ", "-")
            resource_name = (state.resource_id or "unknown").split("/")[-1]
            violations.append(
                Violation(
                    id=f"azure-{raw_name[:8]}-{resource_name}",
                    engine=self.engine,
                    policy_name=policy_name,
                    resource_name=resource_name,
                    resource_kind=state.resource_type or "AzureResource",
                    namespace=None,
                    message=f"Azure Policy: {display}",
                    severity=sev,
                )
            )

        return violations
