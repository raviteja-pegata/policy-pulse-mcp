"""Mock adapters for POLICYPULSE_DEMO=true mode — no cluster or Azure credentials needed."""
from .models import Engine, Policy, Severity, Violation

MOCK_VIOLATIONS: list[Violation] = [
    Violation(
        id="gk-no-privileged-default-bad-deployment",
        engine=Engine.GATEKEEPER,
        policy_name="no-privileged-containers",
        resource_name="bad-deployment",
        resource_kind="Deployment",
        namespace="default",
        message="Privileged container 'app' is not allowed",
        severity=Severity.CRITICAL,
    ),
    Violation(
        id="gk-no-host-network-kube-system-old-daemonset",
        engine=Engine.GATEKEEPER,
        policy_name="no-host-network",
        resource_name="old-daemonset",
        resource_kind="DaemonSet",
        namespace="kube-system",
        message="Container 'agent' must not use hostNetwork",
        severity=Severity.HIGH,
    ),
    Violation(
        id="kyverno-run-as-non-root-default-api-pod",
        engine=Engine.KYVERNO,
        policy_name="disallow-root-containers",
        resource_name="api-pod",
        resource_kind="Pod",
        namespace="default",
        message="Pod must set runAsNonRoot: true in securityContext",
        severity=Severity.HIGH,
    ),
    Violation(
        id="kyverno-resource-limits-staging-worker",
        engine=Engine.KYVERNO,
        policy_name="require-resource-limits",
        resource_name="worker",
        resource_kind="Deployment",
        namespace="staging",
        message="Container 'worker' is missing cpu and memory limits",
        severity=Severity.MEDIUM,
    ),
    Violation(
        id="azure-no-privileged-prod-aks-cluster",
        engine=Engine.AZURE_POLICY,
        policy_name="kubernetes-no-privileged-containers",
        resource_name="prod-aks-cluster",
        resource_kind="Microsoft.ContainerService/managedClusters",
        namespace=None,
        message="AKS cluster does not enforce non-privileged containers policy",
        severity=Severity.HIGH,
    ),
]

MOCK_POLICIES: list[Policy] = [
    Policy(
        name="no-privileged-containers",
        engine=Engine.GATEKEEPER,
        kind="ConstraintTemplate",
        enforcement="deny",
        description="Disallow privileged containers across all namespaces",
    ),
    Policy(
        name="no-host-network",
        engine=Engine.GATEKEEPER,
        kind="ConstraintTemplate",
        enforcement="deny",
        description="Disallow pods from using the host network namespace",
    ),
    Policy(
        name="disallow-root-containers",
        engine=Engine.KYVERNO,
        kind="ClusterPolicy",
        enforcement="enforce",
        description="Require all containers to run as a non-root user",
    ),
    Policy(
        name="require-resource-limits",
        engine=Engine.KYVERNO,
        kind="ClusterPolicy",
        enforcement="audit",
        description="Require CPU and memory limits on all containers",
    ),
    Policy(
        name="kubernetes-no-privileged-containers",
        engine=Engine.AZURE_POLICY,
        kind="PolicyDefinition",
        enforcement="Audit",
        description="Azure Policy: Do not allow privileged containers in Kubernetes cluster",
    ),
]


class MockGatekeeperAdapter:
    engine = Engine.GATEKEEPER

    def is_available(self) -> bool:
        return True

    async def list_policies(self) -> list[Policy]:
        return [p for p in MOCK_POLICIES if p.engine == Engine.GATEKEEPER]

    async def get_violations(self) -> list[Violation]:
        return [v for v in MOCK_VIOLATIONS if v.engine == Engine.GATEKEEPER]


class MockKyvernoAdapter:
    engine = Engine.KYVERNO

    def is_available(self) -> bool:
        return True

    async def list_policies(self) -> list[Policy]:
        return [p for p in MOCK_POLICIES if p.engine == Engine.KYVERNO]

    async def get_violations(self) -> list[Violation]:
        return [v for v in MOCK_VIOLATIONS if v.engine == Engine.KYVERNO]


class MockAzurePolicyAdapter:
    engine = Engine.AZURE_POLICY

    def is_available(self) -> bool:
        return True

    async def list_policies(self) -> list[Policy]:
        return [p for p in MOCK_POLICIES if p.engine == Engine.AZURE_POLICY]

    async def get_violations(self) -> list[Violation]:
        return [v for v in MOCK_VIOLATIONS if v.engine == Engine.AZURE_POLICY]
