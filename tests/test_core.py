import pytest

from policy_pulse_mcp import checks
from policy_pulse_mcp.evaluator import gate
from policy_pulse_mcp.frameworks import CATALOG, enrich, get_control
from policy_pulse_mcp.intelligence import build_risk_summary, engine_label, explain, prioritize
from policy_pulse_mcp.models import Engine, FrameworkRef, Severity, Violation


def _v(
    policy_name: str = "no-privileged-containers",
    severity: Severity = Severity.HIGH,
    message: str = "test",
    engine: Engine = Engine.GATEKEEPER,
    framework_refs: list | None = None,
) -> Violation:
    return Violation(
        id=f"test-{policy_name}",
        engine=engine,
        policy_name=policy_name,
        resource_name="my-pod",
        resource_kind="Pod",
        namespace="default",
        message=message,
        severity=severity,
        framework_refs=framework_refs or [],
    )


COMPLIANT_SPEC = {
    "securityContext": {"runAsNonRoot": True},
    "containers": [
        {
            "name": "app",
            "securityContext": {"readOnlyRootFilesystem": True},
            "resources": {"limits": {"cpu": "500m", "memory": "128Mi"}},
            "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
            "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
        }
    ],
}

VIOLATING_SPEC = {
    "hostNetwork": True,
    "hostPID": True,
    "hostIPC": True,
    "containers": [{"name": "bad", "securityContext": {"privileged": True}}],
}


class TestChecks:
    def test_privileged_container_violating(self):
        spec = {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}
        assert checks.privileged_container(spec) is True

    def test_privileged_container_compliant(self):
        spec = {"containers": [{"name": "c", "securityContext": {"privileged": False}}]}
        assert checks.privileged_container(spec) is False

    def test_host_network_violating(self):
        assert checks.host_network({"hostNetwork": True}) is True

    def test_host_network_compliant(self):
        assert checks.host_network({"hostNetwork": False}) is False

    def test_host_pid_violating(self):
        assert checks.host_pid({"hostPID": True}) is True

    def test_host_pid_compliant(self):
        assert checks.host_pid({}) is False

    def test_host_ipc_violating(self):
        assert checks.host_ipc({"hostIPC": True}) is True

    def test_host_ipc_compliant(self):
        assert checks.host_ipc({"hostIPC": False}) is False

    def test_runs_as_root_violating_no_setting(self):
        assert checks.runs_as_root({}) is True

    def test_runs_as_root_compliant_with_flag(self):
        assert checks.runs_as_root({"securityContext": {"runAsNonRoot": True}}) is False

    def test_no_resource_limits_missing_cpu(self):
        spec = {"containers": [{"name": "c", "resources": {"limits": {"memory": "128Mi"}}}]}
        assert checks.no_resource_limits(spec) is True

    def test_no_resource_limits_compliant(self):
        spec = {"containers": [{"name": "c", "resources": {"limits": {"cpu": "500m", "memory": "128Mi"}}}]}
        assert checks.no_resource_limits(spec) is False

    def test_writable_root_filesystem_violating(self):
        spec = {"containers": [{"name": "c"}]}
        assert checks.writable_root_filesystem(spec) is True

    def test_writable_root_filesystem_compliant(self):
        spec = {"containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}]}
        assert checks.writable_root_filesystem(spec) is False

    def test_no_liveness_probe_violating(self):
        spec = {"containers": [{"name": "c"}]}
        assert checks.no_liveness_probe(spec) is True

    def test_no_liveness_probe_compliant(self):
        spec = {"containers": [{"name": "c", "livenessProbe": {"httpGet": {"path": "/", "port": 80}}}]}
        assert checks.no_liveness_probe(spec) is False

    def test_no_readiness_probe_violating(self):
        spec = {"containers": [{"name": "c"}]}
        assert checks.no_readiness_probe(spec) is True

    def test_no_readiness_probe_compliant(self):
        spec = {"containers": [{"name": "c", "readinessProbe": {"httpGet": {"path": "/", "port": 80}}}]}
        assert checks.no_readiness_probe(spec) is False


class TestFrameworks:
    def test_catalog_has_nine_controls(self):
        assert len(CATALOG) == 9

    def test_all_controls_have_unique_ids(self):
        ids = [c.id for c in CATALOG]
        assert len(ids) == len(set(ids))

    def test_all_controls_have_manifest_check(self):
        for c in CATALOG:
            assert c.manifest_check is not None, f"{c.id} missing manifest_check"

    def test_enrich_with_matching_keyword(self):
        v = _v(policy_name="no-privileged-containers", message="privileged container")
        refs = enrich(v)
        assert len(refs) > 0
        assert "CIS Kubernetes" in {r.framework for r in refs}

    def test_enrich_no_match_returns_empty(self):
        v = _v(policy_name="completely-unrelated-xyz", message="some unrelated message")
        assert enrich(v) == []

    def test_enrich_multiple_matches(self):
        v = _v(policy_name="no-privileged-root-containers", message="privileged root container")
        assert len(enrich(v)) > 1

    def test_get_control_by_id(self):
        c = get_control("no-privileged-containers")
        assert c is not None
        assert c.title == "No Privileged Containers"

    def test_get_control_not_found(self):
        assert get_control("nonexistent-control") is None

    def test_severity_ordering(self):
        severities = [c.severity for c in CATALOG]
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities

    def test_framework_refs_have_required_fields(self):
        for c in CATALOG:
            for ref in c.frameworks:
                assert ref.framework
                assert ref.control_id
                assert ref.control_title

    def test_keywords_are_lowercase(self):
        for c in CATALOG:
            for kw in c.keywords:
                assert kw == kw.lower(), f"Keyword '{kw}' in {c.id} is not lowercase"

    def test_remediation_not_empty(self):
        for c in CATALOG:
            assert c.remediation.strip(), f"{c.id} has empty remediation"


class TestEvaluator:
    def test_gate_clean_manifest(self):
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "good-pod", "namespace": "default"},
            "spec": COMPLIANT_SPEC,
        }
        assert gate(manifest) == []

    def test_gate_privileged_pod(self):
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "bad-pod"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        assert "no-privileged-containers" in [v.policy_name for v in gate(manifest)]

    def test_gate_host_network_pod(self):
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "net-pod"},
            "spec": {"hostNetwork": True, "containers": [{"name": "c"}]},
        }
        assert "no-host-network" in [v.policy_name for v in gate(manifest)]

    def test_gate_multiple_violations(self):
        manifest = {"kind": "Pod", "metadata": {"name": "multi-bad"}, "spec": VIOLATING_SPEC}
        assert len(gate(manifest)) >= 3

    def test_gate_deployment_extracts_pod_spec(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "deploy", "namespace": "default"},
            "spec": {"template": {"spec": {"hostPID": True, "containers": [{"name": "c"}]}}},
        }
        assert "no-host-pid" in [v.policy_name for v in gate(manifest)]

    def test_gate_daemonset_extracts_pod_spec(self):
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "ds"},
            "spec": {"template": {"spec": {"hostIPC": True, "containers": [{"name": "c"}]}}},
        }
        assert "no-host-ipc" in [v.policy_name for v in gate(manifest)]

    def test_gate_unknown_kind_handled(self):
        manifest = {"kind": "UnknownResource", "metadata": {"name": "x"}, "spec": {}}
        assert isinstance(gate(manifest), list)

    def test_gate_violations_have_static_engine(self):
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        assert all(v.engine == Engine.STATIC for v in gate(manifest))

    def test_gate_violations_have_ids(self):
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        assert all(v.id for v in gate(manifest))

    def test_gate_string_manifest_yaml(self):
        yaml_str = """
apiVersion: v1
kind: Pod
metadata:
  name: yaml-pod
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: app
"""
        assert "no-host-network" in [v.policy_name for v in gate(yaml_str)]


class TestIntelligence:
    def test_build_risk_summary_empty(self):
        summary = build_risk_summary([])
        assert summary["total_violations"] == 0
        assert summary["top_risks"] == []

    def test_build_risk_summary_with_violations(self):
        violations = [_v("no-privileged-containers", Severity.CRITICAL), _v("no-host-network", Severity.HIGH)]
        assert build_risk_summary(violations)["total_violations"] == 2

    def test_build_risk_summary_severity_counts(self):
        violations = [_v("p1", Severity.CRITICAL), _v("p2", Severity.CRITICAL), _v("p3", Severity.HIGH)]
        summary = build_risk_summary(violations)
        assert summary["severity_breakdown"]["critical"] == 2
        assert summary["severity_breakdown"]["high"] == 1

    def test_prioritize_orders_by_severity(self):
        violations = [_v("low", Severity.LOW), _v("critical", Severity.CRITICAL), _v("medium", Severity.MEDIUM)]
        ordered = prioritize(violations)
        assert ordered[0].severity == Severity.CRITICAL
        assert ordered[-1].severity == Severity.LOW

    def test_explain_returns_remediation(self):
        result = explain(_v("no-privileged-containers", Severity.CRITICAL))
        assert result.get("remediation")

    def test_explain_includes_framework_refs(self):
        v = _v(
            "no-privileged-containers",
            Severity.CRITICAL,
            framework_refs=[FrameworkRef("CIS Kubernetes", "5.2.1", "Minimize privileged containers")],
        )
        result = explain(v)
        assert result["framework_refs"][0]["framework"] == "CIS Kubernetes"

    def test_engine_label_all_engines(self):
        assert engine_label(Engine.GATEKEEPER) == "OPA Gatekeeper"
        assert engine_label(Engine.KYVERNO) == "Kyverno"
        assert engine_label(Engine.AZURE_POLICY) == "Azure Policy"
        assert engine_label(Engine.STATIC) == "Static Analysis"
