
from policy_pulse_mcp.server import (
    check_manifest_compliance,
    cluster_status,
    explain_violation,
    get_compliance_risk_summary,
    get_violations,
    list_controls,
    list_policies,
)

# A known demo violation ID from demo.py
_KNOWN_VIOLATION_ID = "gk-no-privileged-default-bad-deployment"

_PRIVILEGED_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
"""

_CLEAN_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: app
      securityContext:
        readOnlyRootFilesystem: true
      resources:
        limits:
          cpu: "500m"
          memory: "128Mi"
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
"""


class TestClusterStatus:
    async def test_returns_dict(self):
        result = await cluster_status()
        assert isinstance(result, dict)

    async def test_shows_demo_banner(self):
        result = await cluster_status()
        assert result["demo_mode"] is True
        assert result["demo_banner"] is not None

    async def test_lists_engines(self):
        result = await cluster_status()
        assert "connected_engines" in result
        assert isinstance(result["connected_engines"], list)

    async def test_engine_count(self):
        result = await cluster_status()
        assert result["engine_count"] == 3

    async def test_all_engines_available(self):
        result = await cluster_status()
        for eng in result["connected_engines"]:
            assert eng["available"] is True



class TestListPolicies:
    async def test_returns_dict(self):
        result = await list_policies()
        assert isinstance(result, dict)

    async def test_has_correct_count(self):
        result = await list_policies()
        assert result["total"] == 5

    async def test_filter_by_gatekeeper(self):
        result = await list_policies(engine="gatekeeper")
        assert result["total"] == 2
        for p in result["policies"]:
            assert p["engine"] == "gatekeeper"

    async def test_filter_by_kyverno(self):
        result = await list_policies(engine="kyverno")
        assert result["total"] == 2
        for p in result["policies"]:
            assert p["engine"] == "kyverno"

    async def test_filter_by_azure_policy(self):
        result = await list_policies(engine="azure_policy")
        assert result["total"] == 1

    async def test_all_engines_included(self):
        result = await list_policies()
        engines = {p["engine"] for p in result["policies"]}
        assert "gatekeeper" in engines
        assert "kyverno" in engines
        assert "azure_policy" in engines



class TestGetViolations:
    async def test_returns_dict(self):
        result = await get_violations()
        assert isinstance(result, dict)
        assert "violations" in result

    async def test_violations_have_severity(self):
        result = await get_violations()
        for v in result["violations"]:
            assert v["severity"] in ("critical", "high", "medium", "low", "info")

    async def test_violations_have_engine(self):
        result = await get_violations()
        for v in result["violations"]:
            assert v["engine"] in ("gatekeeper", "kyverno", "azure_policy")

    async def test_filter_by_engine(self):
        result = await get_violations(engine="gatekeeper")
        for v in result["violations"]:
            assert v["engine"] == "gatekeeper"

    async def test_filter_by_namespace(self):
        result = await get_violations(namespace="default")
        for v in result["violations"]:
            assert v["namespace"] == "default"

    async def test_filter_by_min_severity_critical(self):
        result = await get_violations(min_severity="critical")
        for v in result["violations"]:
            assert v["severity"] == "critical"

    async def test_enriched_with_framework_refs(self):
        result = await get_violations()
        enriched = [v for v in result["violations"] if v["framework_refs"]]
        assert len(enriched) > 0



class TestGetComplianceRiskSummary:
    async def test_returns_dict(self):
        result = await get_compliance_risk_summary()
        assert isinstance(result, dict)

    async def test_has_total_count(self):
        result = await get_compliance_risk_summary()
        assert "total_violations" in result
        assert result["total_violations"] == 5

    async def test_has_severity_breakdown(self):
        result = await get_compliance_risk_summary()
        assert "severity_breakdown" in result
        breakdown = result["severity_breakdown"]
        assert "critical" in breakdown
        assert "high" in breakdown

    async def test_has_top_risks(self):
        result = await get_compliance_risk_summary()
        assert "top_risks" in result
        assert len(result["top_risks"]) > 0

    async def test_has_engine_breakdown(self):
        result = await get_compliance_risk_summary()
        assert "engine_breakdown" in result
        assert len(result["engine_breakdown"]) > 0

    async def test_has_recommendation(self):
        result = await get_compliance_risk_summary()
        assert "recommendation" in result
        assert len(result["recommendation"]) > 0



class TestExplainViolation:
    async def test_returns_dict(self):
        result = await explain_violation(_KNOWN_VIOLATION_ID)
        assert isinstance(result, dict)

    async def test_includes_message(self):
        result = await explain_violation(_KNOWN_VIOLATION_ID)
        assert "message" in result
        assert len(result["message"]) > 0

    async def test_includes_remediation(self):
        result = await explain_violation(_KNOWN_VIOLATION_ID)
        assert "remediation" in result
        assert len(result["remediation"]) > 0

    async def test_includes_framework_refs(self):
        result = await explain_violation(_KNOWN_VIOLATION_ID)
        assert "framework_refs" in result

    async def test_invalid_id_returns_error(self):
        result = await explain_violation("nonexistent-id-xyz-123")
        assert "error" in result

    async def test_severity_included(self):
        result = await explain_violation(_KNOWN_VIOLATION_ID)
        assert "severity" in result
        assert result["severity"] == "critical"



class TestCheckManifestCompliance:
    async def test_clean_manifest_passes(self):
        result = await check_manifest_compliance(_CLEAN_MANIFEST)
        assert result["compliant"] is True
        assert result["total_violations"] == 0

    async def test_privileged_manifest_fails(self):
        result = await check_manifest_compliance(_PRIVILEGED_MANIFEST)
        assert result["compliant"] is False

    async def test_returns_violations_list(self):
        result = await check_manifest_compliance(_PRIVILEGED_MANIFEST)
        assert "violations" in result
        assert isinstance(result["violations"], list)

    async def test_violation_has_severity(self):
        result = await check_manifest_compliance(_PRIVILEGED_MANIFEST)
        for v in result["violations"]:
            assert v["severity"] in ("critical", "high", "medium", "low", "info")

    async def test_violation_has_remediation(self):
        result = await check_manifest_compliance(_PRIVILEGED_MANIFEST)
        for v in result["violations"]:
            assert v["remediation"]

    async def test_multiple_violations_detected(self):
        multi_bad = """
kind: Pod
metadata:
  name: multi-bad
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: c
      securityContext:
        privileged: true
"""
        result = await check_manifest_compliance(multi_bad)
        assert result["total_violations"] >= 3

    async def test_violation_has_framework_refs(self):
        result = await check_manifest_compliance(_PRIVILEGED_MANIFEST)
        priv_violation = next(
            (v for v in result["violations"] if v["control_id"] == "no-privileged-containers"), None
        )
        assert priv_violation is not None
        assert len(priv_violation["framework_refs"]) > 0



class TestListControls:
    async def test_returns_list(self):
        result = await list_controls()
        assert "controls" in result
        assert isinstance(result["controls"], list)

    async def test_count(self):
        result = await list_controls()
        assert result["total"] == 9

    async def test_controls_have_required_fields(self):
        result = await list_controls()
        for c in result["controls"]:
            assert c["id"]
            assert c["title"]
            assert c["severity"]
            assert c["remediation"]
            assert isinstance(c["frameworks"], list)
