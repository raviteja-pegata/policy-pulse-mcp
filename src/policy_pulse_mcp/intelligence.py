"""Risk summary, prioritization, and plain-language explanation."""
from .models import Engine, Severity, Violation

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def engine_label(engine: Engine) -> str:
    return {
        Engine.GATEKEEPER: "OPA Gatekeeper",
        Engine.KYVERNO: "Kyverno",
        Engine.AZURE_POLICY: "Azure Policy",
        Engine.STATIC: "Static Analysis",
    }.get(engine, engine.value)


def prioritize(violations: list[Violation]) -> list[Violation]:
    return sorted(violations, key=lambda v: _SEVERITY_ORDER.get(v.severity, 99))


def explain(violation: Violation) -> dict:
    from .frameworks import CATALOG

    control = None
    for c in CATALOG:
        if c.id == violation.policy_name or any(kw in violation.policy_name.lower() for kw in c.keywords):
            control = c
            break

    return {
        "violation_id": violation.id,
        "resource": f"{violation.resource_kind}/{violation.namespace or 'cluster'}/{violation.resource_name}",
        "engine": engine_label(violation.engine),
        "severity": violation.severity.value,
        "message": violation.message,
        "plain_english": _plain_english(violation, control),
        "framework_refs": [
            {
                "framework": ref.framework,
                "control_id": ref.control_id,
                "control_title": ref.control_title,
            }
            for ref in violation.framework_refs
        ],
        "remediation": (
            control.remediation
            if control
            else "Review the policy documentation for remediation guidance."
        ),
    }


def _plain_english(violation: Violation, control) -> str:
    ns = violation.namespace or "cluster-wide"
    name = control.title if control else violation.policy_name
    return (
        f"The {violation.resource_kind} '{violation.resource_name}' in namespace '{ns}' "
        f"violates '{name}'. {violation.message}"
    )


def build_risk_summary(violations: list[Violation]) -> dict:
    if not violations:
        return {
            "total_violations": 0,
            "severity_breakdown": {s.value: 0 for s in Severity},
            "engine_breakdown": {},
            "top_risks": [],
            "regulatory_impact": [],
            "recommendation": "No violations found. Cluster is compliant.",
        }

    severity_counts = {s.value: 0 for s in Severity}
    engine_counts: dict[str, int] = {}

    for v in violations:
        severity_counts[v.severity.value] += 1
        label = engine_label(v.engine)
        engine_counts[label] = engine_counts.get(label, 0) + 1

    top_risks = [
        {
            "violation_id": v.id,
            "policy": v.policy_name,
            "resource": f"{v.resource_kind}/{v.resource_name}",
            "namespace": v.namespace,
            "severity": v.severity.value,
            "engine": engine_label(v.engine),
        }
        for v in prioritize(violations)[:5]
    ]

    return {
        "total_violations": len(violations),
        "severity_breakdown": severity_counts,
        "engine_breakdown": engine_counts,
        "top_risks": top_risks,
        "regulatory_impact": _regulatory_impact(violations),
        "recommendation": _recommendation(severity_counts),
    }


def _regulatory_impact(violations: list[Violation]) -> list[str]:
    frameworks: set[str] = set()
    for v in violations:
        for ref in v.framework_refs:
            frameworks.add(ref.framework)
    return sorted(frameworks)


def _recommendation(severity_counts: dict) -> str:
    if severity_counts.get("critical", 0) > 0:
        n = severity_counts["critical"]
        return f"URGENT: {n} critical violation(s) require immediate remediation."
    if severity_counts.get("high", 0) > 0:
        n = severity_counts["high"]
        return f"HIGH PRIORITY: {n} high-severity violation(s) should be addressed promptly."
    if severity_counts.get("medium", 0) > 0:
        n = severity_counts["medium"]
        return f"MEDIUM: {n} medium-severity violation(s) should be scheduled for remediation."
    return "Cluster security posture is acceptable. Review low-severity items when convenient."
