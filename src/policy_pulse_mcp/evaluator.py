"""Static manifest gate — no cluster required.

Accepts a Kubernetes manifest (dict or YAML string), extracts the pod spec,
and runs every catalog control's manifest_check predicate.
"""
from typing import Union

import yaml

from .frameworks import CATALOG
from .models import Engine, Violation


def _extract_pod_spec(manifest: dict) -> dict | None:
    kind = manifest.get("kind", "")
    spec = manifest.get("spec", {}) or {}

    if kind == "Pod":
        return spec
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"):
        return spec.get("template", {}).get("spec") or {}
    if kind == "CronJob":
        return (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec")
            or {}
        )
    # Fallback: if spec contains containers, treat it as a pod spec
    if spec.get("containers"):
        return spec
    return None


def gate(manifest: Union[dict, str]) -> list[Violation]:
    """Run all catalog checks against a manifest. Returns violations found."""
    if isinstance(manifest, str):
        manifest = yaml.safe_load(manifest)

    pod_spec = _extract_pod_spec(manifest)
    if pod_spec is None:
        return []

    meta = manifest.get("metadata", {}) or {}
    resource_name = meta.get("name", "unknown")
    resource_kind = manifest.get("kind", "unknown")
    namespace = meta.get("namespace")

    violations: list[Violation] = []
    for control in CATALOG:
        if control.manifest_check is None:
            continue
        if control.manifest_check(pod_spec):
            violations.append(
                Violation(
                    id=f"static-{control.id}-{namespace or 'cluster'}-{resource_name}",
                    engine=Engine.STATIC,
                    policy_name=control.id,
                    resource_name=resource_name,
                    resource_kind=resource_kind,
                    namespace=namespace,
                    message=f"Manifest violates control: {control.title}",
                    severity=control.severity,
                    framework_refs=list(control.frameworks),
                )
            )

    return violations
