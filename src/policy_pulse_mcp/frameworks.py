"""Control catalog — 9 controls mapped to CIS Kubernetes, PCI-DSS, NIST 800-53, and SOC 2."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from . import checks
from .models import FrameworkRef, Severity

if TYPE_CHECKING:
    from .models import Violation


@dataclass
class ControlRule:
    id: str
    title: str
    severity: Severity
    frameworks: tuple[FrameworkRef, ...]
    remediation: str
    keywords: tuple[str, ...]
    manifest_check: Callable | None = None


def _f(framework: str, control_id: str, control_title: str) -> FrameworkRef:
    return FrameworkRef(framework=framework, control_id=control_id, control_title=control_title)


CATALOG: list[ControlRule] = [
    ControlRule(
        id="no-privileged-containers",
        title="No Privileged Containers",
        severity=Severity.CRITICAL,
        frameworks=(
            _f("CIS Kubernetes", "5.2.1", "Minimize the admission of privileged containers"),
            _f("PCI-DSS", "2.2.1", "Implement only one primary function per server component"),
            _f("NIST 800-53", "AC-6", "Least Privilege"),
            _f("SOC 2", "CC6.3", "Logical and Physical Access Controls"),
        ),
        remediation=(
            "Remove `securityContext.privileged: true` from all containers. "
            "Grant only the specific Linux capabilities your container needs instead."
        ),
        keywords=("privileged", "privilege"),
        manifest_check=checks.privileged_container,
    ),
    ControlRule(
        id="no-host-network",
        title="No Host Network Access",
        severity=Severity.HIGH,
        frameworks=(
            _f(
                "CIS Kubernetes",
                "5.2.4",
                "Minimize the admission of containers wishing to share the host network namespace",
            ),
            _f("PCI-DSS", "1.3.2", "Restrict inbound and outbound traffic to only that which is necessary"),
            _f("NIST 800-53", "SC-7", "Boundary Protection"),
        ),
        remediation=(
            "Remove `hostNetwork: true` from pod spec. "
            "Use Kubernetes Services and Ingress controllers for network access."
        ),
        keywords=("hostnetwork", "host-network", "host network"),
        manifest_check=checks.host_network,
    ),
    ControlRule(
        id="no-host-pid",
        title="No Host PID Namespace",
        severity=Severity.HIGH,
        frameworks=(
            _f(
                "CIS Kubernetes",
                "5.2.2",
                "Minimize the admission of containers wishing to share the host process ID namespace",
            ),
            _f("NIST 800-53", "AC-3", "Access Enforcement"),
        ),
        remediation="Remove `hostPID: true` from pod spec.",
        keywords=("hostpid", "host-pid", "host pid"),
        manifest_check=checks.host_pid,
    ),
    ControlRule(
        id="no-host-ipc",
        title="No Host IPC Namespace",
        severity=Severity.HIGH,
        frameworks=(
            _f(
                "CIS Kubernetes",
                "5.2.3",
                "Minimize the admission of containers wishing to share the host IPC namespace",
            ),
            _f("NIST 800-53", "AC-3", "Access Enforcement"),
        ),
        remediation="Remove `hostIPC: true` from pod spec.",
        keywords=("hostipc", "host-ipc", "host ipc"),
        manifest_check=checks.host_ipc,
    ),
    ControlRule(
        id="run-as-non-root",
        title="Run as Non-Root User",
        severity=Severity.HIGH,
        frameworks=(
            _f("CIS Kubernetes", "5.2.6", "Minimize the admission of root containers"),
            _f(
                "PCI-DSS",
                "7.1",
                "Limit access to system components to only those individuals whose job requires it",
            ),
            _f("NIST 800-53", "AC-6", "Least Privilege"),
            _f("SOC 2", "CC6.1", "Logical and Physical Access Controls"),
        ),
        remediation=(
            "Set `securityContext.runAsNonRoot: true` in pod spec. "
            "Also set `runAsUser` to a non-zero UID (e.g. 1000)."
        ),
        keywords=("runasnonroot", "runasroot", "non-root", "nonroot", "root"),
        manifest_check=checks.runs_as_root,
    ),
    ControlRule(
        id="resource-limits-required",
        title="Resource Limits Required",
        severity=Severity.MEDIUM,
        frameworks=(
            _f("CIS Kubernetes", "5.2.8", "Limit container resource usage"),
            _f("NIST 800-53", "SC-6", "Resource Availability"),
        ),
        remediation=(
            "Set `resources.limits.cpu` and `resources.limits.memory` on all containers "
            "to prevent noisy-neighbor and denial-of-service scenarios."
        ),
        keywords=("resource", "limits", "requests", "memory", "cpu"),
        manifest_check=checks.no_resource_limits,
    ),
    ControlRule(
        id="read-only-root-filesystem",
        title="Read-Only Root Filesystem",
        severity=Severity.MEDIUM,
        frameworks=(
            _f("CIS Kubernetes", "5.2.7", "Minimize the admission of containers with added capability"),
            _f("NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
            _f("SOC 2", "CC7.1", "Change Management"),
        ),
        remediation=(
            "Set `securityContext.readOnlyRootFilesystem: true` on all containers. "
            "Mount emptyDir or ConfigMap volumes for paths that need to be writable."
        ),
        keywords=("readonlyrootfilesystem", "readonly", "read-only", "writable", "rootfilesystem"),
        manifest_check=checks.writable_root_filesystem,
    ),
    ControlRule(
        id="liveness-probe-required",
        title="Liveness Probe Required",
        severity=Severity.LOW,
        frameworks=(
            _f("CIS Kubernetes", "5.1.1", "Ensure that the API server pod specification file permissions are set"),
        ),
        remediation=(
            "Add a `livenessProbe` to all containers. "
            "This allows Kubernetes to restart the container automatically if it becomes unhealthy."
        ),
        keywords=("liveness", "livenessprobe", "health-check"),
        manifest_check=checks.no_liveness_probe,
    ),
    ControlRule(
        id="readiness-probe-required",
        title="Readiness Probe Required",
        severity=Severity.LOW,
        frameworks=(
            _f("CIS Kubernetes", "5.1.1", "Ensure that the API server pod specification file permissions are set"),
        ),
        remediation=(
            "Add a `readinessProbe` to all containers. "
            "This prevents traffic from being routed to the container before it is ready."
        ),
        keywords=("readiness", "readinessprobe"),
        manifest_check=checks.no_readiness_probe,
    ),
]


def enrich(violation: Violation) -> list[FrameworkRef]:
    """Match a violation's policy name and message against the catalog keywords, return refs."""
    text = (violation.policy_name + " " + violation.message).lower()
    seen: set[tuple[str, str]] = set()
    refs: list[FrameworkRef] = []
    for control in CATALOG:
        if any(kw in text for kw in control.keywords):
            for ref in control.frameworks:
                key = (ref.framework, ref.control_id)
                if key not in seen:
                    seen.add(key)
                    refs.append(ref)
    return refs


def get_control(control_id: str) -> ControlRule | None:
    for c in CATALOG:
        if c.id == control_id:
            return c
    return None
