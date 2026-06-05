"""Pod-spec predicates — each returns True when the spec violates the control."""
from typing import Any

Spec = dict[str, Any]


def privileged_container(spec: Spec) -> bool:
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        if c.get("securityContext", {}).get("privileged") is True:
            return True
    return False


def host_network(spec: Spec) -> bool:
    return spec.get("hostNetwork", False) is True


def host_pid(spec: Spec) -> bool:
    return spec.get("hostPID", False) is True


def host_ipc(spec: Spec) -> bool:
    return spec.get("hostIPC", False) is True


def runs_as_root(spec: Spec) -> bool:
    return spec.get("securityContext", {}).get("runAsNonRoot") is not True


def no_resource_limits(spec: Spec) -> bool:
    for c in spec.get("containers", []):
        limits = c.get("resources", {}).get("limits", {})
        if not limits.get("cpu") or not limits.get("memory"):
            return True
    return False


def writable_root_filesystem(spec: Spec) -> bool:
    for c in spec.get("containers", []):
        if c.get("securityContext", {}).get("readOnlyRootFilesystem") is not True:
            return True
    return False


def no_liveness_probe(spec: Spec) -> bool:
    for c in spec.get("containers", []):
        if not c.get("livenessProbe"):
            return True
    return False


def no_readiness_probe(spec: Spec) -> bool:
    for c in spec.get("containers", []):
        if not c.get("readinessProbe"):
            return True
    return False
