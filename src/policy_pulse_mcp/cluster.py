"""Auto-detect in-cluster vs kubeconfig connection."""
import os


def load_kube_config() -> None:
    """Load kubernetes config, preferring in-cluster when KUBERNETES_SERVICE_HOST is set."""
    try:
        from kubernetes import config  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "kubernetes package not installed. Run: pip install policy-pulse-mcp[kubernetes]"
        ) from exc

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        config.load_incluster_config()
    else:
        kubeconfig = os.environ.get("KUBECONFIG", "~/.kube/config")
        config.load_kube_config(config_file=os.path.expanduser(kubeconfig))
