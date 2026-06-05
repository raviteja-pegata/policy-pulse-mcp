"""Auto-detect in-cluster vs kubeconfig vs workload identity connection."""
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


def load_kube_config_for_context(context: str) -> None:
    # "resourceGroup/clusterName" → workload identity (no kubeconfig needed).
    # Any other string is treated as a kubeconfig context name.
    if "/" in context and not context.startswith("http"):
        resource_group, _, cluster_name = context.partition("/")
        _load_workload_identity(resource_group.strip(), cluster_name.strip())
        return

    try:
        from kubernetes import config  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "kubernetes package not installed. Run: pip install policy-pulse-mcp[kubernetes]"
        ) from exc

    kubeconfig = os.environ.get("KUBECONFIG", "~/.kube/config")
    config.load_kube_config(config_file=os.path.expanduser(kubeconfig), context=context)


def _load_workload_identity(resource_group: str, cluster_name: str) -> None:
    """Build a kubernetes client from a managed identity token — no kubeconfig file required.

    Flow:
      1. Get a management-plane token → call listClusterUserCredential to extract the
         cluster's API server URL and CA certificate (we ignore the exec credential in
         that kubeconfig and substitute our own Azure AD token).
      2. Get an AKS-scoped token (audience 6dae42f8-...) from the same credential.
      3. Build a kubernetes.client.Configuration from those two pieces and set it as default.

    Pre-requisites on each target cluster:
      - AAD integration enabled (default for new AKS clusters).
      - The managed identity must have 'Azure Kubernetes Service RBAC Reader' (Azure RBAC mode)
        OR a ClusterRoleBinding to 'view' pointing at the identity's client ID (local RBAC mode).
    """
    import base64
    import json
    import tempfile
    import urllib.request

    try:
        import yaml  # bundled with the kubernetes package via pyyaml
        from kubernetes import client  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "kubernetes package not installed. Run: pip install policy-pulse-mcp[kubernetes]"
        ) from exc

    from .credentials import build_azure_credential

    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not sub_id:
        raise RuntimeError(
            "AZURE_SUBSCRIPTION_ID must be set for workload identity cluster auth "
            f"(needed to look up {resource_group}/{cluster_name})"
        )

    credential = build_azure_credential()

    # Step 1 — fetch the kubeconfig from the Azure management API.
    # We only use it for the server URL and the CA certificate; the exec-based
    # AAD credential inside the kubeconfig is replaced with our own token below.
    mgmt_token = credential.get_token("https://management.azure.com/.default").token
    cred_url = (
        f"https://management.azure.com/subscriptions/{sub_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.ContainerService/managedClusters/{cluster_name}"
        f"/listClusterUserCredential?api-version=2022-11-01"
    )
    req = urllib.request.Request(
        cred_url,
        method="POST",
        headers={"Authorization": f"Bearer {mgmt_token}", "Content-Type": "application/json"},
        data=b"{}",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        cred_data = json.loads(resp.read())

    raw_kubeconfig = base64.b64decode(cred_data["kubeconfigs"][0]["value"]).decode()
    kube = yaml.safe_load(raw_kubeconfig)
    cluster_block = kube["clusters"][0]["cluster"]
    server = cluster_block["server"]
    ca_b64 = cluster_block.get("certificate-authority-data", "")

    # Step 2 — get a token scoped to the AKS AAD server application.
    # 6dae42f8-4368-4678-94ff-3960e28e3630 is the well-known Azure Kubernetes Service
    # AAD server app ID. AKS API servers validate bearer tokens against this audience.
    aks_token = credential.get_token("6dae42f8-4368-4678-94ff-3960e28e3630/.default").token

    # Step 3 — wire up the kubernetes client.
    configuration = client.Configuration()
    configuration.host = server
    configuration.api_key["authorization"] = aks_token
    configuration.api_key_prefix["authorization"] = "Bearer"

    if ca_b64:
        # Write CA cert to a temp file; the kubernetes client takes a file path, not bytes.
        ca_bytes = base64.b64decode(ca_b64)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as f:
            f.write(ca_bytes)
            configuration.ssl_ca_cert = f.name
    else:
        # No CA data in the kubeconfig — disable verification and log a warning.
        import logging
        logging.getLogger(__name__).warning(
            "No CA certificate found for %s/%s — TLS verification disabled",
            resource_group, cluster_name,
        )
        configuration.verify_ssl = False

    client.Configuration.set_default(configuration)
