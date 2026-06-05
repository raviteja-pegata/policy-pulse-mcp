import os


def build_azure_credential():
    cred_type = os.environ.get("AZURE_CREDENTIAL_TYPE", "auto").lower()

    if cred_type == "cli":
        from azure.identity import AzureCliCredential  # type: ignore[import-untyped]
        return AzureCliCredential()

    if cred_type == "managed_identity":
        from azure.identity import ManagedIdentityCredential  # type: ignore[import-untyped]
        return ManagedIdentityCredential(client_id=os.environ.get("AZURE_CLIENT_ID"))

    if cred_type == "service_principal":
        missing = [v for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET") if not os.environ.get(v)]
        if missing:
            raise ValueError(
                f"AZURE_CREDENTIAL_TYPE=service_principal requires: {', '.join(missing)}"
            )
        from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]
        return ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )

    from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
    return DefaultAzureCredential()
