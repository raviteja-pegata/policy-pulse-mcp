import os

# Must be set before policy_pulse_mcp.server is imported so _build_adapters() picks up demo mode.
os.environ["POLICYPULSE_DEMO"] = "true"
