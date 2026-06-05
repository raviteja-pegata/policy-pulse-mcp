PYTHON   ?= .venv/bin/python
PIP      ?= .venv/bin/pip
PYTEST   ?= .venv/bin/pytest
RUFF     ?= .venv/bin/ruff

.PHONY: install install-all test test-core test-integration test-cov \
        demo-server live-server lint fmt build publish-test publish \
        cluster-up cluster-down

install:
	$(PIP) install -e ".[dev]"

install-all:
	$(PIP) install -e ".[all,dev]"

# ── Tests ────────────────────────────────────────────────────────────────────

test:
	$(PYTEST) tests/

test-core:
	$(PYTEST) tests/test_core.py -v

test-integration:
	$(PYTEST) tests/test_integration.py -v

test-cov:
	$(PYTEST) tests/ --cov=src/policy_pulse_mcp --cov-report=term-missing

# ── Run ──────────────────────────────────────────────────────────────────────

demo-server:
	POLICYPULSE_DEMO=true $(PYTHON) -m policy_pulse_mcp.server

live-server:
	$(PYTHON) -m policy_pulse_mcp.server

# ── Code Quality ─────────────────────────────────────────────────────────────

lint:
	$(RUFF) check src/ tests/

fmt:
	$(RUFF) format src/ tests/

# ── Package ───────────────────────────────────────────────────────────────────

build:
	$(PYTHON) -m build

publish-test:
	$(PYTHON) -m twine upload --repository testpypi dist/*

publish:
	$(PYTHON) -m twine upload dist/*

# ── Local k8s cluster ────────────────────────────────────────────────────────

cluster-up:
	bash scripts/setup-demo-cluster.sh

cluster-down:
	kind delete cluster --name policy-pulse-demo
