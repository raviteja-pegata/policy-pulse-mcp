#!/usr/bin/env bash
# Sets up a Kind cluster with Gatekeeper + Kyverno + non-compliant workloads for demo/testing.
set -euo pipefail

CLUSTER_NAME="policy-pulse-demo"

echo "==> Creating Kind cluster: $CLUSTER_NAME"
kind create cluster --name "$CLUSTER_NAME" --wait 60s

echo "==> Installing OPA Gatekeeper"
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml
kubectl wait --for=condition=Available deployment/gatekeeper-controller-manager \
  -n gatekeeper-system --timeout=120s

echo "==> Installing Kyverno"
kubectl apply -f https://github.com/kyverno/kyverno/releases/download/v1.12.0/install.yaml
kubectl wait --for=condition=Available deployment/kyverno-admission-controller \
  -n kyverno --timeout=120s

echo "==> Applying Gatekeeper policies"
kubectl apply -f demo-cluster/gatekeeper-policies.yaml
sleep 10  # allow webhook to register

echo "==> Applying Kyverno policies"
kubectl apply -f demo-cluster/kyverno-policies.yaml

echo "==> Deploying non-compliant workloads"
kubectl apply -f demo-cluster/non-compliant-workloads.yaml || true  # expected to be rejected/warned

echo ""
echo "==> Cluster ready. Run the live server with:"
echo "    make live-server"
echo ""
echo "==> To tear down:"
echo "    make cluster-down"
