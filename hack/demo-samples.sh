#!/usr/bin/env bash
# Demo on third-party sample data: DefectDojo's Prowler, Trivy and Wiz test files.
# Three "days" of Prowler runs on one AWS account show deduplication across
# Prowler versions and scan-verified closure. Usage: hack/demo-samples.sh [--serve PORT]
set -euo pipefail
cd "$(dirname "$0")/.."
hack/fetch-samples.sh
KAVLO="${KAVLO:-.venv/bin/kavlo}"
S=examples/samples/defectdojo
DIR=.kavlotryx
mkdir -p "$DIR"
rm -f "$DIR/samples.db" "$DIR/samples-tracker.json"
export KAVLO_CONFIG_DIR=examples/samples/config KAVLO_DATABASE_URL="sqlite:///$DIR/samples.db"
export KAVLO_TRACKER=fake KAVLO_FAKE_TRACKER_FILE="$DIR/samples-tracker.json"
export KAVLO_GRAPH_SNAPSHOT=examples/samples/config/graph-snapshot.json
export KAVLO_LEANIX_SNAPSHOT=examples/samples/config/leanix-snapshot.json
export KAVLO_PERSONAS="${KAVLO_PERSONAS:-demo=security_manager,viewer=team_lead}"
ACCOUNT=prowler:aws:123456789012   # pass the scope: an empty scan cannot reveal it
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "Day 1: Prowler finds 3 risky IAM roles; Trivy scans an image and a service directory"
$KAVLO ingest $S/aws_prowler_v3plus/many_vuln.ocsf.json --scanner prowler --scope $ACCOUNT
$KAVLO ingest $S/trivy/scheme_2_many_vulns.json --scanner trivy
$KAVLO ingest $S/trivy/misconfigurations_and_secrets.json --scanner trivy --scope trivy:checkout-service

step "Day 1: a Wiz Issues export (Azure + Kubernetes, Wiz demo tenant) and a wizcli image scan"
$KAVLO ingest $S/wiz/multiple_findings.csv --scanner wiz
$KAVLO ingest $S/wizcli_img/wizcli_img_many_vul.json --scanner wiz

step "Prowler upgraded to 4.5 and run again: the new output format adds no duplicates"
$KAVLO ingest $S/aws_prowler_v3plus/many_vuln_after_4_5_0.ocsf.json --scanner prowler --scope $ACCOUNT

step "Sync ownership connectors (Microsoft Graph and LeanIX snapshots)"
$KAVLO connectors sync all --no-rebuild

step "Owners, groups and tickets"
$KAVLO run
$KAVLO workitems

step "Day 2: two IAM roles fixed; one remains. The rebuilt image has no vulnerabilities"
$KAVLO ingest $S/aws_prowler_v3plus/one_vuln.ocsf.json --scanner prowler --scope $ACCOUNT
$KAVLO ingest $S/wizcli_img/wizcli_img_zero_vul.json --scanner wiz
$KAVLO run

step "Day 3: Prowler reports nothing; the last IAM ticket closes on scan proof"
$KAVLO ingest $S/aws_prowler_v3plus/no_vuln.ocsf.json --scanner prowler --scope $ACCOUNT
$KAVLO run
$KAVLO workitems
$KAVLO tracker list
$KAVLO report

if [ "${1:-}" = "--serve" ]; then
  [ -f "$DIR/demo-tokens" ] || printf 'demo:admin:%s,viewer:viewer:%s\n' "$(openssl rand -hex 16)" "$(openssl rand -hex 16)" > "$DIR/demo-tokens"
  chmod 600 "$DIR/demo-tokens"
  export KAVLO_API_TOKENS="$(cat "$DIR/demo-tokens")"
  echo "console: http://127.0.0.1:${2:-8080}/ui (tokens in $DIR/demo-tokens)"
  exec "$KAVLO" serve --port "${2:-8080}"
fi
