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
export KAVLO_SERVICENOW_SNAPSHOT=examples/samples/config/servicenow-snapshot.json
# Threat intelligence: CISA KEV and FIRST EPSS entries for the sample CVEs, copied from the public feeds
export KAVLO_KEV_SNAPSHOT=examples/samples/config/kev-snapshot.json
export KAVLO_EPSS_SNAPSHOT=examples/samples/config/epss-snapshot.json
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

step "Day 1: a DefectDojo findings export (API v2, made-up product payments-checkout)"
$KAVLO ingest examples/scans/defectdojo-payments-checkout.json --scanner defectdojo

step "Prowler upgraded to 4.5 and run again: the new output format adds no duplicates"
$KAVLO ingest $S/aws_prowler_v3plus/many_vuln_after_4_5_0.ocsf.json --scanner prowler --scope $ACCOUNT

step "Sync connectors: Microsoft Graph, LeanIX and ServiceNow CMDB snapshots; CISA KEV and EPSS"
$KAVLO connectors sync all --no-rebuild

step "Owners, groups and tickets"
$KAVLO run
$KAVLO workitems

step "Triage: an analyst proposes, a second person approves (four eyes)"
PY="${PYTHON:-.venv/bin/python}"
EXP=$("$PY" -c 'import datetime; print(datetime.date.today() + datetime.timedelta(days=60))')
$KAVLO triage propose false_positive --match "defectdojo:ZAP Scan/CWE-693" --as cli:riley \
  --reason "DefectDojo marks this false positive: the CDN sets the CSP header, ZAP scanned the origin"
$KAVLO triage approve 1 --note "Checked the CDN response headers"
$KAVLO triage propose risk_acceptance --match CVE-2022-40897 --as cli:riley --expires "$EXP" \
  --reason "setuptools is only used at build time; the upgrade waits for the base image refresh" \
  --controls "Build runs in an isolated CI job with no network to production" --reference CHG-1042
$KAVLO triage approve 2
$KAVLO triage propose false_positive --match "defectdojo:Semgrep JSON Report/python.lang.security.audit.formatted-sql-query" \
  --as cli:riley --reason "The formatted part is a constant table name, not user input"
$KAVLO triage note decision 3 "Asked the payments team to confirm the table name never comes from a request"
$KAVLO run
$KAVLO triage list

step "Day 2: two IAM roles fixed; one remains. The rebuilt image has no vulnerabilities"
$KAVLO ingest $S/aws_prowler_v3plus/one_vuln.ocsf.json --scanner prowler --scope $ACCOUNT
$KAVLO ingest $S/wizcli_img/wizcli_img_zero_vul.json --scanner wiz
$KAVLO ingest examples/scans/defectdojo-payments-checkout-day2.json --scanner defectdojo
$KAVLO run

step "Day 3: Prowler reports nothing; the last IAM ticket closes on scan proof"
$KAVLO ingest $S/aws_prowler_v3plus/no_vuln.ocsf.json --scanner prowler --scope $ACCOUNT
$KAVLO run
$KAVLO workitems
$KAVLO tracker list
$KAVLO report

if [ "${1:-}" = "--serve" ]; then
  [ -f "$DIR/demo-tokens" ] || printf 'demo:admin:%s,viewer:viewer:%s\n' "$(openssl rand -hex 16)" "$(openssl rand -hex 16)" > "$DIR/demo-tokens"
  # an analyst proposes triage decisions; the demo admin approves them (four eyes)
  grep -q ':analyst:' "$DIR/demo-tokens" || sed -i.bak "s/\$/,riley:analyst:$(openssl rand -hex 16)/" "$DIR/demo-tokens"
  rm -f "$DIR/demo-tokens.bak"
  chmod 600 "$DIR/demo-tokens"
  export KAVLO_API_TOKENS="$(cat "$DIR/demo-tokens")"
  PORT="${2:-8080}"
  if [ "${KAVLO_DEMO_SSO:-1}" = "1" ]; then
    # Single sign-on against a development-only identity provider on localhost (hack/dev_idp.py).
    IDP_PORT=$((PORT + 2))
    export KAVLO_OIDC_ISSUER="http://localhost:$IDP_PORT" KAVLO_OIDC_CLIENT_ID=kavlotryx-demo
    export KAVLO_OIDC_CLIENT_SECRET="dev-only-secret" KAVLO_OIDC_LABEL="the dev identity provider"
    export KAVLO_OIDC_REDIRECT_URL="http://localhost:$PORT/ui/sso/callback"
    export KAVLO_OIDC_ROLE_MAP="admin=kavlotryx-admins,analyst=kavlotryx-analysts,viewer=all-staff"
    "${PYTHON:-.venv/bin/python}" hack/dev_idp.py "$IDP_PORT" &
    IDP_PID=$!
    trap 'kill $IDP_PID 2>/dev/null' EXIT INT TERM
  fi
  echo "console: http://localhost:$PORT/ui (tokens in $DIR/demo-tokens; or sign in with the dev identity provider)"
  "$KAVLO" serve --port "$PORT"
fi
