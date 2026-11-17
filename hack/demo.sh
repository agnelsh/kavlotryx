#!/usr/bin/env bash
# End-to-end demo with the local fake tracker: two days of scans, tickets filed,
# then closed only where a scan proves the fix.
set -euo pipefail
cd "$(dirname "$0")/.."
KAVLO="${KAVLO:-.venv/bin/kavlo}"
WORK="$(mktemp -d)"
export KAVLO_CONFIG_DIR=examples/config
export KAVLO_DATABASE_URL="sqlite:///$WORK/demo.db"
export KAVLO_TRACKER=fake KAVLO_FAKE_TRACKER_FILE="$WORK/tracker.json"
S=examples/scans

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "Day 1: ingest Prowler, Trivy (image + repo) and a second scanner"
$KAVLO ingest $S/prowler-aws-day1.ocsf.json --scanner prowler
$KAVLO ingest $S/trivy-payments-api-1.4.0.json --scanner trivy
$KAVLO ingest $S/trivy-repo-payments-api.json --scanner trivy
$KAVLO ingest $S/grype-payments-api-1.4.0.ocsf.json --scanner ocsf --scope grype:ghcr.io/acme/payments-api

step "Rebuild owners and groups"
$KAVLO rebuild
$KAVLO findings

step "Why does the zlib finding belong to platform?"
ZLIB_ID=$(sqlite3 "$WORK/demo.db" "select id from findings where vuln_id='CVE-2023-45853' limit 1" 2>/dev/null || echo 7)
$KAVLO owner explain "$ZLIB_ID"

step "Dry run, then dispatch (twice: the second run must create nothing)"
$KAVLO dispatch --dry-run
$KAVLO dispatch
$KAVLO dispatch
$KAVLO tracker list

step "Someone marks the openssl ticket Done without a fix"
KEY=$(python3 -c "import json,sys;d=json.load(open('$WORK/tracker.json'));print(next(k for k,v in d['issues'].items() if 'openssl' in v['summary']))")
$KAVLO tracker set-status "$KEY" done
$KAVLO verify

step "Day 2: new scans (bucket fixed, one SSH rule fixed, image 1.4.1 without openssl CVEs)"
$KAVLO ingest $S/prowler-aws-day2.ocsf.json --scanner prowler
$KAVLO ingest $S/trivy-payments-api-1.4.1.json --scanner trivy
$KAVLO run
$KAVLO workitems

step "Grype rescans 1.4.1: now the openssl fix is proven"
echo '[]' > "$WORK/grype-empty.json"
$KAVLO ingest "$WORK/grype-empty.json" --scanner ocsf --scope grype:ghcr.io/acme/payments-api
$KAVLO run
$KAVLO workitems
$KAVLO tracker list

step "Report"
$KAVLO report
echo; echo "demo data in $WORK"
