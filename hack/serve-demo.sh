#!/usr/bin/env bash
# Seed a demo database (two days of sample scans, fake tracker) and serve the API + console.
# Tokens are written to .kavlotryx/demo-tokens (git-ignored). Usage: hack/serve-demo.sh [port]. Sign in at http://127.0.0.1:<port>/ui
set -euo pipefail
PORT="${1:-${PORT:-8080}}"
cd "$(dirname "$0")/.."
KAVLO="${KAVLO:-.venv/bin/kavlo}"
DIR=.kavlotryx
mkdir -p "$DIR"
rm -f "$DIR/demo.db" "$DIR/demo-tracker.json"
export KAVLO_CONFIG_DIR=examples/config KAVLO_DATABASE_URL="sqlite:///$DIR/demo.db"
export KAVLO_TRACKER=fake KAVLO_FAKE_TRACKER_FILE="$DIR/demo-tracker.json"
S=examples/scans
q() { "$KAVLO" "$@" >/dev/null; }
q ingest $S/prowler-aws-day1.ocsf.json --scanner prowler
q ingest $S/trivy-payments-api-1.4.0.json --scanner trivy
q ingest $S/trivy-repo-payments-api.json --scanner trivy
q ingest $S/grype-payments-api-1.4.0.ocsf.json --scanner ocsf --scope grype:ghcr.io/acme/payments-api
q run
KEY=$(python3 -c "import json;d=json.load(open('$DIR/demo-tracker.json'));print(next(k for k,v in d['issues'].items() if 'openssl' in v['summary']))")
q tracker set-status "$KEY" done
q verify
q ingest $S/prowler-aws-day2.ocsf.json --scanner prowler
q ingest $S/trivy-payments-api-1.4.1.json --scanner trivy
q run
if [ ! -f "$DIR/demo-tokens" ]; then
  printf 'demo:admin:%s,viewer:viewer:%s\n' "$(openssl rand -hex 16)" "$(openssl rand -hex 16)" > "$DIR/demo-tokens"
  chmod 600 "$DIR/demo-tokens"
fi
export KAVLO_API_TOKENS="$(cat "$DIR/demo-tokens")"
echo "tokens in $DIR/demo-tokens"
exec "$KAVLO" serve --port "$PORT"
