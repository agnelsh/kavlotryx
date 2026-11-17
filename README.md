# Kavlotryx

Kavlotryx turns security scanner findings into owned, tracked work.

Scanners are good at finding problems and bad at getting them fixed. Every tool speaks its own format, two tools report the same CVE on the same image, a finding names an ARN but never a team, and a ticket gets closed by a person while the weakness is still there. Kavlotryx sits between your scanners and your ticket system and does the coordination work:

1. **Ingest** Prowler, Trivy and Wiz output (Issues and vulnerability CSV exports, wizcli JSON), or any OCSF finding.
2. **Normalize** everything to [OCSF](https://schema.ocsf.io/) (Vulnerability, Compliance and Detection Finding).
3. **Deduplicate** with a stable fingerprint, across scanners and scan runs.
4. **Enrich** with cloud tags, GitHub CODEOWNERS and an image-to-repo map.
5. **Resolve the owner** with ordered rules. Every assignment keeps its evidence and a confidence value; weak ones are flagged for review.
6. **Group** findings that one change removes: one ticket for "upgrade openssl in payments-api", not twelve.
7. **Dispatch** one Jira issue per group, idempotently. Re-runs never create duplicates.
8. **Verify**: a work item closes only when a later scan no longer reports its findings, and reopens if they come back.

Kavlotryx is Apache-2.0 licensed and self-hosted: your vulnerability data stays with you.

> Status: v0.1 in development.

## Try it in two minutes

No Jira needed: the default tracker is a local fake that writes to `.kavlotryx/fake-tracker.json`.

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
hack/demo.sh
```

The demo ingests a day of Prowler and Trivy output, files tickets, then ingests the next day's scans and shows which tickets Kavlotryx closed, kept open or left alone, and why.

### On third-party data

`hack/demo-samples.sh` runs the same flow on real-format Prowler, Trivy and Wiz files from DefectDojo's test suite, downloaded at a pinned commit and checked by SHA-256. It includes a 98-issue Wiz export from Wiz's demo tenant (97 open issues become 39 tickets) and three days of Prowler runs that show deduplication across Prowler versions and tickets that close only on scan proof. See [examples/samples](examples/samples/README.md).

## Ownership you can check

Wrong owners are the fastest way to make teams ignore security tickets, so Kavlotryx always shows its work:

```console
$ kavlo -c examples/config owner explain 7
owner platform by rule codeowners (source github_codeowners), confidence 0.85
evidence: {"repo": "github.com/acme/payments-api", "path": "Dockerfile", "line": 3, "pattern": "/Dockerfile", "handle": "@acme/platform", ...}
  1. override               no     no manual override for this finding or asset
  2. tag                    no     asset has no tags
  3. codeowners             match  github.com/acme/payments-api CODEOWNERS line 3: /Dockerfile @acme/platform
```

Rules run in this order, first match wins:

| Order | Rule | Confidence |
|---|---|---|
| 1 | Manual override (`kavlo owner set` or the console) | 1.0 |
| 2 | Resource tag that names a team (`owner`, `team`, configurable) | 0.9 |
| 3 | Microsoft Graph: a tag names a person, their Entra group names the team | 0.8 |
| 4 | GitHub CODEOWNERS for the file or Dockerfile | 0.85 |
| 5 | LeanIX: the asset belongs to an application, its team owns it | 0.8 |
| 6 | Pattern rule in `ownership.yaml` (asset, name, rule or resource type) | 0.75 |
| 7 | Cloud account or registry default | 0.5 (needs review) |
| — | Fallback owner | 0.0 |

## Using it

```bash
export KAVLO_CONFIG_DIR=examples/config            # ownership.yaml, policy.yaml
export KAVLO_DATABASE_URL=sqlite:///./kavlotryx.db  # or postgresql+psycopg://...

kavlo ingest prowler-output.ocsf.json --scanner prowler
kavlo ingest trivy-image.json --scanner trivy
kavlo ingest trivy-fs.json --scanner trivy --scope trivy:checkout-service   # directory scans need a scope
kavlo ingest wiz-issues.csv --scanner wiz      # Wiz Issues or Vulnerability CSV export, or wizcli JSON
kavlo run --dry-run            # rebuild owners and groups, show the tickets it would file
kavlo run                      # file and verify tickets
kavlo workitems
kavlo findings --review        # owners below the confidence limit
kavlo report                   # counts and success metrics
```

To file real Jira Cloud issues, set `KAVLO_JIRA_URL`, `KAVLO_JIRA_EMAIL` and `KAVLO_JIRA_TOKEN`, and give each owner a `jira_project` in `ownership.yaml`. Credentials are read from the environment only.

### Web console

`kavlo serve` also serves a console at `/ui`, signed in with the same API tokens (admin, analyst and viewer roles; ingest tokens are upload-only). It has five menus:

- **Dashboard**: the pipeline status (stages, scanner freshness, connector syncs, tracker, owner review) and a dashboard per persona. *Vulnerability analyst*: severity and scanner mix, review queue, newest findings. *Engineering team lead*: only their team's work, by due date. *Cloud platform owner*: the fixes that remove the most findings, and the packages and rules that spread widest. *Security manager*: the success measures against their targets, SLA and age, progress by owner. *Change manager*: fixes on production-tagged resources. Each person's choice is remembered; `KAVLO_PERSONAS` sets defaults per token.
- **Vulnerabilities**: every finding once, with filters for severity, status, kind, scanner, owner, owner rule, confidence, fix availability, production tags, work item state, ticket, age, account and artifact; facet counts; sorting; CSV export (formula-safe). A *Work items* tab holds the tickets, with a proof-of-closure timeline per item.
- **Ownership**: owners, the rule ladder, the review queue, manual overrides, and the **Microsoft Graph** and **LeanIX** connectors with their mappings and a sync button.
- **Scanners**: freshness per scanner and scope, scan history, upload and verifier decisions.
- **Settings**: admins edit the remediation policy (confidence limit, due days, dispatch rules, production tags, stale-scan hours); changes are stored in the database and audited. Tracker, connector and token settings are shown as set or not set, never their values. The audit log is here too.

It follows your system's light or dark setting ("Solar Phosphor" dark, "Light Terminal Mode" light), with a toggle. The console is server-rendered with no build step and loads nothing from third-party hosts, under a strict Content-Security-Policy. Sessions are signed cookies that hold a hash of the token, never the token itself, and every form carries a CSRF token. Set `KAVLO_SESSION_SECRET` so sessions survive restarts.

To try it with sample data:

```bash
hack/demo-samples.sh --serve 8080   # Prowler, Trivy and Wiz samples, Graph and LeanIX snapshots
hack/serve-demo.sh 8080             # the small built-in example
```

Tokens are written to `.kavlotryx/demo-tokens`.

### Ownership connectors

Two connectors add identity and application context. A sync copies what ownership needs into local tables; owner resolution reads only those tables, so a rebuild never calls an external API.

| Connector | What it resolves | Live mode | Rule |
|---|---|---|---|
| Microsoft Graph | A tag that names a person (`Owner=jd@acme.com`) → their Entra ID groups → a team via `connectors.graph.group_map` | `KAVLO_GRAPH_TENANT_ID`, `KAVLO_GRAPH_CLIENT_ID`, `KAVLO_GRAPH_CLIENT_SECRET`; app permission `GroupMember.Read.All` | 3, confidence 0.80 |
| LeanIX | An asset's app tag, image or resource name, or repository → an Application fact sheet → its team (`connectors.leanix.team_map`), or its responsible person through Graph | `KAVLO_LEANIX_HOST`, `KAVLO_LEANIX_TOKEN` (API token, read access) | 5, confidence 0.80 |

The full rule order is: manual override (1.0), team tag (0.9), Microsoft Graph person (0.8), CODEOWNERS (0.85), LeanIX application (0.8), pattern (0.75), account or registry default (0.5). Each connector can also read a JSON snapshot (`KAVLO_GRAPH_SNAPSHOT`, `KAVLO_LEANIX_SNAPSHOT`) for demos and air-gapped installs; see `examples/samples/config/`.

```bash
kavlo connectors sync all     # or graph / leanix; re-resolves owners afterwards
kavlo connectors status
```

The clients are tested against mocked HTTP only; they have not yet run against a live tenant or LeanIX workspace.

### REST API

```bash
export KAVLO_API_TOKENS="ci:ingest:$(openssl rand -hex 24),me:admin:$(openssl rand -hex 24)"
kavlo serve --host 0.0.0.0 --port 8080
curl -H "Authorization: Bearer $TOKEN" -F scanner=trivy -F file=@trivy.json http://localhost:8080/api/v1/scans
```

OpenAPI is served at `/docs`. Roles: `admin`, `analyst`, `viewer`, `ingest` (upload only, for CI).

## Writing an adapter

An adapter is a class with a `parse(bytes) -> ParseResult` method that returns OCSF records. Register it under the `kavlotryx.adapters` entry-point group in your own package and `kavlo ingest --scanner yourtool` picks it up.

## What Kavlotryx does not do

It does not scan, it does not invent a new findings format, and it never changes your cloud resources or code.

## License

Apache-2.0.
