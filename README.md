# Kavlotryx

Kavlotryx turns security scanner findings into owned, tracked work.

Scanners are good at finding problems and bad at getting them fixed. Every tool speaks its own format, two tools report the same CVE on the same image, a finding names an ARN but never a team, and a ticket gets closed by a person while the weakness is still there. Kavlotryx sits between your scanners and your ticket system and does the coordination work:

1. **Ingest** Prowler, Trivy and Wiz output (Issues and vulnerability CSV exports, wizcli JSON), DefectDojo findings (API v2), or any OCSF finding.
2. **Normalize** everything to [OCSF](https://schema.ocsf.io/) (Vulnerability, Compliance and Detection Finding).
3. **Deduplicate** with a stable fingerprint, across scanners and scan runs.
4. **Enrich** with cloud tags, GitHub CODEOWNERS and an image-to-repo map.
5. **Resolve the owner** with ordered rules. Every assignment keeps its evidence and a confidence value; weak ones are flagged for review.
6. **Group** findings that one change removes: one ticket for "upgrade openssl in payments-api", not twelve.
7. **Dispatch** one Jira issue per group, idempotently. Re-runs never create duplicates.
8. **Verify**: a work item closes only when a later scan no longer reports its findings, and reopens if they come back.
9. **Triage** what you won't fix: false positives and risk acceptances carry a written reason, need a second approver, and acceptances expire. The audit report turns all of it into a register with control checks and a SHA-256 digest.

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
kavlo ingest dojo-findings.json --scanner defectdojo   # GET /api/v2/findings/?related_fields=true
kavlo pull defectdojo          # or read DefectDojo directly, one scan per product (see below)
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
- **Vulnerabilities**: every finding once, with filters for severity, status, kind, scanner, owner, owner rule, confidence, fix availability, production tags, work item state, ticket, age, account and artifact; facet counts; sorting; CSV export (formula-safe). A *Work items* tab holds the tickets, with a proof-of-closure timeline per item. The *Triage* and *Audit report* tabs are described below; findings and work items also take notes.
- **Ownership**: owners, the rule ladder, the review queue, manual overrides, and the **Microsoft Graph** and **LeanIX** connectors with their mappings and a sync button. A *Leaders & engineers* tab maps open findings to people (see below).
- **Scanners**: freshness per scanner and scope, scan history, upload and verifier decisions.
- **Settings**: admins edit the remediation policy (confidence limit, due days, dispatch rules, production tags, stale-scan hours, the longest risk acceptance per severity, four eyes); changes are stored in the database and audited. Tracker, connector and token settings are shown as set or not set, never their values. The audit log is here too.

It follows your system's light or dark setting ("Solar Phosphor" dark, "Light Terminal Mode" light), with a toggle. The console is server-rendered with no build step and loads nothing from third-party hosts, under a strict Content-Security-Policy. Sessions are signed cookies that hold a hash of the token, never the token itself, and every form carries a CSRF token. Set `KAVLO_SESSION_SECRET` so sessions survive restarts.

To try it with sample data:

```bash
hack/demo-samples.sh --serve 8080   # Prowler, Trivy, Wiz and DefectDojo samples, Graph and LeanIX snapshots, triage
hack/serve-demo.sh 8080             # the small built-in example
```

Tokens are written to `.kavlotryx/demo-tokens`: an admin, a viewer and an analyst (`riley`), so you can propose a triage decision as the analyst and approve it as the admin.

### Ownership connectors

Two connectors add identity and application context. A sync copies what ownership needs into local tables; owner resolution reads only those tables, so a rebuild never calls an external API.

| Connector | What it resolves | Live mode | Rule |
|---|---|---|---|
| Microsoft Graph | A tag that names a person (`Owner=jd@acme.com`) → their Entra ID groups → a team via `connectors.graph.group_map` | `KAVLO_GRAPH_TENANT_ID`, `KAVLO_GRAPH_CLIENT_ID`, `KAVLO_GRAPH_CLIENT_SECRET`; app permissions `GroupMember.Read.All`, and `User.Read.All` for managers | 3, confidence 0.80 |
| LeanIX | An asset's app tag, image or resource name, or repository → an Application fact sheet → its team (`connectors.leanix.team_map`), or its responsible person through Graph | `KAVLO_LEANIX_HOST`, `KAVLO_LEANIX_TOKEN` (API token, read access) | 5, confidence 0.80 |

The full rule order is: manual override (1.0), team tag (0.9), Microsoft Graph person (0.8), CODEOWNERS (0.85), LeanIX application (0.8), pattern (0.75), account or registry default (0.5). Each connector can also read a JSON snapshot (`KAVLO_GRAPH_SNAPSHOT`, `KAVLO_LEANIX_SNAPSHOT`) for demos and air-gapped installs; see `examples/samples/config/`.

```bash
kavlo connectors sync all     # or graph / leanix; re-resolves owners afterwards
kavlo connectors status
```

The clients are tested against mocked HTTP only; they have not yet run against a live tenant or LeanIX workspace.

#### Leaders and engineers

The Microsoft Graph sync also reads the owners of each mapped Entra group and walks the `manager` chain above everyone it found (`connectors.graph.manager_levels`, default 3; managers are fetched with `$batch`). The *Leaders & engineers* tab under Ownership, and `GET /api/v1/people`, use that to map every open finding to people:

- **Engineers** see the findings *named* to them (the Graph person tag, the LeanIX responsible person, or a person tag on the asset) and their team's queue (every finding of the owner their group maps to).
- **Leaders** are group owners and anyone with reports. Their roll-up is every finding of the teams they lead and of everyone below them in the manager chain.
- Each person shows Critical and High counts, overdue work items and the oldest finding. A person page lists their findings and links to Vulnerabilities filtered to that person.
- Owners with no Entra people are listed as *reach nobody*, so the gap is visible.

This view only reads. It never changes an owner: owner resolution still uses group membership alone.

### DefectDojo as a source

If your team already runs DefectDojo, keep it. Kavlotryx reads its findings and adds what DefectDojo leaves to people: owners with evidence, one ticket per fix, and closure on scan proof.

```bash
export KAVLO_DEFECTDOJO_URL=https://defectdojo.example.com
export KAVLO_DEFECTDOJO_TOKEN=...              # an API v2 key; read-only use
kavlo pull defectdojo                          # every product, or --product NAME (repeat)
```

Each product becomes its own scan scope, `defectdojo:<product>`, so a product with nothing left open still proves its fixes. Findings with a CVE or GHSA become vulnerability findings; SAST, DAST and other rules become detection findings keyed by test type and rule. The product, product type, environment and DefectDojo tags become asset tags, so ownership patterns and the production priority bump work on them.

DefectDojo marks a false positive or an accepted risk as inactive. Kavlotryx doesn't treat that as a fix: those findings stay open and show up on the Triage page as suggestions, and a person decides. Mitigated findings count as fixed, which means you're trusting DefectDojo's reimport for that product; send the scanner output to Kavlotryx directly when you need scanner-grade proof. Duplicates and out-of-scope rows are skipped. The pull only sends GET requests and refuses a `next` link to another host.

### Triage and the audit report

Some findings won't be fixed, and the reason should be on record. A **false positive** says the scanner is wrong. A **risk acceptance** says the weakness is real but accepted for now: it needs compensating controls and an expiry date, at most `acceptance_max_days` for its highest severity (30 days for Critical by default).

An analyst or admin proposes a decision from a finding, from a work item (every open finding in it), or from a DefectDojo suggestion. An admin approves or rejects it, and with `triage_four_eyes` on (the default) that admin has to be someone else. Only an approved decision changes anything: its findings get the status `accepted` or `false_positive`, leave the open queues, and a work item with nothing else open closes its ticket as *Closed by triage*, with a comment that says it wasn't fixed. When an acceptance expires or someone revokes a decision, the findings are open again and the ticket reopens. A scan that stops reporting a triaged finding still marks it fixed, and if it comes back it returns under its decision.

Notes go on findings, work items and decisions. They're append-only, like the audit log.

The **audit report** (`/ui/triage/report`, `GET /api/v1/reports/triage`, `kavlo triage report`) covers a period and an optional owner: the risk-acceptance and false-positive registers, the decision log from the audit table, the notes, and six control checks (segregation of duties, expiry within policy, audit trail, status integrity, pending proposals, expiring soon). It downloads as JSON with a SHA-256 digest over the canonical JSON, or as a CSV register, and prints cleanly to PDF.

```bash
kavlo triage propose risk_acceptance --match CVE-2022-40897 --expires 2027-01-15 \
  --reason "Build-time only; upgrade waits for the base image" --controls "Isolated CI job"
kavlo triage approve 1          # as someone else
kavlo triage list
kavlo triage report --from 2026-10-01 --format csv --out register.csv
```

### REST API

```bash
export KAVLO_API_TOKENS="ci:ingest:$(openssl rand -hex 24),me:admin:$(openssl rand -hex 24)"
kavlo serve --host 0.0.0.0 --port 8080
curl -H "Authorization: Bearer $TOKEN" -F scanner=trivy -F file=@trivy.json http://localhost:8080/api/v1/scans
```

OpenAPI is served at `/docs`. Roles: `admin`, `analyst`, `viewer`, `ingest` (upload only, for CI). Triage lives under `/api/v1/triage/decisions` (propose, then `approve`, `reject` or `revoke`), notes under `/api/v1/notes/{finding|work_item|decision}/{id}`, and the DefectDojo pull at `POST /api/v1/scans/defectdojo/pull` (admin).

## Writing an adapter

An adapter is a class with a `parse(bytes) -> ParseResult` method that returns OCSF records. Register it under the `kavlotryx.adapters` entry-point group in your own package and `kavlo ingest --scanner yourtool` picks it up.

## What Kavlotryx does not do

It does not scan, it does not invent a new findings format, and it never changes your cloud resources or code.

## License

Apache-2.0.
