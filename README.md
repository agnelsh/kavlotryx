# Kavlotryx

Kavlotryx turns security scanner findings into owned, tracked work.

Scanners are good at finding problems and bad at getting them fixed. Every tool speaks its own format. Two tools report the same CVE on the same image. A finding names an ARN but never a team. And a ticket gets closed while the weakness is still there. Kavlotryx sits between your scanners and your ticket system and does that coordination work:

1. **Ingest** Prowler, Trivy and Wiz output (Issues and vulnerability CSV exports, wizcli JSON), DefectDojo findings (API v2), or any OCSF finding.
2. **Normalize** everything to [OCSF](https://schema.ocsf.io/): Vulnerability, Compliance and Detection Findings.
3. **Deduplicate** with a stable fingerprint, across scanners and scan runs.
4. **Enrich** with cloud tags, GitHub CODEOWNERS and an image-to-repo map.
5. **Resolve the owner** with ordered rules. Every assignment keeps its evidence and a confidence score, and weak ones go to a review queue.
6. **Group** the findings that one change removes: one ticket for "upgrade openssl in payments-api", not twelve.
7. **Dispatch** one Jira issue per group. Running it again never creates a duplicate.
8. **Verify** before closing: a work item closes only when a later scan stops reporting its findings, and it reopens if they come back.
9. **Triage** what you won't fix. False positives and risk acceptances need a written reason and a second approver, and acceptances expire. The audit report turns all of it into a register with control checks and a SHA-256 digest.

Kavlotryx is Apache-2.0 licensed and self-hosted, so your vulnerability data stays with you.

> Status: v0.1, in development.

## Try it in two minutes

You don't need Jira. The default tracker is a local fake that writes to `.kavlotryx/fake-tracker.json`.

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
hack/demo.sh
```

The demo ingests a day of Prowler and Trivy output and files tickets. Then it ingests the next day's scans and shows which tickets closed, which stayed open, which were left alone, and why.

### On third-party data

`hack/demo-samples.sh` runs the same flow on real-format Prowler, Trivy and Wiz files from DefectDojo's test suite. The script downloads them at a pinned commit and checks each one against a SHA-256 sum. The set includes a 98-issue Wiz export from Wiz's demo tenant (97 open issues become 39 tickets), and three days of Prowler runs that show deduplication across Prowler versions and tickets that only close on scan proof. See [examples/samples](examples/samples/README.md).

## Ownership you can check

Nothing makes teams ignore security tickets faster than tickets sent to the wrong team. So Kavlotryx always shows how it picked an owner:

```console
$ kavlo -c examples/config owner explain 7
owner platform by rule codeowners (source github_codeowners), confidence 0.85
evidence: {"repo": "github.com/acme/payments-api", "path": "Dockerfile", "line": 3, "pattern": "/Dockerfile", "handle": "@acme/platform", ...}
  1. override               no     no manual override for this finding or asset
  2. tag                    no     asset has no tags
  3. codeowners             match  github.com/acme/payments-api CODEOWNERS line 3: /Dockerfile @acme/platform
```

The rules run in this order, and the first match wins:

| Order | Rule | Confidence |
|---|---|---|
| 1 | Manual override (`kavlo owner set` or the console) | 1.0 |
| 2 | Resource tag that names a team (`owner`, `team`, configurable) | 0.9 |
| 3 | Microsoft Graph: a tag names a person, and their Entra group names the team | 0.8 |
| 4 | GitHub CODEOWNERS for the file or Dockerfile | 0.85 |
| 5 | LeanIX: the asset belongs to an application, and its team owns it | 0.8 |
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

To file real Jira Cloud issues, set `KAVLO_JIRA_URL`, `KAVLO_JIRA_EMAIL` and `KAVLO_JIRA_TOKEN`, and give each owner a `jira_project` in `ownership.yaml`. Credentials only ever come from the environment.

### Web console

`kavlo serve` also serves a console at `/ui`. People sign in with their organization account through OIDC single sign-on (see below), or with an API token (admin, analyst and viewer roles; ingest tokens can only upload). It has five menus:

- **Dashboard**: pipeline status (stages, scanner freshness, connector syncs, tracker, owner review) and a dashboard for each persona.
  - *Vulnerability analyst*: severity and scanner mix, the review queue, the newest findings.
  - *Engineering team lead*: only their team's work, by due date.
  - *Cloud platform owner*: the fixes that remove the most findings, and the packages and rules that spread widest.
  - *Security manager*: success measures against their targets, SLA and age, progress by owner.
  - *Change manager*: fixes on production-tagged resources.

  The console remembers each person's choice, and `KAVLO_PERSONAS` sets a default per token.
- **Vulnerabilities**: every finding once, with filters for severity, status, kind, scanner, owner, owner rule, confidence, fix availability, production tags, work item state, ticket, age, account and artifact. It has facet counts, sorting and a formula-safe CSV export. The *Work items* tab holds the tickets, each with a proof-of-closure timeline. The *Triage* and *Audit report* tabs are covered below. Findings and work items also take notes.
- **Ownership**: owners, the rule ladder, the review queue, manual overrides, and the Microsoft Graph and LeanIX connectors with their mappings and a sync button. The *Leaders & engineers* tab maps open findings to people (see below).
- **Scanners**: freshness per scanner and scope, scan history, uploads and verifier decisions.
- **Settings**, in five tabs:
  - *IAM*: single sign-on settings, the group-to-role map and API tokens.
  - *User Management*: single sign-on users.
  - *Policy*: confidence limit, due days, dispatch rules, production tags, stale-scan hours, the longest risk acceptance per severity, and four eyes. Changes are stored in the database and audited.
  - *Connectors*: Jira, DefectDojo, Microsoft Graph and LeanIX.
  - *Configuration*: config files, the database schema revision and the audit log.

  Credentials show as set or not set, never their values.

The console follows your system's light or dark setting, with a toggle. It's server-rendered with no build step, it loads nothing from third-party hosts, and it runs under a strict Content-Security-Policy. Sessions are signed cookies that hold a token hash or a user id, never a token or a password, and every form carries a CSRF token. Set `KAVLO_SESSION_SECRET` so sessions survive restarts.

To try it with sample data:

```bash
hack/demo-samples.sh --serve 8080   # Prowler, Trivy, Wiz and DefectDojo samples, Graph and LeanIX snapshots, triage
hack/serve-demo.sh 8080             # the small built-in example
```

The demo writes three tokens to `.kavlotryx/demo-tokens`: an admin, a viewer and an analyst (`riley`). Propose a triage decision as the analyst, then approve it as the admin. The sample demo also starts a development-only identity provider two ports up (`hack/dev_idp.py`; localhost only, no passwords). Pick Avery or Dana (admins), Riley (analyst), Vic (viewer) or Sam (no access). Set `KAVLO_DEMO_SSO=0` to leave it out.

### Public demo

`KAVLO_DEMO_MODE=1` turns the console into a public, read-only demo: anonymous visitors browse every page as a viewer, every change is blocked, a banner explains it, and the REST API stays closed. Behind a proxy, set `KAVLO_PUBLIC_URL` to the address people use. `deploy/Dockerfile.demo` builds an image with the sample data already seeded, and [deploy/cloudflare](deploy/cloudflare/README.md) deploys it to Cloudflare Containers.

### Ownership connectors

Two connectors add identity and application context. A sync copies what ownership needs into local tables, and owner resolution reads only those tables, so a rebuild never calls an external API.

| Connector | What it resolves | Live mode | Rule |
|---|---|---|---|
| Microsoft Graph | A tag that names a person (`Owner=jd@acme.com`) → their Entra ID groups → a team via `connectors.graph.group_map` | `KAVLO_GRAPH_TENANT_ID`, `KAVLO_GRAPH_CLIENT_ID`, `KAVLO_GRAPH_CLIENT_SECRET`; app permissions `GroupMember.Read.All`, plus `User.Read.All` for managers | 3, confidence 0.80 |
| LeanIX | An asset's app tag, image or resource name, or repository → an Application fact sheet → its team (`connectors.leanix.team_map`), or its responsible person through Graph | `KAVLO_LEANIX_HOST`, `KAVLO_LEANIX_TOKEN` (API token with read access) | 5, confidence 0.80 |

Each connector can also read a JSON snapshot (`KAVLO_GRAPH_SNAPSHOT`, `KAVLO_LEANIX_SNAPSHOT`), which is handy for demos and air-gapped installs. See `examples/samples/config/`.

```bash
kavlo connectors sync all     # or graph / leanix; re-resolves owners afterwards
kavlo connectors status
```

These clients are tested against mocked HTTP only. They haven't run against a live tenant or LeanIX workspace yet.

#### Leaders and engineers

The Microsoft Graph sync also reads the owners of each mapped Entra group and walks the `manager` chain above everyone it finds (`connectors.graph.manager_levels`, default 3, fetched in `$batch` calls). The *Leaders & engineers* tab under Ownership, and `GET /api/v1/people`, use that to map every open finding to people:

- **Engineers** see the findings named to them (through the Graph person tag, the LeanIX responsible person, or a person tag on the asset), plus their team's queue: every finding of the owner their group maps to.
- **Leaders** are group owners and anyone with reports. Their roll-up is every finding of the teams they lead and of everyone below them in the manager chain.
- Each person shows Critical and High counts, overdue work items and their oldest finding. A person page lists their findings and links to Vulnerabilities filtered to that person.
- Owners with no people in Entra show up as *reach nobody*, so the gap is visible.

This view only reads. It never changes an owner; owner resolution still uses group membership alone.

### Single sign-on and users

The console signs people in with OpenID Connect, so Microsoft Entra ID, Okta, Google, Keycloak, Auth0 and other OIDC providers all work. Register Kavlotryx as a web app with the redirect URI `https://<your host>/ui/sso/callback`, then set:

```bash
export KAVLO_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export KAVLO_OIDC_CLIENT_ID=<application id>
export KAVLO_OIDC_CLIENT_SECRET=<client secret>
export KAVLO_OIDC_REDIRECT_URL=https://kavlotryx.example.com/ui/sso/callback
export KAVLO_OIDC_ROLE_MAP="admin=<group id>,analyst=<group id>|<group id>,viewer=*"
export KAVLO_OIDC_LABEL="Microsoft Entra ID"          # the button text
export KAVLO_SESSION_SECRET=$(openssl rand -hex 32)   # sessions survive restarts and replicas
```

Sign-in uses the authorization-code flow with PKCE, `state` and `nonce`. Kavlotryx checks the ID token's signature against the provider's published keys (asymmetric algorithms only), along with its issuer, audience, expiry and nonce.

A user is created at first sign-in, and their role comes from the groups claim (`KAVLO_OIDC_GROUPS_CLAIM`, default `groups`). Entra ID sends group object ids; set the claim to `roles` if you'd rather use app roles. The highest matching role wins, `*` matches everyone, and someone who matches nothing can't sign in.

Admins see every user under Settings. They can pin a role, hand it back to the groups claim, deactivate a user, or end all of a user's sessions. These changes apply immediately, because each request reads the user. Nobody can change their own user, so you can't lock yourself out by accident. `kavlo users list|set-role|use-groups|deactivate|activate` does the same from the CLI.

API tokens keep working for the REST API and CI. On the console they act as a break-glass sign-in; set `KAVLO_TOKEN_LOGIN=0` to hide that once SSO works. An install with SSO and no tokens at all is fine too.

### Database migrations

Alembic migrations ship inside the package, and Kavlotryx brings the database to the latest revision when it starts. If your database predates migrations, Kavlotryx adopts it: it creates the missing tables and stamps it as the baseline, without losing data. When several replicas share one database, set `KAVLO_AUTO_MIGRATE=0` and run the upgrade once per release:

```bash
kavlo db upgrade      # to the latest revision
kavlo db current      # where the database is, and what the code needs
kavlo db history
kavlo db downgrade 0001
```

If you change a model, run `kavlo db revision -m "what changed"` and review the generated file. A test checks that the migrations build exactly the models, on both SQLite and PostgreSQL.

### DefectDojo as a source

If your team already runs DefectDojo, keep it. Kavlotryx reads its findings and adds the parts DefectDojo leaves to people: owners with evidence, one ticket per fix, and closure on scan proof.

```bash
export KAVLO_DEFECTDOJO_URL=https://defectdojo.example.com
export KAVLO_DEFECTDOJO_TOKEN=...              # an API v2 key; only used to read
kavlo pull defectdojo                          # every product, or --product NAME (repeat)
```

Each product becomes its own scan scope, `defectdojo:<product>`, so a product with nothing left open still proves its fixes. Findings with a CVE or GHSA become vulnerability findings; SAST, DAST and other rules become detection findings, keyed by test type and rule. The product, product type, environment and DefectDojo tags become asset tags, so ownership patterns and the production priority bump work on them.

DefectDojo marks false positives and accepted risks as inactive. Kavlotryx doesn't treat that as a fix: those findings stay open and appear on the Triage page as suggestions, and a person makes the call. Mitigated findings do count as fixed, which means you're trusting DefectDojo's reimport for that product. If you need scanner-grade proof, send the scanner output to Kavlotryx directly. Duplicates and out-of-scope rows are skipped. The pull only sends GET requests, and it refuses a `next` link that points to another host.

### Triage and the audit report

Some findings won't get fixed, and the reason belongs on record. A **false positive** says the scanner is wrong. A **risk acceptance** says the weakness is real but accepted for now. It needs compensating controls and an expiry date, at most `acceptance_max_days` for its highest severity (30 days for Critical by default).

An analyst or admin proposes a decision from a finding, from a work item (covering every open finding in it), or from a DefectDojo suggestion. An admin then approves or rejects it, and with `triage_four_eyes` on (the default) that admin has to be someone else.

Nothing changes until a decision is approved. Then its findings get the status `accepted` or `false_positive` and leave the open queues. A work item with nothing else open closes its ticket as *Closed by triage*, with a comment saying it wasn't fixed. When an acceptance expires or someone revokes a decision, the findings open again and the ticket reopens. A scan that stops reporting a triaged finding still marks it fixed, and if the finding comes back, it falls under its decision again.

Notes go on findings, work items and decisions. Like the audit log, they're append-only.

The **audit report** (`/ui/triage/report`, `GET /api/v1/reports/triage`, `kavlo triage report`) covers a period and, optionally, one owner. It holds the risk-acceptance and false-positive registers, the decision log from the audit table, the notes, and six control checks: segregation of duties, expiry within policy, audit trail, status integrity, pending proposals and expiring soon. You can download it as JSON with a SHA-256 digest over the canonical JSON, or as a CSV register, and it prints cleanly to PDF.

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

OpenAPI is served at `/docs`. The roles are `admin`, `analyst`, `viewer` and `ingest` (upload only, for CI). Admins manage single sign-on users at `/api/v1/users`. Triage lives under `/api/v1/triage/decisions` (propose, then `approve`, `reject` or `revoke`), notes under `/api/v1/notes/{finding|work_item|decision}/{id}`, and the DefectDojo pull at `POST /api/v1/scans/defectdojo/pull` (admin only).

## Writing an adapter

An adapter is a class with a `parse(bytes) -> ParseResult` method that returns OCSF records. Register it under the `kavlotryx.adapters` entry-point group in your own package, and `kavlo ingest --scanner yourtool` picks it up.

## What Kavlotryx doesn't do

It doesn't scan, it doesn't invent yet another findings format, and it never changes your cloud resources or your code.

## License

Apache-2.0.
