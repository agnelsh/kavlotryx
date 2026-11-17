# Kavlotryx

Kavlotryx turns security scanner findings into owned, tracked work.

Scanners are good at finding problems and bad at getting them fixed. Every tool speaks its own format, two tools report the same CVE on the same image, a finding names an ARN but never a team, and a ticket gets closed by a person while the weakness is still there. Kavlotryx sits between your scanners and your ticket system and does the coordination work:

1. **Ingest** Prowler and Trivy output, or any OCSF finding.
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
| 1 | Manual override (`kavlo owner set`) | 1.0 |
| 2 | Resource tag (`owner`, `team`, configurable) | 0.9 |
| 3 | GitHub CODEOWNERS for the file or Dockerfile | 0.85 |
| 4 | Pattern rule in `ownership.yaml` | 0.75 |
| 5 | Cloud account or registry default | 0.5 (needs review) |
| 6 | Fallback owner | 0.0 |

## Using it

```bash
export KAVLO_CONFIG_DIR=examples/config            # ownership.yaml, policy.yaml
export KAVLO_DATABASE_URL=sqlite:///./kavlotryx.db  # or postgresql+psycopg://...

kavlo ingest prowler-output.ocsf.json --scanner prowler
kavlo ingest trivy-image.json --scanner trivy
kavlo run --dry-run            # rebuild owners and groups, show the tickets it would file
kavlo run                      # file and verify tickets
kavlo workitems
kavlo findings --review        # owners below the confidence limit
kavlo report                   # counts and success metrics
```

To file real Jira Cloud issues, set `KAVLO_JIRA_URL`, `KAVLO_JIRA_EMAIL` and `KAVLO_JIRA_TOKEN`, and give each owner a `jira_project` in `ownership.yaml`. Credentials are read from the environment only.

### Web console

`kavlo serve` also serves a console at `/ui`, signed in with the same API tokens (admin, analyst and viewer roles; ingest tokens are upload-only). It has four pages that follow the Kavlotryx Stitch designs:

- **Overview**: open findings, active work, verified closures and what needs a person.
- **Findings & ownership**: the deduplicated records, the rule ladder, and an inspector with the full `owner explain` trace, the raw OCSF record, scanner provenance and a manual override form.
- **Work items & Jira**: state counts, ticket noise, a dry-run dispatch, and a detail page per work item with its proof-of-closure timeline and the exact ticket body.
- **Verification & ingest**: scans, file upload, verifier decisions and the audit log.

It follows your system's light or dark setting ("Solar Phosphor" dark, "Light Terminal Mode" light), with a toggle. The console is server-rendered with no build step and loads nothing from third-party hosts, under a strict Content-Security-Policy. Sessions are signed cookies that hold a hash of the token, never the token itself, and every form carries a CSRF token. Set `KAVLO_SESSION_SECRET` so sessions survive restarts.

To try it with sample data:

```bash
hack/serve-demo.sh 8080   # tokens are written to .kavlotryx/demo-tokens
```

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
