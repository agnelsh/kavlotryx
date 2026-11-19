# Kavlotryx

Open-source (Apache-2.0) platform that turns scanner findings into owned, tracked, scan-verified work.
Requirement ids (FR-IN-01, NFR-SEC-02, ...) tag each feature; cite them in code and tests.

## Commands

- Tests: `.venv/bin/pytest` (SQLite). On PostgreSQL: `KAVLO_TEST_DATABASE_URL=postgresql+psycopg://... .venv/bin/pytest`
- Lint: `.venv/bin/ruff check src tests`
- Demo: `hack/demo.sh` (fake tracker, no Jira needed); `hack/demo-samples.sh --serve 8187` adds a dev OIDC provider
- Schema: Alembic in `src/kavlotryx/migrations`. A model change needs `kavlo db revision -m "..."`; `tests/test_migrations.py` fails until migrations match the models.

## Invariants (do not break)

- OCSF is the stored model. Adapters emit OCSF 2002/2003/2004; extra facts go under `unmapped.kavlotryx`. Do not invent a new format.
- A work item closes as `verified` only when a scan of the same scanner AND scope no longer reports its findings. A ticket status alone never closes it. The only other close is `triaged`: every finding left is covered by an approved triage decision, and it reopens when a decision ends.
- Dispatch is idempotent: label `kavlo-<hash>`, search before create. A re-run or a fresh database never creates a second ticket.
- Every owner assignment stores rule, source, evidence and confidence. Below `confidence_limit` it is `needs_review`. An LLM may only suggest, never assign.
- Every connector works with missing data (FR-EN-07): missing tags, files or repos are trace entries, not errors.
- Credentials come from env only (NFR-SEC-02). Ticket text is ADF text nodes, never Jira markup (NFR-SEC-04). JQL input goes through `check_label`.
- Every write goes to `audit_events`.
- SSO (FR-IF-10): ID tokens are verified (JWKS signature, asymmetric algs only, iss, aud, exp, nonce); PKCE and state on every flow. Sessions read the user on every request. No user can change their own role or deactivate themself.
- ServiceNow CMDB (FR-EN-08): a CI matches by resource id, CI tag or a name only one CI has; an ambiguous name is never used. GET-only Table API, host must be *.service-now.com or *.servicenowservices.com.
- Priority (FR-PR-01/02): severity, then one level up for production or business-critical (tag or CI), one up for EPSS ≥ threshold, KEV sets a floor. Every change is a stored reason. The content hash uses reason codes, not texts, so daily EPSS moves never rewrite tickets. Threat feeds are public, live mode is opt-in (`KAVLO_THREAT_INTEL_LIVE=1`), https only.
- Triage (FR-IF-06..09): only an approved (`active`) decision changes a finding's status. Four eyes by default; a risk acceptance always expires. A scanner or DefectDojo flag is a suggestion, never a decision. Notes are append-only.
