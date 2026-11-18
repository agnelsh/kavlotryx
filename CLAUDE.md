# Kavlotryx

Open-source (Apache-2.0) platform that turns scanner findings into owned, tracked, scan-verified work.
Requirement ids (FR-IN-01, NFR-SEC-02, ...) tag each feature; cite them in code and tests.

## Commands

- Tests: `.venv/bin/pytest` (SQLite). On PostgreSQL: `KAVLO_TEST_DATABASE_URL=postgresql+psycopg://... .venv/bin/pytest`
- Lint: `.venv/bin/ruff check src tests`
- Demo: `hack/demo.sh` (fake tracker, no Jira needed)

## Invariants (do not break)

- OCSF is the stored model. Adapters emit OCSF 2002/2003/2004; extra facts go under `unmapped.kavlotryx`. Do not invent a new format.
- A work item closes as `verified` only when a scan of the same scanner AND scope no longer reports its findings. A ticket status alone never closes it. The only other close is `triaged`: every finding left is covered by an approved triage decision, and it reopens when a decision ends.
- Dispatch is idempotent: label `kavlo-<hash>`, search before create. A re-run or a fresh database never creates a second ticket.
- Every owner assignment stores rule, source, evidence and confidence. Below `confidence_limit` it is `needs_review`. An LLM may only suggest, never assign.
- Every connector works with missing data (FR-EN-07): missing tags, files or repos are trace entries, not errors.
- Credentials come from env only (NFR-SEC-02). Ticket text is ADF text nodes, never Jira markup (NFR-SEC-04). JQL input goes through `check_label`.
- Every write goes to `audit_events`.
- Triage (FR-IF-06..09): only an approved (`active`) decision changes a finding's status. Four eyes by default; a risk acceptance always expires. A scanner or DefectDojo flag is a suggestion, never a decision. Notes are append-only.
