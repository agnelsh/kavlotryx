# Third-party sample data

This folder lets you try Kavlotryx on scanner output that was not written for Kavlotryx.
The files come from the [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) test suite
(BSD-3-Clause). They are downloaded at a pinned commit and checked against `SHA256SUMS`.
They are not stored in this repository.

```bash
hack/fetch-samples.sh            # download into examples/samples/defectdojo/ (git-ignored)
hack/demo-samples.sh             # run the three-day story below
hack/demo-samples.sh --serve 8080  # same, then open the console at /ui
```

## The story

| Day | Scan | What Kavlotryx does |
|---|---|---|
| 1 | Prowler `many_vuln.ocsf.json`: 3 risky IAM roles in account 123456789012 | 3 findings, owner `identity` by the `iam-roles` pattern, 3 tickets |
| 1 | Trivy `scheme_2_many_vulns.json`: image `teamdojo:latest` | OS packages go to `platform` and `app/libs/` jars to `app`, both through CODEOWNERS |
| 1 | Trivy `misconfigurations_and_secrets.json`: a directory scan | urllib3 CVEs and a Dockerfile rule, owner `app` |
| 1 | Wiz Issues export `wiz/multiple_findings.csv`: 98 issues from Wiz's demo tenant (Azure, AKS) | 97 open issues (1 is RESOLVED) become 39 work items, e.g. 26 guest users → 1 `identity` ticket. Owners come from the `Owner` tag, resource-type patterns and the subscription default |
| 1 | wizcli image scan `wizcli_img_many_vul.json` | 8 vulnerabilities; the secret is counted as skipped |
| 1 | Prowler 4.5 `many_vuln_after_4_5_0.ocsf.json` | 0 new: the newer output format deduplicates into the same findings |
| 2 | Prowler `one_vuln.ocsf.json` | 2 IAM findings fixed; their tickets close with scan proof |
| 2 | wizcli `wizcli_img_zero_vul.json`: the same image, rebuilt | all 8 image findings fixed; their tickets close |
| 3 | Prowler `no_vuln.ocsf.json` (empty) | the last IAM ticket closes |

`config/` holds the ownership rules for this data. The sample image has no source label, so
`image_repos` maps it to a made-up repository with the CODEOWNERS file in `config/codeowners/`.

## Known gaps this data shows

- **Pass `--scope` for empty or directory scans.** An empty Prowler file and a Trivy scan of `.`
  do not say what was scanned. Without `--scope`, a later scan cannot prove fixes, and the CLI warns.
- **Secrets are not ingested yet.** Trivy and wizcli secrets are counted as skipped (secret findings
  are planned for v0.2).
- **Wiz IGNORED issues stay open.** Only RESOLVED issues count as fixed. An IGNORED issue still
  exists, so it is not closed until risk-acceptance exceptions arrive (v0.3).
- **wizcli IaC scans need `--scope`.** wizcli names them "IAC scan <time>", which is not an identity.
- **Trivy Kubernetes reports** (`trivy k8s`) use a different format and are not supported.
