"""Ingest one scanner output: parse, normalize, deduplicate, mark fixed (FR-IN, FR-DD, FR-VF-02)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from kavlotryx.adapters import get_adapter
from kavlotryx.core.fingerprint import fingerprint
from kavlotryx.db import Finding, FindingSource, Observation, Scan, audit, utcnow
from kavlotryx.ocsf.extract import FindingFacts, extract_facts

# Facts that a later scan may update on an existing finding.
_MUTABLE = (
    "severity_id", "title", "description", "remediation", "fixed_version", "tags",
    "repo", "path", "region", "artifact", "asset_name", "src_package",
)


@dataclass
class IngestReport:
    scan_id: int
    scanner: str
    scope: str
    records: int
    findings_seen: int
    new: int
    fixed: int
    reopened: int
    skipped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["skipped_count"] = len(self.skipped)
        d["skipped"] = self.skipped[:50]
        return d


def _new_finding(fp: str, f: FindingFacts) -> Finding:
    return Finding(
        fingerprint=fp,
        kind=f.kind,
        class_uid=f.class_uid,
        asset_key=f.asset_key,
        asset_type=f.asset_type,
        asset_name=f.asset_name,
        artifact=f.artifact,
        vuln_id=f.vuln_id,
        package=f.package,
        src_package=f.src_package,
        installed_version=f.installed_version,
        fixed_version=f.fixed_version,
        rule_key=f.rule_key,
        title=f.title,
        description=f.description,
        remediation=f.remediation,
        severity_id=f.severity_id,
        provider=f.provider,
        account_uid=f.account_uid,
        region=f.region,
        repo=f.repo,
        path=f.path,
        tags=dict(f.tags),
    )


def ingest(
    session: Session,
    scanner: str,
    data: bytes,
    scope: str | None = None,
    actor: str = "system",
) -> IngestReport:
    adapter = get_adapter(scanner)
    parsed = adapter.parse(data)
    scope = (scope or parsed.default_scope or adapter.name).strip()
    now = utcnow()

    scan = Scan(scanner=adapter.name, scope=scope, record_count=len(parsed.records),
                skipped_count=len(parsed.skipped))
    session.add(scan)
    session.flush()

    # Deduplicate inside this scan first: one fingerprint, one finding.
    by_fp: dict[str, FindingFacts] = {}
    for rec in parsed.records:
        facts = extract_facts(rec)
        if not facts.asset_key:
            parsed.skipped.append(f"{facts.title or 'record'}: no asset identifier")
            continue
        fp = fingerprint(facts)
        session.add(Observation(scan_id=scan.id, fingerprint=fp, class_uid=facts.class_uid, raw=rec))
        prev = by_fp.get(fp)
        if prev is None or facts.severity_id > prev.severity_id:
            by_fp[fp] = facts

    existing = {}
    if by_fp:
        fps = list(by_fp)
        for i in range(0, len(fps), 500):
            for fnd in session.scalars(select(Finding).where(Finding.fingerprint.in_(fps[i:i + 500]))):
                existing[fnd.fingerprint] = fnd

    new = reopened = 0
    for fp, facts in by_fp.items():
        fnd = existing.get(fp)
        if fnd is None:
            fnd = _new_finding(fp, facts)
            fnd.first_seen = now
            session.add(fnd)
            session.flush()
            new += 1
        else:
            for attr in _MUTABLE:
                val = getattr(facts, attr)
                if val not in ("", {}, None):
                    setattr(fnd, attr, val)
            if fnd.status == "fixed":
                fnd.status = "open"
                fnd.fixed_at = None
                fnd.fixed_by_scan_id = None
                fnd.reopen_count += 1
                reopened += 1
        fnd.last_seen = now

        src = session.scalar(
            select(FindingSource).where(
                FindingSource.finding_id == fnd.id,
                FindingSource.scanner == adapter.name,
                FindingSource.scope == scope,
            )
        )
        if src is None:
            session.add(FindingSource(finding_id=fnd.id, scanner=adapter.name, scope=scope,
                                      last_scan_id=scan.id, first_seen=now, last_seen=now))
        else:
            src.present = True
            src.last_scan_id = scan.id
            src.last_seen = now
    session.flush()

    # A finding is fixed only when a scan of the same scanner AND the same scope
    # no longer reports it, and no other source still reports it (FR-VF-02).
    gone = session.scalars(
        select(FindingSource).where(
            FindingSource.scanner == adapter.name,
            FindingSource.scope == scope,
            FindingSource.present.is_(True),
            FindingSource.last_scan_id != scan.id,
        )
    ).all()
    touched: set[int] = set()
    for src in gone:
        src.present = False
        touched.add(src.finding_id)
    session.flush()

    fixed = 0
    for fid in touched:
        still = session.scalar(
            select(FindingSource.id).where(FindingSource.finding_id == fid,
                                           FindingSource.present.is_(True))
        )
        fnd = session.get(Finding, fid)
        if still is None and fnd is not None and fnd.status == "open":
            fnd.status = "fixed"
            fnd.fixed_at = now
            fnd.fixed_by_scan_id = scan.id
            fixed += 1

    scan.new_count, scan.fixed_count, scan.reopened_count = new, fixed, reopened
    scan.skipped_count = len(parsed.skipped)
    audit(session, actor, "scan.ingest", f"scan:{scan.id}", scanner=adapter.name, scope=scope,
          records=len(parsed.records), new=new, fixed=fixed, reopened=reopened)
    session.commit()
    return IngestReport(scan_id=scan.id, scanner=adapter.name, scope=scope,
                        records=len(parsed.records), findings_seen=len(by_fp), new=new,
                        fixed=fixed, reopened=reopened, skipped=parsed.skipped)
