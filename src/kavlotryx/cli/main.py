"""``kavlo``: the Kavlotryx command-line interface (FR-IF-02).

The CLI works on the local database named by KAVLO_DATABASE_URL and the
config files in KAVLO_CONFIG_DIR (or --config).
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from kavlotryx import __version__
from kavlotryx.adapters import AdapterError, available_adapters
from kavlotryx.config import Settings
from kavlotryx.db import Finding, WorkItem
from kavlotryx.dispatch.base import TrackerError
from kavlotryx.ocsf.severity import SEVERITY_NAMES
from kavlotryx.service import Kavlotryx, NotFound

app = typer.Typer(help="Kavlotryx: scanner findings to owned, tracked, scan-verified work.",
                  no_args_is_help=True)
owner_app = typer.Typer(help="Explain or override finding owners.", no_args_is_help=True)
tracker_app = typer.Typer(help="Inspect the fake tracker used for demos.", no_args_is_help=True)
connectors_app = typer.Typer(help="Microsoft Graph and LeanIX ownership connectors.", no_args_is_help=True)
app.add_typer(owner_app, name="owner")
app.add_typer(connectors_app, name="connectors")
app.add_typer(tracker_app, name="tracker")
console = Console()

_state: dict[str, Settings] = {}

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="Directory with ownership.yaml and policy.yaml")]
DbOpt = Annotated[str | None, typer.Option("--db", help="Database URL (default from KAVLO_DATABASE_URL)")]


@app.callback()
def main(config: ConfigOpt = None, db: DbOpt = None) -> None:
    s = Settings.from_env()
    if config:
        s.config_dir = config
    if db:
        s.database_url = db
    _state["settings"] = s


def svc() -> Kavlotryx:
    return Kavlotryx(_state.get("settings") or Settings.from_env())


def actor() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # pragma: no cover
        return "cli"


def fail(msg: str) -> None:
    console.print(f"[red]error:[/red] {msg}")
    raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print the version and the installed adapters."""
    console.print(f"kavlotryx {__version__}; adapters: {', '.join(sorted(available_adapters()))}")


@app.command()
def ingest(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    scanner: Annotated[str, typer.Option("--scanner", "-s", help="prowler | trivy | ocsf")],
    scope: Annotated[str | None, typer.Option(help="Scan scope; defaults to the scanned account or artifact")] = None,
) -> None:
    """Ingest one scanner output file."""
    try:
        r = svc().ingest(scanner, file.read_bytes(), scope=scope, actor=actor())
    except AdapterError as e:
        fail(str(e))
    console.print(f"scan {r.scan_id} [bold]{r.scanner}[/bold] scope={r.scope}: {r.records} records, "
                  f"{r.findings_seen} findings, {r.new} new, {r.fixed} fixed, {r.reopened} reopened, "
                  f"{len(r.skipped)} skipped")
    for reason in r.skipped[:10]:
        console.print(f"  skipped: {reason}")
    if not scope and r.scope == r.scanner:
        console.print("[yellow]warning:[/yellow] the scope could not be read from this file; pass --scope "
                      "so that a later scan can prove fixes for the same account or artifact")


@app.command()
def rebuild() -> None:
    """Resolve owners and regroup open findings into work items."""
    r = svc().rebuild()
    console.print(f"{r.findings} open findings -> {r.work_items} work items; "
                  f"{r.needs_review} findings need owner review; {r.reopened} items reopened")


@app.command()
def dispatch(dry_run: Annotated[bool, typer.Option("--dry-run")] = False) -> None:
    """Create or update one ticket per work item."""
    try:
        r = svc().dispatch(dry_run=dry_run, actor=actor())
    except TrackerError as e:
        fail(str(e))
    t = Table("work item", "action", "ticket", "detail", title="dispatch (dry run)" if dry_run else "dispatch")
    for a in r.actions:
        t.add_row(a.work_item, a.action, a.ticket, a.detail)
    console.print(t)


@app.command()
def verify(dry_run: Annotated[bool, typer.Option("--dry-run")] = False) -> None:
    """Read ticket status and close, keep open or reopen work items based on scans."""
    try:
        r = svc().verify(dry_run=dry_run, actor=actor())
    except TrackerError as e:
        fail(str(e))
    t = Table("work item", "action", "ticket", "detail", title="verify")
    for a in r.actions:
        t.add_row(a.work_item, a.action, a.ticket, a.detail)
    console.print(t if r.actions else "nothing to change")


@app.command()
def run(dry_run: Annotated[bool, typer.Option("--dry-run")] = False) -> None:
    """rebuild, dispatch and verify in one step."""
    try:
        console.print_json(json.dumps(svc().run(dry_run=dry_run, actor=actor())))
    except TrackerError as e:
        fail(str(e))


@app.command()
def findings(
    owner: str | None = None,
    status: str = "open",
    review: Annotated[bool, typer.Option("--review", help="Only findings whose owner needs review")] = False,
    limit: int = 50,
) -> None:
    """List findings."""
    with svc().session() as s:
        q = select(Finding).where(Finding.status == status)
        if owner:
            q = q.where(Finding.owner_slug == owner)
        if review:
            q = q.where(Finding.needs_review.is_(True))
        rows = s.scalars(q.order_by(Finding.severity_id.desc(), Finding.id).limit(limit)).all()
    t = Table("id", "sev", "what", "asset", "owner", "conf", "rule", "item")
    for f in rows:
        what = f"{f.vuln_id} {f.package}" if f.kind == "vuln" else f.rule_key
        conf = f"{f.owner_confidence:.2f}" + ("*" if f.needs_review else "")
        t.add_row(str(f.id), SEVERITY_NAMES.get(f.severity_id, "?"), what, f.asset_key[-48:],
                  f.owner_slug, conf, f.owner_rule, f.work_item_key)
    console.print(t)
    console.print("* = below the confidence limit, owner needs review")


@app.command()
def workitems(owner: str | None = None, state: str | None = None) -> None:
    """List work items."""
    with svc().session() as s:
        q = select(WorkItem)
        if owner:
            q = q.where(WorkItem.owner_slug == owner)
        if state:
            q = q.where(WorkItem.state == state)
        rows = s.scalars(q.order_by(WorkItem.owner_slug, WorkItem.key)).all()
        counts = {w.key: 0 for w in rows}
        for f in s.scalars(select(Finding).where(Finding.status == "open", Finding.work_item_key != "")):
            if f.work_item_key in counts:
                counts[f.work_item_key] += 1
    t = Table("key", "owner", "priority", "state", "open", "due", "ticket", "title")
    for w in rows:
        flag = "" if w.dispatchable else " (not dispatched)"
        t.add_row(w.key, w.owner_slug, w.priority, w.state + flag, str(counts[w.key]),
                  w.due_date.isoformat() if w.due_date else "", w.ticket_key, w.title)
    console.print(t)


@app.command()
def report() -> None:
    """Print the summary report and success metrics."""
    console.print_json(json.dumps(svc().summary(), default=str))


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    insecure_no_auth: Annotated[
        bool, typer.Option("--insecure-no-auth", help="Allow requests without a token (local use only)")
    ] = False,
) -> None:
    """Run the REST API."""
    import uvicorn

    from kavlotryx.api import create_app

    uvicorn.run(create_app(svc(), insecure_no_auth=insecure_no_auth), host=host, port=port)


@owner_app.command("explain")
def owner_explain(finding_id: int) -> None:
    """Show every ownership rule tried for one finding, and why."""
    try:
        a = svc().explain(finding_id)
    except NotFound as e:
        fail(str(e))
    console.print(f"owner [bold]{a.owner}[/bold] by rule {a.rule} (source {a.source}), "
                  f"confidence {a.confidence:.2f}" + (" [yellow]needs review[/yellow]" if a.needs_review else ""))
    if a.evidence:
        console.print(f"evidence: {json.dumps(a.evidence)}")
    for i, t in enumerate(a.trace, start=1):
        mark = "[green]match[/green]" if t.matched else "[dim]no[/dim]"
        console.print(f"  {i}. {t.rule:<22} {mark}  {t.reason}")


@owner_app.command("set")
def owner_set(
    finding_id: int,
    owner: str,
    match: Annotated[str, typer.Option(help="asset: every finding on the asset; finding: only this one")] = "asset",
    reason: str = "",
) -> None:
    """Override the owner. The override becomes the highest-order rule."""
    try:
        o = svc().set_owner(finding_id, owner, actor(), reason, match)
    except (NotFound, ValueError) as e:
        fail(str(e))
    console.print(f"override saved: {o.match_type} {o.match_value} -> {o.owner_slug}. Run 'kavlo rebuild'.")


@connectors_app.command("sync")
def connectors_sync(
    name: Annotated[str, typer.Argument(help="graph | leanix | all")],
    no_rebuild: Annotated[bool, typer.Option("--no-rebuild", help="Do not re-resolve owners after the sync")] = False,
) -> None:
    """Copy people (Graph) or applications (LeanIX) into the local cache, then rebuild owners."""
    from kavlotryx.connectors import CONNECTORS, ConnectorError

    k = svc()
    for n in (CONNECTORS if name == "all" else (name,)):
        try:
            run = k.sync_connector(n, actor=actor(), rebuild=False)
        except ConnectorError as e:
            fail(str(e))
        console.print(f"{n}: {run.mode} sync ok {json.dumps(run.counts)}")
    if not no_rebuild:
        r = k.rebuild()
        console.print(f"rebuilt: {r.work_items} work items, {r.needs_review} findings need owner review")


@connectors_app.command("status")
def connectors_status() -> None:
    """Show each connector's mode and last sync."""
    from kavlotryx.connectors import CONNECTORS, connector_mode, last_runs

    k = svc()
    with k.session() as s:
        runs = last_runs(s)
    t = Table("connector", "mode", "last sync", "status", "counts")
    for n in CONNECTORS:
        r = runs[n]
        t.add_row(n, connector_mode(k.settings, n), r.finished_at.isoformat() if r and r.finished_at else "never",
                  r.status if r else "", json.dumps(r.counts) if r else "")
    console.print(t)


@tracker_app.command("list")
def tracker_list() -> None:
    """List issues in the fake tracker."""
    from kavlotryx.dispatch.fake import FakeTracker

    ft = FakeTracker(svc().settings.fake_tracker_file)
    t = Table("key", "status", "priority", "due", "summary", "comments")
    for i in ft.issues.values():
        t.add_row(i["key"], i["status"], i["priority"], i["due"] or "", i["summary"], str(len(i["comments"])))
    console.print(t)


@tracker_app.command("set-status")
def tracker_set_status(key: str, status: Annotated[str, typer.Argument(help="new | indeterminate | done")]) -> None:
    """Change an issue's status in the fake tracker, as a person would in Jira."""
    from kavlotryx.dispatch.fake import FakeTracker

    ft = FakeTracker(svc().settings.fake_tracker_file)
    try:
        ft.transition(key, status)
    except TrackerError as e:
        fail(str(e))
    console.print(f"{key} -> {status}")


if __name__ == "__main__":  # pragma: no cover
    app()
