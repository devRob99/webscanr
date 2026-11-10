"""WebScan command-line interface (Typer)."""

from __future__ import annotations

import time
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from webscan import store
from webscan.audit.logger import AuditLogger
from webscan.config import (
    CONFIG_NAMES,
    AssetRegistry,
    ConfigError,
    load_providers,
    load_scoring,
    load_settings,
)
from webscan.context import RunContext, build_context
from webscan.pipeline import ScanResult, collect, prioritize, run_demo_collection
from webscan.scope.enforcer import ScopeEnforcer, ScopeError

app = typer.Typer(
    help="WebScan: vulnerability scanning and prioritization for nonprofits. "
    "Runs on mock data unless live mode is explicitly enabled and approved.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


class Lang(StrEnum):
    en = "en"
    es = "es"


class Format(StrEnum):
    terminal = "terminal"
    json = "json"
    csv = "csv"
    html = "html"
    pdf = "pdf"


OperatorOpt = Annotated[str | None, typer.Option("--operator", help="Operator name recorded in the audit log.")]
ConfigDirOpt = Annotated[Path | None, typer.Option("--config-dir", help="Directory with the config JSON files.")]
ExampleOpt = Annotated[
    bool, typer.Option("--example-config", help="Use the committed *.example.json placeholder configs.")
]
NoRedactOpt = Annotated[
    bool, typer.Option("--no-redact", help="Write UNREDACTED output to output/unredacted/ (local use only).")
]
LangOpt = Annotated[Lang, typer.Option("--lang", help="Output language.")]


def _fail(message: str, code: int = 1) -> typer.Exit:
    console.print(f"[bold red]{message}[/bold red]")
    return typer.Exit(code)


def _context(command: str, **kwargs) -> RunContext:
    """Build the run context, turning config and scope failures into clear halts."""
    try:
        ctx = build_context(command, **kwargs)
    except ScopeError as exc:
        console.print(f"[bold red]SCOPE HALT:[/bold red] {exc}")
        console.print(
            "Create config/allowed_targets.json from the .example.json template, "
            "or run [bold]webscan demo[/bold] to try the tool on mock data."
        )
        raise typer.Exit(2) from exc
    except ConfigError as exc:
        raise _fail(f"CONFIG ERROR: {exc}") from exc
    if ctx.no_redact:
        console.print(
            "[bold yellow]WARNING:[/bold yellow] redaction is OFF. Output goes to output/unredacted/ and contains "
            "raw hostnames and IPs. Do not share or commit it. This use has been recorded in the audit log."
        )
    return ctx


def _print_warnings(ctx: RunContext) -> None:
    for warning in ctx.warnings:
        console.print(f"[yellow]note:[/yellow] {warning}")


# --------------------------------------------------------------------------- validate


@app.command()
def validate(
    operator: OperatorOpt = None, config_dir: ConfigDirOpt = None, example_config: ExampleOpt = False
) -> None:
    """Validate all config files and the whitelist."""
    settings = load_settings(config_dir=config_dir, use_examples=example_config)
    audit = AuditLogger(settings.log_dir / "audit.jsonl", operator=operator, command="validate")
    table = Table(title="Configuration check", title_justify="left")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Details", overflow="fold")
    problems = 0
    scope: ScopeEnforcer | None = None
    assets: AssetRegistry | None = None

    def row(name: str, ok: bool | None, detail: str) -> None:
        nonlocal problems
        status = {True: "[green]OK[/green]", False: "[red]ERROR[/red]", None: "[yellow]DEFAULTS[/yellow]"}[ok]
        problems += ok is False
        table.add_row(name, status, detail)

    for name in CONFIG_NAMES:
        path = settings.config_path(name)
        try:
            if name == "allowed_targets":
                scope = ScopeEnforcer.from_file(path)
                row(path.name, True, f"{len(scope.listed_domains())} domain entries; whitelist loaded")
            elif name == "assets_metadata":
                assets = AssetRegistry.from_file(path)
                row(path.name, True, f"{len(assets.assets)} assets")
            elif not path.exists():
                (load_scoring if name == "scoring" else load_providers)(settings)
                row(path.name, None, "file not present; built-in defaults are used")
            elif name == "scoring":
                load_scoring(settings)
                row(path.name, True, "multipliers, bands, and grade settings are valid")
            else:
                cfg = load_providers(settings)
                approved = ", ".join(cfg["approved_providers"]) or "none"
                row(path.name, True, f"approved external providers: {approved}")
        except (ScopeError, ConfigError) as exc:
            row(path.name, False, str(exc))

    if scope and assets:
        outside = [
            asset.alias for asset in assets.assets if any(not scope.check(t).in_scope for t in asset.targets)
        ]
        if outside:
            row("cross-check", False, "assets with targets missing from the whitelist: " + ", ".join(outside))
        else:
            row("cross-check", True, "every asset target is covered by the whitelist")

    live = settings.live_mode_env
    key = "set" if settings.get_env("HACKERTARGET_API_KEY") else "not set"
    row(".env", True, f"WEBSCAN_LIVE_MODE={'true' if live else 'false'}; HACKERTARGET_API_KEY {key}")
    console.print(table)
    audit.log("validate", status="ok" if not problems else "error", detail=f"{problems} problem(s)")
    if problems:
        raise _fail(f"{problems} problem(s) found. Fix them before scanning.")
    console.print("[green]Configuration is valid.[/green]")


# --------------------------------------------------------------------------- scope-check


@app.command("scope-check")
def scope_check(
    target: Annotated[str, typer.Argument(help="IP address, CIDR block, or hostname to check.")],
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
) -> None:
    """Show whether a target is in scope and why."""
    ctx = _context("scope-check", operator=operator, config_dir=config_dir, use_examples=example_config)
    decision = ctx.scope.check(target)
    asset = ctx.assets.lookup(decision.target) if decision.kind else None
    shown = ctx.redactor(decision.target) if decision.kind else "(rejected input)"
    console.print(f"Target:            {shown}")
    console.print(f"Type:              {decision.kind or 'invalid'}")
    console.print(f"Asset:             {asset.alias if asset else 'not in assets_metadata'}")
    verdict = "[green]IN SCOPE[/green]" if decision.in_scope else "[bold red]OUT OF SCOPE[/bold red]"
    console.print(f"Decision:          {verdict}")
    external = "[green]allowed[/green]" if decision.external_ok else "[red]never[/red]"
    console.print(f"External provider: {external}")
    console.print(f"Reason:            {decision.reason}")
    ctx.audit.log(
        "scope_check" if decision.in_scope else "scope_rejection", targets=[target],
        status="ok" if decision.in_scope else "rejected", detail=decision.reason,
    )
    if not decision.in_scope:
        raise typer.Exit(2)


# --------------------------------------------------------------------------- scan


@app.command()
def scan(
    asset: Annotated[str | None, typer.Option("--asset", help="Asset alias from assets_metadata.")] = None,
    all_assets: Annotated[bool, typer.Option("--all", help="Scan every asset in the inventory.")] = False,
    live: Annotated[bool, typer.Option("--live", help="Request live mode (also needs .env and approval).")] = False,
    include_wip: Annotated[bool, typer.Option("--include-wip", help="Also run WIP stub providers.")] = False,
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
    no_redact: NoRedactOpt = False,
) -> None:
    """Run enabled providers against one asset or the whole inventory."""
    if bool(asset) == bool(all_assets):
        raise _fail("Choose exactly one of --asset <alias> or --all.")
    ctx = _context(
        "scan", operator=operator, config_dir=config_dir, use_examples=example_config, live=live, no_redact=no_redact
    )
    from webscan.providers.registry import target_providers

    if asset:
        chosen = ctx.assets.get(asset)
        if chosen is None:
            known = ", ".join(a.alias for a in ctx.assets.assets)
            raise _fail(f"Unknown asset alias. Known aliases: {known}")
        assets = [chosen]
    else:
        assets = list(ctx.assets.assets)
    providers = target_providers(ctx, include_wip=include_wip)

    modes = Table(title="Providers", title_justify="left")
    modes.add_column("Provider")
    modes.add_column("Mode")
    modes.add_column("Why", overflow="fold")
    for provider in providers:
        allowed, reason = ctx.guard.live_allowed(provider.name, third_party=provider.is_external)
        is_live = provider.is_live()
        if allowed and not is_live:
            reason = "no API key configured"
        modes.add_row(
            provider.name + (" (WIP)" if provider.wip else ""),
            "[green]live[/green]" if is_live else "[magenta]mock[/magenta]", reason,
        )
    console.print(modes)

    started = time.perf_counter()
    try:
        findings = collect(ctx, assets, providers)
    except ScopeError as exc:
        console.print(f"[bold red]SCOPE HALT:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    store.replace(ctx, findings, {p.name for p in providers}, {a.alias for a in assets})
    ctx.audit.log(
        "scan", targets=[t for a in assets for t in a.targets], mode=ctx.mode_label, status="ok",
        findings=len(findings), duration_ms=(time.perf_counter() - started) * 1000,
        providers=[p.name for p in providers],
    )
    _print_warnings(ctx)
    console.print(
        f"Collected [bold]{len(findings)}[/bold] raw findings from {len(assets)} asset(s). "
        "Next: [bold]webscan prioritize[/bold] or [bold]webscan report[/bold]."
    )


# --------------------------------------------------------------------------- ingest-quantro


@app.command("ingest-quantro")
def ingest_quantro(
    report_file: Annotated[Path, typer.Argument(help="Path to a Quantro report (JSON).")],
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
    no_redact: NoRedactOpt = False,
) -> None:
    """Ingest a Quantro report (assumed schema; mapping set in providers.json)."""
    ctx = _context(
        "ingest-quantro", operator=operator, config_dir=config_dir, use_examples=example_config, no_redact=no_redact
    )
    from webscan.providers.quantro.parser import QuantroFormatError
    from webscan.providers.quantro.provider import QuantroProvider

    try:
        findings = QuantroProvider(ctx).ingest_file(report_file)
    except QuantroFormatError as exc:
        raise _fail(f"Could not read the Quantro report: {exc}") from exc
    store.replace(ctx, findings, {"quantro"})
    _print_warnings(ctx)
    console.print(
        f"Ingested [bold]{len(findings)}[/bold] findings from the Quantro report. "
        "Next: [bold]webscan prioritize[/bold]."
    )


# --------------------------------------------------------------------------- prioritize / report


def _current_result(ctx: RunContext, input_file: Path | None = None) -> ScanResult:
    if input_file is not None:
        try:
            raw = store.load_findings_file(ctx, input_file)
        except (OSError, ValueError) as exc:
            raise _fail(f"Could not read the input file: {exc.__class__.__name__}") from exc
    else:
        raw = store.load_raw(ctx)
    if not raw:
        raise _fail(
            "No findings yet. Run `webscan scan --all`, `webscan ingest-quantro <file>`, or `webscan demo` first."
        )
    result = prioritize(ctx, raw)
    store.save_result(ctx, ctx.redactor.redact_obj(result.to_dict()))
    return result


@app.command("prioritize")
def prioritize_cmd(
    input_file: Annotated[
        Path | None, typer.Option("--input", help="Prioritize findings from a JSON file instead of stored state.")
    ] = None,
    lang: LangOpt = Lang.en,
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
    no_redact: NoRedactOpt = False,
) -> None:
    """Score, sort, and batch all current findings."""
    ctx = _context(
        "prioritize", operator=operator, config_dir=config_dir, use_examples=example_config, no_redact=no_redact,
        lang=lang.value,
    )
    from webscan.history import record_run
    from webscan.reporting import terminal

    result = _current_result(ctx, input_file)
    record_run(ctx, result)
    terminal.render(result, ctx, console)


def _write_outputs(ctx: RunContext, result: ScanResult, formats: list[Format], both_languages: bool = False) -> list[Path]:
    from webscan.reporting import export, html_report

    out = ctx.output_dir
    lang = ctx.lang
    written: list[Path] = []
    if Format.json in formats:
        written.append(export.export_json(result, ctx, out / "webscan_findings.json"))
    if Format.csv in formats:
        written.append(export.export_csv(result, ctx, out / "webscan_findings.csv"))
        written.append(export.export_batches_csv(result, ctx, out / "webscan_batches.csv"))
    if Format.html in formats or Format.pdf in formats:
        languages = ["en", "es"] if both_languages else [lang]
        for code in languages:
            other = "es" if code == "en" else "en"
            alt = f"webscan_report_{other}.html" if both_languages else None
            html_path = html_report.write_html(result, ctx, out / f"webscan_report_{code}.html", code, alt)
            if Format.html in formats:
                written.append(html_path)
            if Format.pdf in formats and code == lang:
                ok, detail = html_report.write_pdf(html_path, out / f"webscan_report_{code}.pdf")
                if ok:
                    written.append(out / f"webscan_report_{code}.pdf")
                    if Format.html not in formats:
                        written.append(html_path)
                else:
                    console.print(f"[yellow]PDF not created:[/yellow] {detail}")
                    if html_path not in written:
                        written.append(html_path)
    ctx.audit.log("report", mode=result.meta["data_mode"], status="ok", formats=[f.value for f in formats],
                  files=[p.name for p in written])
    return written


def _list_files(ctx: RunContext, paths: list[Path]) -> None:
    if not paths:
        return
    from webscan.knowledge.base import ui

    console.print(f"\n[bold]{ui(ctx.lang)['files_written']}:[/bold]")
    for path in paths:
        try:
            shown = path.relative_to(ctx.settings.root)
        except ValueError:
            shown = path
        console.print(f"  {shown}")


@app.command()
def report(
    lang: LangOpt = Lang.en,
    fmt: Annotated[Format, typer.Option("--format", help="Output format.")] = Format.terminal,
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
    no_redact: NoRedactOpt = False,
) -> None:
    """Produce a report from the current findings."""
    ctx = _context(
        "report", operator=operator, config_dir=config_dir, use_examples=example_config, no_redact=no_redact,
        lang=lang.value,
    )
    result = _current_result(ctx)
    if fmt is Format.terminal:
        from webscan.reporting import terminal

        terminal.render(result, ctx, console)
        ctx.audit.log("report", mode=result.meta["data_mode"], status="ok", formats=["terminal"])
        return
    _list_files(ctx, _write_outputs(ctx, result, [fmt]))


# --------------------------------------------------------------------------- demo


@app.command()
def demo(
    lang: LangOpt = Lang.en,
    include_wip: Annotated[
        bool, typer.Option("--include-wip", help="Also include mock results from WIP stub providers.")
    ] = False,
    pdf: Annotated[bool, typer.Option("--pdf/--no-pdf", help="Also try to create a PDF report.")] = True,
    operator: OperatorOpt = None,
    no_redact: NoRedactOpt = False,
) -> None:
    """Run the full pipeline on mock data. Uses no network and needs no configuration."""
    ctx = _context("demo", operator=operator, demo=True, no_redact=no_redact, lang=lang.value)
    from webscan.history import record_run
    from webscan.reporting import terminal

    started = time.perf_counter()
    raw = run_demo_collection(ctx, include_wip=include_wip)
    store.save_raw(ctx, raw)
    result = prioritize(ctx, raw)
    store.save_result(ctx, ctx.redactor.redact_obj(result.to_dict()))
    record_run(ctx, result)
    terminal.render(result, ctx, console)
    formats = [Format.json, Format.csv, Format.html] + ([Format.pdf] if pdf else [])
    written = _write_outputs(ctx, result, formats, both_languages=True)
    ctx.audit.log(
        "demo", mode="mock", status="ok", findings=len(result.findings), grade=result.summary.grade,
        duration_ms=(time.perf_counter() - started) * 1000,
    )
    _list_files(ctx, written)


# --------------------------------------------------------------------------- reference data


@app.command("refresh-reference-data")
def refresh_reference_data(operator: OperatorOpt = None) -> None:
    """Update the local CISA KEV and EPSS snapshots (downloads public files; sends no target data)."""
    from webscan.enrichment.reference import EPSS_URL, KEV_URL, ReferenceDataError, refresh

    settings = load_settings()
    audit = AuditLogger(settings.log_dir / "audit.jsonl", operator=operator, command="refresh-reference-data")
    console.print(f"Downloading public reference files:\n  {KEV_URL}\n  {EPSS_URL}")
    started = time.perf_counter()
    try:
        counts = refresh(settings.data_dir / "reference")
    except (ReferenceDataError, OSError, ValueError) as exc:
        audit.log("refresh_reference_data", mode="live", status="error", detail=exc.__class__.__name__,
                  duration_ms=(time.perf_counter() - started) * 1000)
        raise _fail(f"Refresh failed ({exc.__class__.__name__}: {exc}). The existing snapshots were kept.") from exc
    except Exception as exc:  # noqa: BLE001 - network libraries raise many types; keep old data
        audit.log("refresh_reference_data", mode="live", status="error", detail=exc.__class__.__name__,
                  duration_ms=(time.perf_counter() - started) * 1000)
        raise _fail(f"Refresh failed ({exc.__class__.__name__}). The existing snapshots were kept.") from exc
    audit.log("refresh_reference_data", mode="live", status="ok", duration_ms=(time.perf_counter() - started) * 1000,
              kev=counts["kev"], epss=counts["epss"])
    console.print(f"[green]Updated.[/green] KEV entries: {counts['kev']}; EPSS scores: {counts['epss']}")


# --------------------------------------------------------------------------- later-phase commands


@app.command()
def changes(
    lang: LangOpt = Lang.en,
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
    demo_data: Annotated[bool, typer.Option("--demo", help="Compare demo runs instead of real runs.")] = False,
) -> None:
    """Show what changed between the two most recent prioritized runs."""
    ctx = _context(
        "changes", operator=operator, config_dir=config_dir, use_examples=example_config, demo=demo_data,
        lang=lang.value,
    )
    from webscan.history import latest_changes, render_changes

    diff = latest_changes(ctx)
    if diff is None:
        raise _fail("Need at least two recorded runs. Run `webscan prioritize` (or `webscan demo`) again later.")
    render_changes(diff, ctx, console)
    ctx.audit.log("changes", status="ok", new=len(diff["new"]), resolved=len(diff["resolved"]))


@app.command()
def dashboard(
    host: Annotated[str, typer.Option("--host", help="Interface to bind. Keep the default for local use.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8765,
    demo_data: Annotated[bool, typer.Option("--demo", help="Serve demo data.")] = False,
    operator: OperatorOpt = None,
    config_dir: ConfigDirOpt = None,
    example_config: ExampleOpt = False,
) -> None:
    """Start the optional local web dashboard (needs: pip install -e ".[dashboard]")."""
    try:
        import uvicorn

        from webscan.dashboard.app import create_app
    except ImportError as exc:
        raise _fail('The dashboard needs extra packages. Install them with: pip install -e ".[dashboard]"') from exc
    ctx = _context("dashboard", operator=operator, config_dir=config_dir, use_examples=example_config, demo=demo_data)
    ctx.audit.log("dashboard_start", status="ok", detail=f"port {port}")
    console.print(f"Dashboard on http://{host}:{port}  (Ctrl+C to stop)")
    uvicorn.run(create_app(ctx), host=host, port=port, log_level="warning")


@app.command()
def web() -> None:
    """Start the local web UI (needs: pip install -e ".[web]"). Hosts and ports come from .env."""
    try:
        from webscan.web.server import PortInUseError, serve
        from webscan.web.settings import WebConfigError, WebSettings
    except ImportError as exc:
        raise _fail('The web UI needs extra packages. Install them with: pip install -e ".[web]"') from exc
    settings = load_settings()
    try:
        web_settings = WebSettings.from_env(settings.env)
    except WebConfigError as exc:
        raise _fail(f"CONFIG ERROR: {exc}") from exc
    console.print(f"WebScan UI:  [bold]{web_settings.ui_origin}[/bold]")
    console.print(f"WebScan API: {web_settings.api_origin}/api  (local only)")
    live = "on" if settings.live_mode_env else "off (demo mode only; set WEBSCAN_LIVE_MODE=true in .env for real scans)"
    console.print(f"Live scanning: {live}")
    console.print("Press Ctrl+C to stop.")
    try:
        serve(settings, web_settings)
    except PortInUseError as exc:
        raise _fail(str(exc)) from exc
    except ImportError as exc:
        raise _fail('The web UI needs extra packages. Install them with: pip install -e ".[web]"') from exc


if __name__ == "__main__":
    app()
