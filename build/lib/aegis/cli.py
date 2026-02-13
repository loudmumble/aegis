import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .config import AegisConfig
from .llm import OllamaClient
from .capture.flows import FlowTracker
from .capture.reader import PcapReader
from .detection.cadence import CadenceAnalyzer, CadenceClassification, CadenceResult
from .detection.rules import RuleEngine, RuleMatch
from .detection.analyzer import ThreatAnalyzer, ThreatVerdict
from .alerting.pipeline import AlertPipeline


console = Console()


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


@click.group()
@click.version_option(__version__, prog_name="aegis")
def main() -> None:
    """Aegis -- Agentic Intrusion Detection System"""
    pass


@main.command()
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to aegis config YAML file.",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    help="Skip LLM threat analysis (cadence + rules only).",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def analyze(
    pcap_path: str,
    config: str | None,
    skip_llm: bool,
    verbose: bool,
) -> None:
    """Analyze a PCAP file for agentic traffic patterns."""
    pcap_file = Path(pcap_path).resolve()

    cfg = AegisConfig.from_file(Path(config)) if config else AegisConfig()
    cfg.verbose = verbose
    cfg.ensure_dirs()

    _print_banner()

    analysis_start = time.time()

    # Phase 1: Extract flows
    console.print("[bold]Phase 1: Extracting network flows...[/]")
    tracker = FlowTracker(flow_timeout=cfg.capture.flow_timeout)
    reader = PcapReader(tracker)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        _ = progress.add_task("Reading PCAP...", total=None)
        flows = reader.read_pcap(pcap_file)

    console.print(f"  Extracted [bold]{len(flows)}[/] flows")
    total_pkts = sum(f.packet_count for f in flows)
    console.print(f"  Total packets: [bold]{total_pkts:,}[/]")

    if not flows:
        console.print("[yellow]No flows found in PCAP.[/]")
        sys.exit(0)

    # Phase 2: Cadence analysis
    console.print("\n[bold]Phase 2: Cadence analysis (ITT fingerprinting)...[/]")
    cadence_analyzer = CadenceAnalyzer(cfg.cadence)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        _ = progress.add_task("Analyzing timing patterns...", total=None)
        cadence_results = cadence_analyzer.analyze_flows(flows)

    _print_cadence_summary(cadence_results)

    # Phase 3: Rule evaluation
    console.print("\n[bold]Phase 3: Rule evaluation...[/]")
    engine = RuleEngine(
        rules_dir=cfg.rules.rules_dir,
        builtin_enabled=cfg.rules.builtin_enabled,
    )
    rule_matches = engine.evaluate_all(cadence_results, flows)

    if rule_matches:
        _print_rule_matches(rule_matches)
    else:
        console.print("  [green]No rules triggered.[/]")

    # Phase 4: LLM threat analysis
    threat_verdict = None
    if not skip_llm:
        suspicious = [
            r
            for r in cadence_results
            if r.classification
            in (CadenceClassification.AGENT, CadenceClassification.MIXED)
        ]
        if suspicious:
            console.print("\n[bold]Phase 4: LLM threat analysis...[/]")
            llm = OllamaClient(cfg.ollama)

            with console.status("[bold cyan]Checking Ollama connectivity..."):
                if not llm.is_available():
                    console.print(
                        f"[bold red]Cannot reach Ollama at {cfg.ollama.base_url}[/]"
                    )
                    console.print("Use --skip-llm for cadence-only analysis.")
                    skip_llm = True

            if not skip_llm:
                analyzer = ThreatAnalyzer(cfg, llm)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                    transient=True,
                ) as progress:
                    _ = progress.add_task("LLM reasoning...", total=None)
                    threat_verdict = analyzer.analyze(cadence_results, flows)

                _print_threat_verdict(threat_verdict)
                llm.close()
        else:
            console.print("\n[dim]Phase 4: Skipped — no agent-like flows detected.[/]")
    else:
        console.print("\n[dim]Phase 4: Skipped (--skip-llm)[/]")

    # Phase 5: Alert generation
    console.print("\n[bold]Phase 5: Generating alerts...[/]")
    pipeline = AlertPipeline(cfg.alerts)
    alerts = pipeline.process(cadence_results, rule_matches, threat_verdict)

    analysis_time = time.time() - analysis_start

    if alerts:
        console.print(f"  [bold red]{len(alerts)} alert(s) generated[/]")
        if cfg.alerts.json_log_enabled:
            console.print(f"  Log: {cfg.alerts.json_log_path}")
    else:
        console.print("  [green]No alerts generated — traffic appears clean.[/]")

    console.print(f"\n[bold]Analysis complete.[/] Total time: {analysis_time:.1f}s\n")


@main.command()
@click.option(
    "--pattern",
    "-p",
    type=click.Choice(["agent", "human", "mixed"]),
    default="agent",
    help="Traffic pattern to simulate.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./aegis-data/test.pcap",
    help="Output PCAP file path.",
)
def generate(pattern: str, output: str) -> None:
    """Generate synthetic PCAP for testing cadence detection."""
    _print_banner()

    output_path = Path(output)
    console.print(f"Generating [bold]{pattern}[/] traffic pattern...")

    try:
        result = PcapReader.generate_test_pcap(output_path, pattern=pattern)
        console.print(f"[green]Generated:[/] {result}")
        console.print(f"\nRun: [bold]aegis analyze {result}[/]")
    except RuntimeError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)


@main.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to aegis config YAML file.",
)
def rules(config: str | None) -> None:
    """List all detection rules."""
    cfg = AegisConfig.from_file(Path(config)) if config else AegisConfig()

    engine = RuleEngine(
        rules_dir=cfg.rules.rules_dir,
        builtin_enabled=cfg.rules.builtin_enabled,
    )

    table = Table(title="Aegis Detection Rules", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Tags")
    table.add_column("Enabled")

    for rule in engine.rules:
        sev_style = SEVERITY_STYLES.get(rule.severity, "dim")
        table.add_row(
            rule.id,
            rule.name,
            f"[{sev_style}]{rule.severity.upper()}[/]",
            ", ".join(rule.tags),
            "[green]Yes[/]" if rule.enabled else "[red]No[/]",
        )

    console.print(table)
    console.print(f"\n[bold]{len(engine.rules)}[/] rules loaded")


def _print_banner() -> None:
    banner = """[bold cyan]
    _    _____ ____ ___ ____
   / \\  | ____/ ___|_ _/ ___|
  / _ \\ |  _|| |  _ | |\\___ \\
 / ___ \\| |__| |_| || | ___) |
/_/   \\_\\_____\\____|___|____/
[/]"""
    console.print(banner)
    console.print(f"[dim]Agentic Intrusion Detection System v{__version__}[/]\n")


def _print_cadence_summary(results: list[CadenceResult]) -> None:
    """Print summary of cadence analysis results."""
    if not results:
        console.print("  [dim]No flows with sufficient data for analysis.[/]")
        return

    counts: dict[str, int] = {}
    for r in results:
        key = r.classification.value
        counts[key] = counts.get(key, 0) + 1

    table = Table(show_header=True, header_style="bold")
    table.add_column("Classification")
    table.add_column("Count", justify="right")

    class_styles = {
        "agent": "bold red",
        "mixed": "yellow",
        "human": "green",
        "unknown": "dim",
    }
    for cls_name in ["agent", "mixed", "human", "unknown"]:
        count = counts.get(cls_name, 0)
        style = class_styles.get(cls_name, "dim") if count > 0 else "dim"
        table.add_row(f"[{style}]{cls_name.upper()}[/]", f"[{style}]{count}[/]")

    console.print(table)

    # Show details for suspicious flows
    suspicious = [
        r
        for r in results
        if r.classification
        in (CadenceClassification.AGENT, CadenceClassification.MIXED)
    ]
    if suspicious:
        console.print(f"\n  [bold red]Suspicious flows ({len(suspicious)}):[/]")
        for r in suspicious:
            style = (
                "red" if r.classification == CadenceClassification.AGENT else "yellow"
            )
            console.print(
                f"    [{style}]{r.classification.value.upper()}[/] "
                + f"{r.flow_key_str} — "
                + f"confidence: {r.confidence:.0%}, "
                + f"IAT: {r.mean_iat_ms:.1f}ms ± {r.std_iat_ms:.1f}ms"
            )
            if r.best_model_match:
                console.print(f"      Model match: [bold]{r.best_model_match}[/]")
            if r.transition_detected:
                console.print(
                    f"      [yellow]Transition detected at packet ~{r.transition_index}[/]"
                )


def _print_rule_matches(matches: list[RuleMatch]) -> None:
    """Print rule match summary."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Flow")
    table.add_column("Conditions")

    for match in matches:
        style = SEVERITY_STYLES.get(match.severity, "dim")
        table.add_row(
            f"[{style}]{match.severity.upper()}[/]",
            match.rule.name,
            match.flow_key[:40] + ("..." if len(match.flow_key) > 40 else ""),
            "; ".join(match.matched_conditions[:3]),
        )

    console.print(table)
    console.print(f"  [bold]{len(matches)}[/] rule(s) triggered")


def _print_threat_verdict(verdict: ThreatVerdict) -> None:
    """Print LLM threat analysis verdict."""
    style = SEVERITY_STYLES.get(verdict.severity, "dim")

    panel_content = (
        f"[{style}]{verdict.classification.upper()}[/] — "
        + f"Severity: [{style}]{verdict.severity.upper()}[/]\n"
        + f"Confidence: {verdict.confidence:.0%}"
    )

    console.print(Panel(panel_content, title="Threat Verdict", border_style=style))

    if verdict.summary:
        console.print(f"\n  {verdict.summary}")

    if verdict.intent_chains:
        console.print(f"\n  [bold]Intent Chains ({len(verdict.intent_chains)}):[/]")
        for chain in verdict.intent_chains:
            console.print(
                f"    [{style}]{chain.attack_type.upper()}[/] "
                + f"(confidence: {chain.confidence:.0%})"
            )
            for step in chain.steps[:5]:
                console.print(f"      - {step.get('action', '')}")

    if verdict.mitre_techniques:
        console.print(f"\n  [bold]MITRE ATT&CK:[/]")
        for t in verdict.mitre_techniques[:8]:
            console.print(f"    {t.get('id', '')} {t.get('name', '')}")

    if verdict.recommended_actions:
        console.print(f"\n  [bold]Recommended Actions:[/]")
        for action in verdict.recommended_actions[:5]:
            console.print(f"    - {action}")
