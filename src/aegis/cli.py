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
from .llm import HybridLLMClient
from .capture.flows import FlowTracker
from .capture.reader import PcapReader
from .detection.cadence import CadenceAnalyzer, CadenceClassification, CadenceResult
from .detection.rules import RuleEngine, RuleMatch
from .detection.analyzer import ThreatAnalyzer, ThreatVerdict
from .alerting.pipeline import AlertPipeline
from .capture.live import LiveCapture, AnalysisCycleResult, MonitorStats


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
            llm = HybridLLMClient(cfg.llm)

            with console.status("[bold cyan]Checking LLM connectivity..."):
                if not llm.is_available():
                    console.print("[bold red]No LLM backend available[/]")
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


@main.command()
@click.option(
    "--interface",
    "-i",
    type=str,
    default="any",
    help="Network interface to capture on (default: any).",
)
@click.option(
    "--filter",
    "-f",
    "bpf_filter",
    type=str,
    default="tcp",
    help="BPF filter expression (default: tcp).",
)
@click.option(
    "--interval",
    type=float,
    default=10.0,
    help="Analysis interval in seconds (default: 10).",
)
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
    help="Skip LLM threat analysis.",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
@click.option(
    "--pcap-dir",
    type=click.Path(),
    default="./aegis-data/pcap/live",
    help="Directory for PCAP ring buffer segments (default: ./aegis-data/pcap/live).",
)
@click.option(
    "--preserve",
    is_flag=True,
    help="Enable PCAP ring buffer (requires tcpdump).",
)
@click.option(
    "--kernel-net",
    is_flag=True,
    help="Enable eBPF kernel network monitoring for PID attribution (requires ebpf-sensors).",
)
def monitor(
    interface: str,
    bpf_filter: str,
    interval: float,
    config: str | None,
    skip_llm: bool,
    verbose: bool,
    pcap_dir: str,
    preserve: bool,
    kernel_net: bool,
) -> None:
    """Live network monitoring for agentic traffic patterns.

    Captures packets in real-time and analyzes them for C2 beaconing,
    LLM-driven traffic, and other agentic attack indicators.

    Requires elevated privileges (sudo) for packet capture on most systems.
    """
    cfg = AegisConfig.from_file(Path(config)) if config else AegisConfig()
    cfg.verbose = verbose
    cfg.capture.interface = interface
    cfg.capture.bpf_filter = bpf_filter
    cfg.ensure_dirs()

    pcap_buffer = None
    if preserve:
        from .capture.pcap_buffer import PcapRingBuffer

        pcap_buffer = PcapRingBuffer(pcap_dir=Path(pcap_dir))

    kernel_collector = None
    if kernel_net:
        from .capture.kernel_net import ebpf_sensors_available, KernelNetCollector

        if ebpf_sensors_available():
            try:
                kernel_collector = KernelNetCollector()
            except RuntimeError as exc:
                console.print(
                    f"[yellow]Warning: Could not initialize kernel net collector: {exc}[/]"
                )
        else:
            console.print(
                "[yellow]Warning: --kernel-net requires ebpf-sensors package. "
                "Install with: pip install ebpf-sensors[/]"
            )

    _print_banner()
    console.print("[bold]Live Network Monitoring[/]")
    console.print(f"  Interface: [bold]{interface}[/]")
    console.print(f"  BPF filter: [bold]{bpf_filter}[/]")
    console.print(f"  Analysis interval: [bold]{interval}s[/]")
    console.print(f"  Rules loaded: [bold]{9}[/] (7 builtin + 2 C2 beaconing)")
    if pcap_buffer:
        console.print(f"  PCAP ring buffer: [bold]{pcap_dir}[/]")
    if kernel_collector:
        console.print("  Kernel net monitor: [bold green]enabled[/]")
    console.print("\n  Press [bold]Ctrl+C[/] to stop monitoring.\n")
    console.rule("[bold cyan]Live Capture Active[/]")

    live = LiveCapture(
        capture_config=cfg.capture,
        cadence_config=cfg.cadence,
        rules_dir=cfg.rules.rules_dir,
        analysis_interval=interval,
        pcap_buffer=pcap_buffer,
        kernel_net_collector=kernel_collector,
    )

    def on_result(result: AnalysisCycleResult) -> None:
        """Print analysis results in real-time."""
        if not result.cadence_results and not result.rule_matches:
            if verbose:
                console.print(
                    f"  [dim]Cycle {result.cycle_number}: no analyzable flows[/]"
                )
            return

        ts = time.strftime("%H:%M:%S")

        for cr in result.cadence_results:
            style = (
                "red"
                if cr.classification.value == "agent"
                else ("yellow" if cr.classification.value == "mixed" else "green")
            )
            console.print(
                f"  [{style}][{ts}][/] "
                f"[{style}]{cr.classification.value.upper():>7}[/] "
                f"{cr.flow_key_str} "
                f"IAT={cr.mean_iat_ms:.0f}ms CV={cr.cv:.3f} "
                f"conf={cr.confidence:.0%}"
            )
            if cr.best_model_match:
                console.print(f"           Model: [bold]{cr.best_model_match}[/]")

        for rm in result.rule_matches:
            sev_style = SEVERITY_STYLES.get(rm.severity, "dim")
            console.print(
                f"  [bold {sev_style}][{ts}] ALERT: {rm.rule.name}[/] "
                f"({rm.severity.upper()}) -- {rm.flow_key[:50]}"
            )
            for cond in rm.matched_conditions[:3]:
                console.print(f"           {cond}")

    if pcap_buffer:
        pcap_buffer.start(interface=interface, bpf_filter=bpf_filter)

    try:
        live.start(on_result=on_result)
    except PermissionError:
        console.print(
            "\n[bold red]Permission denied.[/] Live capture requires elevated privileges."
        )
        console.print("Run with: [bold]sudo aegis monitor[/]")
        sys.exit(1)
    except RuntimeError as e:
        console.print(f"\n[bold red]Error:[/] {e}")
        sys.exit(1)
    finally:
        if pcap_buffer:
            pcap_buffer.stop()
        stats = live.stats
        console.rule("[bold cyan]Monitoring Complete[/]")
        console.print(f"\n  Packets captured: [bold]{stats.packets_captured:,}[/]")
        console.print(f"  Flows analyzed:   [bold]{stats.flows_analyzed}[/]")
        console.print(f"  Alerts generated: [bold]{stats.alerts_generated}[/]")
        console.print(f"  Analysis cycles:  [bold]{stats.analysis_cycles}[/]")
        console.print(f"  Uptime:           [bold]{stats.uptime_seconds:.1f}s[/]")
        console.print(
            f"  Rate:             [bold]{stats.packets_per_second:.1f} pkt/s[/]"
        )
        if pcap_buffer:
            console.print(
                f"  PCAP segments:    [bold]{pcap_buffer.segments_written}[/] written, "
                f"[bold]{pcap_buffer.segments_preserved}[/] preserved"
            )


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
