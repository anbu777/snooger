"""
Interactive TUI — Rich-based terminal interface for Snooger.
Provides progress bars, styled prompts, and tables.
"""
import sys
import logging
from typing import List, Optional

logger = logging.getLogger('snooger')

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


def get_user_choice(prompt: str, options: List[str], default: int = 1) -> str:
    """Interactive numbered choice menu with Rich styling."""
    if HAS_RICH:
        console.print(f"\n[bold cyan]{prompt}[/bold cyan]")
        for i, opt in enumerate(options, 1):
            marker = " [dim](default)[/dim]" if i == default else ""
            console.print(f"  [bold white][{i}][/bold white] {opt}{marker}")
        while True:
            try:
                raw = Prompt.ask(
                    f"[yellow]Choice [1-{len(options)}][/yellow]",
                    default=str(default)
                )
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return options[idx]
                console.print(f"  [red]Enter a number between 1 and {len(options)}[/red]")
            except (ValueError, KeyboardInterrupt):
                console.print("\n[red][!] Interrupted.[/red]")
                sys.exit(0)
    else:
        print(f"\n{prompt}")
        for i, opt in enumerate(options, 1):
            marker = " (default)" if i == default else ""
            print(f"  [{i}] {opt}{marker}")
        while True:
            try:
                raw = input(f"Choice [1-{len(options)}]: ").strip()
                if not raw:
                    return options[default - 1]
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            except (ValueError, EOFError, KeyboardInterrupt):
                print("\n[!] Interrupted.")
                sys.exit(0)


def get_user_input(prompt: str, default: str = '') -> str:
    """Get text input from user."""
    if HAS_RICH:
        return Prompt.ask(f"[cyan]{prompt}[/cyan]", default=default)
    else:
        display = f" [{default}]" if default else ""
        try:
            raw = input(f"{prompt}{display}: ").strip()
            return raw if raw else default
        except (EOFError, KeyboardInterrupt):
            return default


def confirm_action(msg: str, default: bool = False) -> bool:
    """Yes/no confirmation prompt."""
    if HAS_RICH:
        try:
            return Confirm.ask(f"[yellow]{msg}[/yellow]", default=default)
        except (EOFError, KeyboardInterrupt):
            return False
    else:
        hint = "Y/n" if default else "y/N"
        try:
            resp = input(f"{msg} ({hint}): ").strip().lower()
            if not resp:
                return default
            return resp in ('y', 'yes')
        except (EOFError, KeyboardInterrupt):
            return False


def print_banner(version: str = "3.0") -> None:
    """Print the Snooger banner."""
    banner = r"""
 ░▒▓███████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓███████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒▒▓███▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░
"""
    if HAS_RICH:
        console.print(f"[bold red]{banner}[/bold red]")
        console.print(f"[bold white]          v{version} Professional | Pentesting Framework | Kali Linux Edition[/bold white]\n")
    else:
        print(banner)
        print(f"          v{version} Professional | Pentesting Framework | Kali Linux Edition\n")


def print_phase_header(phase_num: int, phase_name: str) -> None:
    """Print a styled phase header."""
    if HAS_RICH:
        console.print(Panel(
            f"[bold white]PHASE {phase_num}[/bold white] — {phase_name}",
            style="bold cyan", width=60
        ))
    else:
        print(f"\n{'='*60}")
        print(f"  [PHASE {phase_num}] {phase_name}")
        print(f"{'='*60}")


def print_finding(severity: str, message: str) -> None:
    """Print a finding with severity color."""
    colors = {
        'critical': 'bold red',
        'high': 'bold yellow',
        'medium': 'yellow',
        'low': 'green',
        'info': 'dim',
    }
    if HAS_RICH:
        color = colors.get(severity.lower(), 'white')
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '⚪'}.get(severity.lower(), '')
        console.print(f"  {emoji} [{color}][{severity.upper()}][/{color}] {message}")
    else:
        print(f"  [{severity.upper()}] {message}")


def print_summary_table(data: dict) -> None:
    """Print a summary table of scan results."""
    if HAS_RICH:
        table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="white")
        table.add_column("Value", style="bold white", justify="right")
        for key, value in data.items():
            table.add_row(key, str(value))
        console.print(table)
    else:
        for key, value in data.items():
            print(f"  {key}: {value}")


def create_progress() -> Optional['Progress']:
    """Create a Rich progress bar context manager."""
    if HAS_RICH:
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        )
    return None
