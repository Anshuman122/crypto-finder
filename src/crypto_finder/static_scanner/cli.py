import typer
from pathlib import Path
import json
from crypto_finder.static_scanner.core import StaticScanner
from crypto_finder.common.logging import log
from crypto_finder.common.config import settings, ROOT_DIR

DEFAULT_RULES_PATH = ROOT_DIR / "src" / "crypto_finder" / "static_scanner" / "signatures" / "findcrypt.yar"

def scan(
    binary_path: Path = typer.Option(
        ...,
        "--binary-path",
        "-b",
        help="The binary file to scan.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    rules_path: Path = typer.Option(
        DEFAULT_RULES_PATH,
        "--rules-path",
        "-r",
        help="Path to the YARA rules file.",
        exists=True,
        file_okay=True,
    ),
    output_json: Path = typer.Option(
        None,
        "--output-json",
        "-o",
        help="Optional path to save results as a JSON file.",
        dir_okay=False,
        writable=True,
    ),
):

    log.info(f"CLI command invoked to scan '{binary_path.name}'.")
    try:
        scanner = StaticScanner(rules_path=rules_path)
        results = scanner.scan(binary_path=binary_path)

        if not results:
            typer.secho("No cryptographic signatures found.", fg=typer.colors.YELLOW)
            return

        typer.secho(f"Found {len(results)} potential cryptographic signature(s):", fg=typer.colors.GREEN, bold=True)
        for result in results:
            typer.secho(f"\n--- Rule: {result['rule']} ({result['crypto_name']}) ---", fg=typer.colors.CYAN)
            for match in result['matches']:
                typer.echo(f"  - Found at offset {hex(match['offset'])} with data preview: {match['data'][:32]}...")

        if output_json:
            with open(output_json, 'w') as f:
                json.dump(results, f, indent=4)
            typer.secho(f"\nResults saved to {output_json}", fg=typer.colors.BRIGHT_BLUE)

    except Exception as e:
        log.error(f"Scan failed: {e}")
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
