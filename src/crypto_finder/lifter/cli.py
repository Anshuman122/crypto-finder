
import typer
from pathlib import Path
from crypto_finder.lifter.core import Lifter
from crypto_finder.common.logging import log
import os

def lift(
    binary_path: Path = typer.Option(
        ...,
        "--binary-path",
        "-b",
        help="The path to the binary file to be lifted.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        "-o",
        help="The directory where the lifted JSON output will be saved.",
        file_okay=False,
        dir_okay=True,
        writable=True,
    )
):

    log.info(f"CLI command invoked to lift '{binary_path.name}'.")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    lifter = Lifter()
    result_path = lifter.process_binary(binary_path, output_dir)
    
    if result_path:
        typer.secho(f" Analysis complete! Output at: {result_path}", fg=typer.colors.GREEN)
    else:
        typer.secho(f" Analysis failed. Check logs for details.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
