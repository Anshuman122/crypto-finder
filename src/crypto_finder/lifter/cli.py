# Hinglish: Typer ka use karke ek modern aur easy-to-use CLI.
# Isse lifter ko terminal se run karna aasaan ho jaata hai.

import typer
from pathlib import Path
from crypto_finder.lifter.core import Lifter
from crypto_finder.common.logging import log

# Typer application object banao.
app = typer.Typer(help="Crypto Finder's Binary Lifting Tool using Ghidra.")

@app.command()
def lift(
    binary_path: Path = typer.Option(
        ..., # ... matlab yeh option required hai.
        "--binary-path",
        "-b",
        help="The path to the binary file to be lifted.",
        exists=True,      # File ka exist karna zaroori hai.
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
    """
    Analyzes a single binary file with Ghidra and saves the output.
    Ek binary file ko analyze karke output save karta hai.
    """
    log.info(f"CLI command invoked to lift '{binary_path.name}'.")
    
    # Output directory agar exist nahi karti to banao.
    output_dir.mkdir(parents=True, exist_ok=True)
    
    lifter = Lifter()
    result_path = lifter.process_binary(binary_path, output_dir)
    
    if result_path:
        typer.secho(f"✅ Analysis complete! Output at: {result_path}", fg=typer.colors.GREEN)
    else:
        typer.secho(f"❌ Analysis failed. Check logs for details.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

# Is file ko directly run karne ke liye (optional)
if __name__ == "__main__":
    app()