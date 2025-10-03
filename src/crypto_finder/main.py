# Hinglish: Hum yahan main.py ko update kar rahe hain taaki naya 'dynamic-run' command add ho sake.

import typer
from crypto_finder.common.logging import log

# Lifter, Static Scanner, Symbolic, aur Dynamic se unke CLI functions ko import karo.
from crypto_finder.lifter.cli import lift
from crypto_finder.static_scanner.cli import scan
from crypto_finder.symbolic.cli import analyze_loops
from crypto_finder.dynamic_runner.cli import dynamic_run

# Main Typer application object.
app = typer.Typer(
    name="crypto-finder",
    help="A robust framework for finding cryptographic primitives in firmware. 🚀",
    add_completion=False,
)

# Har function ko ek alag command ke roop me register karo.
app.command(name="lift")(lift)
app.command(name="scan")(scan)
app.command(name="symbolic-loops")(analyze_loops)
app.command(name="dynamic-run")(dynamic_run)


@app.callback()
def main_callback():
    """
    Crypto Finder CLI - Use a command like 'lift', 'scan', 'dynamic-run' etc. to get started.
    """
    log.info("Crypto Finder main CLI invoked.")

if __name__ == "__main__":
    app()