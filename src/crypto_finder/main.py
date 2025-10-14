import typer
from crypto_finder.common.logging import log
from crypto_finder.lifter.cli import lift
from crypto_finder.static_scanner.cli import scan
from crypto_finder.symbolic.cli import analyze_loops
from crypto_finder.dynamic_runner.cli import dynamic_run

app = typer.Typer(
    name="crypto-finder",
    help="A robust framework for finding cryptographic primitives in firmware. 🚀",
    add_completion=False,
)

app.command(name="lift")(lift)
app.command(name="scan")(scan)
app.command(name="symbolic-loops")(analyze_loops)
app.command(name="dynamic-run")(dynamic_run)


@app.callback()
def main_callback():

    log.info("Crypto Finder main CLI invoked.")

if __name__ == "__main__":
    app()
