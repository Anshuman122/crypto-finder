# Hinglish: Yeh hamari application ka main entry point hai.
# Yeh ek "router" ki tarah kaam karta hai jo alag-alag commands (jaise 'lift', 'scan') ko unke respective modules se jodta hai.

import typer
from crypto_finder.common.logging import log

# Alag-alag modules se unke CLI 'app' object ko import karo.
from crypto_finder.lifter.cli import app as lifter_app
# from crypto_finder.static_scanner.cli import app as scanner_app # (Ise hum baad me add karenge)

# Main Typer application object banao.
app = typer.Typer(
    name="crypto-finder",
    help="A robust framework for finding cryptographic primitives in firmware. 🚀",
    add_completion=False, # Shell completion ko disable kar do, for simplicity.
)

# Lifter module ke saare commands ko 'lift' subcommand ke andar add karo.
# Ab aap 'crypto-finder lift --binary-path ...' use kar sakte hain.
app.add_typer(lifter_app, name="lift")

# Yahan hum baad me aur bhi commands add karenge.
# app.add_typer(scanner_app, name="scan")


@app.callback()
def main_callback():
    """
    Crypto Finder CLI - Use a command like 'lift' to get started.
    """
    log.info("Crypto Finder main CLI invoked.")

if __name__ == "__main__":
    app()