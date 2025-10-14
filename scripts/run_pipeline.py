

import typer
from pathlib import Path

from crypto_finder.common.logging import log
from crypto_finder.common.db import SessionLocal, Binary, AnalysisResult, create_db_and_tables
from crypto_finder.static_scanner.core import StaticScanner

DEFAULT_RULES_PATH = Path(__file__).parent.parent / "src" / "crypto_finder" / "static_scanner" / "signatures" / "findcrypt.yar"

app = typer.Typer()

@app.command()
def run(
    binary_path: Path = typer.Option(..., "--binary-path", "-b", help="The binary file to analyze.", exists=True),
):
    """Runs the full analysis pipeline on a single binary file."""
    log.info(f"Full pipeline run for '{binary_path.name}' shuru ho raha hai.")
    
    db = SessionLocal()
    create_db_and_tables()
    
    try:
 
        db_binary = db.query(Binary).filter(Binary.filepath == str(binary_path)).first()
        if not db_binary:
            log.info("Yeh naya binary hai. Isse database me add kiya ja raha hai.")
            db_binary = Binary(
                filename=binary_path.name,
                filepath=str(binary_path),
                filesize=binary_path.stat().st_size
            )
            db.add(db_binary)
            db.commit()
            db.refresh(db_binary)


        log.info("--- Static Analysis Stage ---")
        scanner = StaticScanner(rules_path=DEFAULT_RULES_PATH)
        static_results = scanner.scan(binary_path)

        scan_result_entry = AnalysisResult(
            binary_id=db_binary.id,
            analysis_type="static_scan",
            result_data={"signatures": static_results}
        )
        db.add(scan_result_entry)

        db.commit()
        log.success("Pipeline finished. Saare results database me save ho gaye hain.")
        
    except Exception as e:
        log.error(f"Pipeline ke dauran ek error aaya: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    app()
