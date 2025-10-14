
import subprocess
import tempfile
import json
from pathlib import Path

from crypto_finder.common.config import settings
from crypto_finder.common.logging import log

class GhidraAdapter:
    

    def __init__(self):
        self.headless_path = settings.ghidra.headless_path
        if not self.headless_path.exists():
            raise FileNotFoundError(
                f"Ghidra headless script not found at: {self.headless_path}. Please check your config."
            )
        
        self.script_path = Path(__file__).parent.parent.parent.parent / "plugins" / "ghidra_plugin" / "GhidraExportScript.py"
        if not self.script_path.exists():
            raise FileNotFoundError(f"GhidraExportScript.py not found at {self.script_path}")

    def lift(self, binary_path: Path) -> dict:

        if not binary_path.exists():
            log.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            project_name = "tempGhidraProject"
            output_json_path = temp_dir / "output.json"

            log.info(f"Starting Ghidra analysis for {binary_path.name}...")
            
            command = [
                str(self.headless_path),
                str(temp_dir),
                project_name,
                "-import",
                str(binary_path),
                "-postscript",
                str(self.script_path),
                str(output_json_path),
                "-deleteProject", 
                
            ]

            try:
        
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=300
                )
                log.debug("Ghidra process output:\n" + process.stdout)

                if output_json_path.exists():
                    log.info("Ghidra analysis successful. Parsing output.")
                    with open(output_json_path, 'r') as f:
                        return json.load(f)
                else:
                    log.error("Ghidra analysis finished, but no output file was created.")
                    raise RuntimeError("Ghidra did not produce an output file.")

            except FileNotFoundError:
                log.error(f"Ghidra command not found: {self.headless_path}")
                raise
            except subprocess.CalledProcessError as e:
                log.error(f"Ghidra analysis failed with exit code {e.returncode}.")
                log.error("Ghidra Stderr:\n" + e.stderr)
                raise RuntimeError(f"Ghidra analysis failed: {e.stderr}")
            except subprocess.TimeoutExpired:
                log.error("Ghidra analysis timed out.")
                raise TimeoutError("Ghidra analysis took too long.")
