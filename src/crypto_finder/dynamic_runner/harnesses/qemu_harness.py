
import subprocess
from pathlib import Path
from crypto_finder.common.logging import log

def run_with_qemu(binary_path: Path):

    qemu_executable = "qemu-arm-static"
    
    if not binary_path.exists():
        log.error(f"Binary not found: {binary_path}")
        return

    command = [qemu_executable, str(binary_path)]
    
    log.info(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        log.info("QEMU execution successful.")
        log.info(f"STDOUT:\n{result.stdout}")
        log.error(f"STDERR:\n{result.stderr}")
    except FileNotFoundError:
        log.error(f"'{qemu_executable}' not found. Please install QEMU user-mode emulation.")
    except Exception as e:
        log.error(f"QEMU execution error: {e}")
