
import subprocess
from pathlib import Path
import typer

from crypto_finder.common.logging import log

ROOT_DIR = Path(__file__).parent.parent

OUTPUT_DIR = ROOT_DIR / "data" / "controlled_dataset"

TINY_AES_C_CODE = """

int main() {
    // Placeholder for AES operations
    return 0;
}
"""
CRYPTO_SOURCES_DIR = ROOT_DIR / "scripts" / "crypto_sources"

TARGETS = {
    "x86_64": "gcc",
    "armv7": "arm-linux-gnueabihf-gcc",
   
}

def build():
    """Compiles crypto source code for multiple architectures to create a dataset."""
    log.info("Controlled dataset build process shuru ho raha hai...")
    
  
    CRYPTO_SOURCES_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)
    
 
    dummy_file = CRYPTO_SOURCES_DIR / "tiny_aes.c"
    if not dummy_file.exists():
        log.warning("Dummy crypto source file 'tiny_aes.c' banayi ja rahi hai.")
        dummy_file.write_text(TINY_AES_C_CODE)
    
    source_files = list(CRYPTO_SOURCES_DIR.glob("*.c"))
    if not source_files:
        log.error("Crypto source directory me koi .c file nahi mili.")
        raise typer.Exit(code=1)
        
    for name, compiler in TARGETS.items():
        target_dir = OUTPUT_DIR / name
        target_dir.mkdir(exist_ok=True)
        log.info(f"--- Compiling for target: {name} using '{compiler}' ---")
        
        for source_file in source_files:
            output_file = target_dir / source_file.stem
            
            command = [compiler, str(source_file), "-o", str(output_file)]
            
            try:
         
                subprocess.run(command, check=True, capture_output=True, text=True)
                log.success(f"Successfully compiled '{source_file.name}' to '{output_file}'")
            except FileNotFoundError:
                log.error(f"Compiler '{compiler}' nahi mila. Please install it and ensure it's in your PATH.")
                continue
            except subprocess.CalledProcessError as e:
                log.error(f"'{source_file.name}' ko compile karne me error aaya.")
                log.error(f"Error output:\n{e.stderr}")
                continue

if __name__ == "__main__":
    build()
