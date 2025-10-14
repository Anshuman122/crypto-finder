from pathlib import Path
from crypto_finder.lifter.adapters.ghidra import GhidraAdapter
from crypto_finder.common.logging import log

class Lifter:


    def __init__(self):
        self.ghidra_adapter = GhidraAdapter()

    def process_binary(self, binary_path: Path, output_dir: Path):

        log.info(f"Processing binary: {binary_path.name}")
        
        try:
            
            lifted_data = self.ghidra_adapter.lift(binary_path)

            
            output_path = output_dir / f"{binary_path.name}.ghidra.json"
            
            
            with open(output_path, 'w') as f:
                import json
                json.dump(lifted_data, f, indent=4)

            log.success(f"Successfully lifted binary. Output saved to {output_path}")
            return output_path

        except Exception as e:
            log.error(f"Failed to process {binary_path.name}: {e}")
            return None
