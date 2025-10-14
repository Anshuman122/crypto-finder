from pathlib import Path
import angr
from typing import List, Dict, Any

from crypto_finder.common.logging import log

class SymbolicAnalyzer:


    def __init__(self, binary_path: Path):
        if not binary_path.exists():
            log.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        log.info(f"'{binary_path.name}' is being loaded on angr project...")

        self.project = angr.Project(str(binary_path), auto_load_libs=False)
        log.success("Angr project successfully loaded.")

    def find_loops(self, function_address: int = None) -> List[Dict[str, Any]]:

        log.info("Loop finding analysis is starting...")

        try:

            cfg = self.project.analyses.CFG(fail_fast=True)

            loop_finder = self.project.analyses.LoopFinder(kb=cfg.kb)
            
            results = []
            for loop in loop_finder.loops:
           
                if function_address and loop.entry.addr not in self.project.kb.functions[function_address].block_addrs:
                    continue
                
                loop_info = {
                    "entry_address": hex(loop.entry.addr),
                    "node_count": len(loop.body_nodes),
                }
                results.append(loop_info)
            
            log.success(f"Loop analysis complete. Found {len(results)} loop(s).")
            return results
        except Exception as e:
            log.error(f"Angr analysis ke dauran ek error aaya: {e}")
            return []
