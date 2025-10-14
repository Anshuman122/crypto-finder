from pathlib import Path
import yara
from typing import List, Dict, Any

from crypto_finder.common.logging import log

class StaticScanner:

    def __init__(self, rules_path: Path):

        if not rules_path.exists():
            log.error(f"YARA rules file not found at: {rules_path}")
            raise FileNotFoundError(f"YARA rules file not found at: {rules_path}")
        
        try:
            log.info(f"YARA rules file '{rules_path.name}' is being compiled...")
            self.rules = yara.compile(filepath=str(rules_path))
            log.success("YARA rules successfully compiled.")
        except yara.Error as e:
            log.error(f"YARA rules compilation error: {e}")
            raise

    def scan(self, binary_path: Path) -> List[Dict[str, Any]]:

        if not binary_path.exists():
            log.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        log.info(f"'{binary_path.name}' is being scanned for finding cryptographic signatures...")
        matches = self.rules.match(filepath=str(binary_path))
        
        results = []
        for match in matches:
            result = {
                "rule": match.rule,
                "crypto_name": match.meta.get("crypto_name", "Unknown"),
                "description": match.meta.get("description", "No description"),
                "matches": [
                    {
                        "offset": offset,
                        "identifier": identifier,
                        "data": data.hex(),
                    }
                    for offset, identifier, data in match.strings
                ],
            }
            results.append(result)

        if results:
            log.success(f"Scan complete. Found {len(results)} matching rule(s).")
        else:
            log.warning("Scan complete. No matching crypto signatures found.")
            
        return results
