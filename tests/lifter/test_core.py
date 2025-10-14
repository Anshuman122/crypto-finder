
import pytest
from pathlib import Path
import json
from crypto_finder.lifter.core import Lifter

@pytest.mark.skip(reason="Requires a live Ghidra instance and proper config. For local validation only.")
def test_process_binary_real(test_binary: Path, tmp_path: Path):

    lifter = Lifter()
    output_dir = tmp_path

    result_path = lifter.process_binary(test_binary, output_dir)

    assert result_path is not None, "Lifter returned no output file path."
    assert result_path.exists(), "Output JSON file not created."
    assert result_path.name == f"{test_binary.name}.ghidra.json", "Name of output file is wrong."

    with open(result_path, 'r') as f:
        data = json.load(f)
    
    assert data["binary_name"] == test_binary.name, "Name of Binary must be in JSON "
    assert len(data["functions"]) >= 2, "Atleast'main' aur 'add' function must have been returned."
    
    function_names = {f["name"] for f in data["functions"]}
    assert "main" in function_names, "'main' function not found."
    assert "add" in function_names, "'add' function not found."
