# Hinglish: Lifter ke core logic ke liye ek test file.

import pytest
from pathlib import Path
from crypto_finder.lifter.core import Lifter

# Mocking Ghidra for tests to avoid running the actual heavy process.
# Hum actual tests me Ghidra ko run nahi karna chahte kyunki woh slow hai.
@pytest.mark.skip(reason="Requires a live Ghidra instance and proper config. Mocking is needed for CI.")
def test_process_binary_real(test_binary: Path, tmp_path: Path):
    """
    Ek real test jo GhidraAdapter ko call karta hai.
    Isko normally skip kiya jaayega aur sirf local testing me run kiya jaayega.
    """
    # Arrange
    lifter = Lifter()
    output_dir = tmp_path

    # Act
    result_path = lifter.process_binary(test_binary, output_dir)

    # Assert
    assert result_path is not None
    assert result_path.exists()
    assert result_path.name == f"{test_binary.name}.ghidra.json"
    
    # JSON content ko bhi check kar sakte hain.
    import json
    with open(result_path, 'r') as f:
        data = json.load(f)
    assert data["binary_name"] == test_binary.name
    assert len(data["functions"]) > 0 # Kam se kam 'main' aur 'add' function hone chahiye.