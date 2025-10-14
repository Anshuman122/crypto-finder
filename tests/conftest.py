
import pytest
from pathlib import Path
import subprocess

@pytest.fixture(scope="session")
def test_binary(tmp_path_factory) -> Path:

    session_tmp_dir = tmp_path_factory.mktemp("binaries")
    source_file = session_tmp_dir / "test.c"
    output_file = session_tmp_dir / "test_executable"

    c_code = """
    #include <stdio.h>

    int add(int a, int b) {
        return a + b;
    }

    int main() {
        printf("Hello, world! Result: %d\\n", add(5, 10));
        return 0;
    }
    """
    source_file.write_text(c_code)

    try:
        subprocess.run(
            ["gcc", str(source_file), "-o", str(output_file)],
            check=True,
            capture_output=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        pytest.fail(f"Could not compile test binary with gcc. Is gcc installed and in PATH? Error: {e}")
    
    return output_file
