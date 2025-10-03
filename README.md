# Crypto Finder

An AI/ML framework to automatically identify and interpret cryptographic primitives in firmware binaries. This project provides a robust pipeline for lifting, scanning, and analyzing binaries from multiple architectures.

## Features
-   **Multi-ISA Lifting**: Converts binary code to a generic intermediate representation using Ghidra.
-   **Static Scanning**: Uses YARA to find known cryptographic constants and signatures.
-   **Symbolic Analysis**: Employs `angr` to analyze loops and complex code paths.
-   **Dynamic Analysis**: Uses `unicorn` for fine-grained CPU emulation and tracing.
-   **ML-Powered Classification**: A PyTorch-based model to classify functions.

## 🚀 Getting Started

### Prerequisites
-   Python 3.9+
-   Ghidra installed on your system.
-   Cross-compilation toolchains for ARM, MIPS, etc. (for dataset creation).

### Installation
1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd crypto_finder
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    # Windows
    .\.venv\Scripts\Activate
    # Linux/macOS
    source .venv/bin/activate
    ```

3.  **Install the project in editable mode with development dependencies:**
    ```bash
    pip install -e ".[dev]"
    ```
    This command installs all libraries from `pyproject.toml`.

### Usage
The project is run via a single command-line interface.

```bash
# Show all available commands
crypto-finder --help

# Lift a binary using the lifter module
crypto-finder lift --binary-path /path/to/your/binary.bin --output-dir /path/to/output