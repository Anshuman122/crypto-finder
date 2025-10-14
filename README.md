# 🤖 AI/ML-Based Identification of Cryptographic Primitives and Protocols in Multi-Architecture Firmware Binaries
### Team Loud ( Team ID 64517 )

---

## 📌 Introduction & Problem Context
The rapid proliferation of IoT and embedded systems has led to a security crisis. Billions of devices—from routers and cameras to industrial controllers—run on "black-box" firmware with undocumented or obfuscated code. Identifying the cryptographic functions within these binaries is a monumental challenge for security auditors, yet it is critical for ensuring confidentiality, integrity, and discovering vulnerabilities.

This project provides a unified, intelligent framework to automate this process. By integrating classic binary analysis techniques with modern **Machine Learning**, we transform the manual, architecture-specific task of reverse engineering into a scalable, automated pipeline. Our system dissects firmware binaries from heterogeneous architectures (x86, ARM, MIPS), identifies cryptographic primitives, and provides actionable intelligence.

---

## 🚀 Current Achievements & System Status

### Multi-Architecture Lifting Pipeline ⚙️  
- Integrated **Ghidra Headless** to lift binary code from multiple architectures into standardized P-Code.  

### Hybrid Analysis Engine 🔬  
- **Static Scanner:** `YARA`-based detection of cryptographic constants.  
- **Symbolic Analyzer:** `angr`-based CFG + loop detection.  
- **Dynamic Analyzer:** `Unicorn Engine` micro-emulation of code snippets.  

### Extensible Machine Learning Core 🧠  
- **PyTorch**-based MLP classifier for crypto vs non-crypto function detection.  

### Scalable Data & API Backend ☁️  
- Persistent storage with **SQLAlchemy**.  
- **FastAPI** server exposing ML predictions via REST.  

### Modular & Runnable Toolchain 🛠️  
- CLI built with **Typer**.  
- Independent modules (`lift`, `scan`, etc.) runnable as standalone tools.  

---

## 🏗 Technical Architecture: A Deep Dive

### I. Data Ingestion & Preprocessing
| Component | Technology | Role |
|-----------|------------|------|
| Firmware Corpus | Python + `requests` | Build local dataset of real-world firmware. |
| Controlled Dataset | Cross-compilation | Generate labeled crypto/non-crypto datasets across architectures. |
| Data Persistence | SQLAlchemy + SQLite/Postgres | Store metadata + analysis results. |

### II. Core Analysis Pipeline
| Component | Technology | Role |
|-----------|------------|------|
| Lifter | Ghidra Headless | Convert machine code → P-Code JSON. |
| Static Scanner | YARA | Detect crypto constants. |
| Symbolic Analyzer | angr | Explore CFGs, detect loops. |
| Dynamic Analyzer | Unicorn | Lightweight emulation for traces. |

### III. Machine Learning Core
| Step | Details |
|------|---------|
| Feature Extraction | `ml/features.py` extracts opcode counts, function size. |
| Data Handling | `ml/datasets.py` serves feature vectors + labels. |
| Classification Model | `CryptoClassifierMLP` (PyTorch MLP). |
| Training/Evaluation | `ml/train.py` + `ml/evaluate.py` with sklearn metrics. |

### IV. Service Layer & Deployment
| Component | Technology | Role |
|-----------|------------|------|
| API Layer | FastAPI | `/predict` endpoint for ML inference. |
| Data Validation | Pydantic | Schema validation + docs. |
| Deployment | Docker + Uvicorn | Containerized + reproducible builds. |
| User Interface | Typer CLI | CLI commands for all modules. |

---

## 🖼️ System Visuals
*(High-level architecture diagram placeholder)*  

---

## 🔒 Robustness & Reliability
| Module | Purpose | Mechanism |
|--------|---------|-----------|
| Config | Centralized settings | `common/config.py` + Pydantic validation. |
| Error Handling | Prevent crashes | Structured logging with Loguru. |
| Reproducibility | Stable builds | Docker + pyproject.toml. |
| Testing | Code correctness | Pytest fixtures and automated tests. |

---

# 🔐 Crypto Finder

Crypto Finder is a research & engineering toolkit for **detecting cryptographic primitives** inside binaries and firmware images.  
It combines **static analysis (Ghidra, Capstone, YARA), dynamic analysis (QEMU harnesses), symbolic execution (angr)**, and **ML-based detection** to classify and analyze crypto functions.

---

## 📸 Showcase & Demo

### CLI in Action
```powershell
# Scan binary for constants
crypto-finder scan --binary-path C:\Windows\System32\bcrypt.dll

# Symbolic loop detection
crypto-finder symbolic-loops --binary-path ./sample.exe

# Dynamic emulation of shellcode
crypto-finder dynamic-run --shellcode "554889e5c3"

```
###API Prediction Example
```
{
  "function_name": "AES_encrypt_block",
  "prediction": {
    "label": "crypto",
    "confidence": 0.9875
  }
}
```

##🛣 Future Roadmap

GNNs & Transformers for CFG/P-Code sequences.

Protocol-level detection (TLS handshakes, key exchanges).

Full-system emulation with FirmAE
.

Web Dashboard for visualization of analysis results.

## 📂 Repository Structure

```text
crypto_finder/

├── data/                     # (In .gitignore) Local data for the project
│   ├── 01_raw/               # Original firmware images
│   ├── 03_processed/         # Lifted code, traces, etc.
│   └── 05_models/            # Trained model artifacts
│
├── docker/                   # For a reproducible environment
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   └── docker-compose.yml
│
├── notebooks/                # For research, exploration, and prototyping
│   └── 01-model-prototyping.ipynb
│
├── plugins/                  # Plugins for external tools like Ghidra and IDA Pro
│   ├── ghidra_plugin/
│   └── ida_plugin/
│
├── scripts/                  # Helper scripts for automation
│   ├── download_firmware.py
│   ├── build_controlled_dataset.py
│   └── run_pipeline.py
│
├── src/                      # MAIN SOURCE CODE DIRECTORY
│   └── crypto_finder/        # The core Python package
│       ├── main.py           # Main entry point
│       │
│       ├── lifter/           # Binary lifting
│       │   ├── cli.py
│       │   ├── core.py
│       │   └── adapters/
│       │       ├── ghidra.py
│       │       └── capstone.py
│       │
│       ├── static_scanner/   # Static scanning
│       │   ├── cli.py
│       │   ├── core.py
│       │   └── signatures/
│       │       ├── crypto_constants.json
│       │       └── findcrypt.yar
│       │
│       ├── dynamic_runner/   # Dynamic emulation
│       │   ├── cli.py
│       │   ├── core.py
│       │   └── harnesses/
│       │       └── qemu_harness.py
│       │
│       ├── symbolic/         # Symbolic analysis
│       │   ├── cli.py
│       │   └── loop_analyzer.py
│       │
│       ├── ml/               # ML models
│       │   ├── datasets.py
│       │   ├── features.py
│       │   ├── models.py
│       │   ├── train.py
│       │   └── evaluate.py
│       │
│       ├── api/              # REST API (FastAPI)
│       │   ├── main.py
│       │   ├── models.py
│       │   └── endpoints.py
│       │
│       ├── reporter/         # Report generation
│       │   ├── core.py
│       │   └── templates/
│       │       └── report_template.html
│       │
│       └── common/           # Shared utilities
│           ├── config.py
│           ├── db.py
│           └── logging.py
│
├── tests/                    # Tests for reliability
│   ├── lifter/
│   │   └── test_core.py
│   └── ml/
│       └── test_models.py
│
├── .gitignore
├── README.md                 # Project documentation
└── pyproject.toml            # Dependencies & config
```

#🤝 Contact

Project – Crypto Finder
Team - Loud 
