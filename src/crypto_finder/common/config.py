# Hinglish: Pydantic ka use karke ek robust configuration setup.
# Yeh settings ko validate karta hai aur ensure karta hai ki sab aasaani se accessible ho.

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import DirectoryPath
from pathlib import Path

# Project ka root directory find karo. Yeh ek global variable hai.
ROOT_DIR = Path(__file__).parent.parent.parent.parent

class GhidraSettings(BaseSettings):
    """Ghidra se related saari settings."""
    # Yahan ek default path diya gaya hai. Isse apne actual Ghidra path se replace karein.
    install_path: DirectoryPath = Path("C:/tools/ghidra_11.1.2_PUBLIC")

    @property
    def headless_path(self) -> Path:
        # Operating system ke hisab se headless script ka path return karo.
        if os.name == 'nt': # Windows
            return self.install_path / "support" / "analyzeHeadless.bat"
        return self.install_path / "support" / "analyzeHeadless"

class Settings(BaseSettings):
    """Project ki saari main settings."""
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding='utf-8', extra='ignore')

    # Project Directories
    data_dir: DirectoryPath = ROOT_DIR / "data"
    raw_data_dir: DirectoryPath = data_dir / "01_raw"
    processed_data_dir: DirectoryPath = data_dir / "03_processed"
    models_dir: DirectoryPath = data_dir / "05_models"

    # Database
    database_url: str = f"sqlite:///{data_dir / 'crypto_finder.db'}"

    # Ghidra Settings
    ghidra: GhidraSettings = GhidraSettings()

    def __init__(self, **values):
        super().__init__(**values)
        # Yeh directories ensure karti hain ki exist karti hain.
        self.data_dir.mkdir(exist_ok=True)
        self.raw_data_dir.mkdir(exist_ok=True)
        self.processed_data_dir.mkdir(exist_ok=True)
        self.models_dir.mkdir(exist_ok=True)

# Ek global settings object jo pure application me use hoga.
settings = Settings()