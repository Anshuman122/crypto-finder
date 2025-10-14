
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import DirectoryPath
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.parent.parent

class GhidraSettings(BaseSettings):
    install_path: DirectoryPath = Path("C:/tools/ghidra_11.1.2_PUBLIC")

    @property
    def headless_path(self) -> Path:
        if os.name == 'nt': 
            return self.install_path / "support" / "analyzeHeadless.bat"
        return self.install_path / "support" / "analyzeHeadless"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", env_file_encoding='utf-8', extra='ignore')

    data_dir: DirectoryPath = ROOT_DIR / "data"
    raw_data_dir: DirectoryPath = data_dir / "01_raw"
    processed_data_dir: DirectoryPath = data_dir / "03_processed"
    models_dir: DirectoryPath = data_dir / "05_models"

    database_url: str = f"sqlite:///{data_dir / 'crypto_finder.db'}"

    ghidra: GhidraSettings = GhidraSettings()

    def __init__(self, **values):
        super().__init__(**values)
        self.data_dir.mkdir(exist_ok=True)
        self.raw_data_dir.mkdir(exist_ok=True)
        self.processed_data_dir.mkdir(exist_ok=True)
        self.models_dir.mkdir(exist_ok=True)

settings = Settings()
