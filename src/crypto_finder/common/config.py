
# Hinglish: Pydantic ka use karke ek robust configuration setup.
# Yeh settings ko validate karta hai aur ensure karta hai ki sab aasaani se accessible ho.

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import DirectoryPath, FilePath, AnyUrl
from pathlib import Path

# Project ka root directory find karo.
# __file__ -> config.py -> common -> crypto_finder -> src -> ROOT
ROOT_DIR = Path(__file__).parent.parent.parent.parent

class GhidraSettings(BaseSettings):
    """Ghidra se related saari settings."""
    # Apne system ka Ghidra installation path yahan daalo.
    # Environment variable se bhi set kar sakte ho: CRYPTO_FINDER_GHIDRA_INSTALL_PATH
    install_path: DirectoryPath = Path("C:/Program Files/ghidra_11.1.2_PUBLIC") 
    
    @property
    def headless_path(self) -> Path:
        # Operating system ke hisab se headless script ka path return karo.
        if os.name == 'nt': # Windows
            return self.install_path / "support" / "analyzeHeadless.bat"
        return self.install_path / "support" / "analyzeHeadless"

class Settings(BaseSettings):
    """Project ki saari main settings."""
    # .env file se load karne ke liye configuration
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