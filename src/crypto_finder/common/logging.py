# Hinglish: Loguru ka use karke ek behtar aur modern logging setup.
# Isse logging karna aasaan aur powerful ho jaata hai.

import sys
from loguru import logger

def setup_logging():
    """Application ke liye logging ko configure karta hai."""
    # Pehle se मौजूद saare handlers ko remove karo.
    logger.remove()

    # Console (terminal) me log karne ke liye ek naya handler add karo.
    # Iska format behtar readability ke liye set kiya gaya hai.
    logger.add(
        sys.stderr,
        level="DEBUG",
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True,
    )
    
    # File me log karne ke liye ek handler (optional, agar zaroorat pade).
    # logger.add(
    #     "logs/app.log",
    #     level="DEBUG",
    #     rotation="10 MB", # Har 10 MB ke baad nayi file.
    #     retention="10 days", # 10 din purane logs delete.
    #     format="{time} {level} {message}",
    # )

    logger.info("Logger successfully configured.")
    return logger

# Ek global logger object jo pure application me use hoga.
log = setup_logging()
