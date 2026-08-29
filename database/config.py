from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# SQLite database file
DATABASE_PATH = BASE_DIR / "scan_history.db"

# SQLAlchemy database URL
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"