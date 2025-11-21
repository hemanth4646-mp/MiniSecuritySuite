import logging
import sys
from pathlib import Path

def setup_logging(name: str, level=logging.INFO):
    """Configure logging with color and format."""
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmt)
        log.addHandler(handler)
    log.setLevel(level)
    return log

def ensure_dir(path: Path):
    """Ensure directory exists, creating if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)