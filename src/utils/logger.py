"""
Logging Utility

Standardized logging across sc-guard modules.

Why Centralized Logging?
- Consistent log format across all modules
- Easy to toggle debug mode
- Separates user-facing output from debug logs
- File logging for troubleshooting
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(name: str, log_file: str = None, level: int = logging.INFO):
    """
    Create configured logger instance.
    
    Args:
        name: Logger name (usually __name__ from calling module)
        log_file: Optional path to log file
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_format = logging.Formatter(
        '[%(levelname)s] %(name)s: %(message)s'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
        file_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger
