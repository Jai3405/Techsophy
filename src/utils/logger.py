"""Structured logging utilities."""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler


def get_logger(
    name: str, level: int = logging.INFO, verbose: bool = False
) -> logging.Logger:
    """
    Create and configure a logger with structured output.

    Args:
        name: Logger name
        level: Logging level
        verbose: Enable verbose logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else level)

    # Rich handler for beautiful console output
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.DEBUG if verbose else level)

    formatter = logging.Formatter(
        "%(message)s",
        datefmt="[%X]",
    )
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.propagate = False

    return logger
