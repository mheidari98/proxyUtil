import logging
from typing import ClassVar

__all__ = ["CustomFormatter"]

_GREY = "\x1b[38;20m"
_YELLOW = "\x1b[33;20m"
_RED = "\x1b[31;20m"
_BOLD_RED = "\x1b[31;1m"
_GREEN = "\x1b[32;20m"
_RESET = "\x1b[0m"
_BASE = "%(asctime)s - %(levelname)s - %(message)s"


# https://stackoverflow.com/a/56944256
class CustomFormatter(logging.Formatter):
    _FORMATTERS: ClassVar[dict[int, logging.Formatter]] = {
        level: logging.Formatter(f"{color}{_BASE}{_RESET}")
        for level, color in (
            (logging.DEBUG, _GREY),
            (logging.INFO, _GREEN),
            (logging.WARNING, _YELLOW),
            (logging.ERROR, _RED),
            (logging.CRITICAL, _BOLD_RED),
        )
    }

    def format(self, record):
        return self._FORMATTERS[record.levelno].format(record)
