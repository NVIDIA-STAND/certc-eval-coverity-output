"""Backward-compatible entry point for the CERT-C evaluator UI."""
from __future__ import annotations

from ui import main

__all__ = ["main"]

if __name__ == "__main__":
    main()
