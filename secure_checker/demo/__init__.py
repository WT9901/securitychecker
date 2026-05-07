"""
demo/__init__.py

Demo module for secure form integration.
Registers the demo blueprint for /demo/* routes.
"""

from .routes import demo_bp

__all__ = ["demo_bp"]
