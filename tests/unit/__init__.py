# /c:/Users/ren/Desktop/graduation-project/code/vuln_scanner_backend/tests/unit/__init__.py

# This file is used to mark the `unit` directory as a Python package.
# It can also be used to import shared fixtures or configurations for unit tests.

# Example: Import shared fixtures or configurations
from ..conftest import test_app, client

# Ensure that the unit tests are discoverable by pytest
__all__ = ["test_users", "test_tasks", "test_feedback", "test_vul"]
