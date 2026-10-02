"""Shared pytest configuration.

Runs from the ``backend`` directory (``python -m pytest``); make sure the
application package is importable and that importing ``app.database`` does not
require a real database connection.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tests exercise pure parsing/graph logic and never connect to the database.
os.environ.setdefault("DATABASE_URL", "sqlite://")
