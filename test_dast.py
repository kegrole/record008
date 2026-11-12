"""Repository-root shim so `python -m unittest test_dast -v` works from root."""

from tests.test_dast import *  # noqa: F401,F403

if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
