# errors.py
"""Domain exceptions so library code never calls sys.exit()."""


class WgError(Exception):
    """Fatal, already-localized error that maps to a process exit code."""

    def __init__(self, message="", exit_code=1):
        super().__init__(message)
        self.exit_code = int(exit_code)
