# errors.py
"""Domain exceptions so library code never calls sys.exit()."""


class WgError(Exception):
    """Fatal, already-localized error that maps to a process exit code.

    Convention: an empty message means the message was already emitted
    (e.g. a formatted presentation note, or diagnostics printed by the
    apply path); frontends (cli/tui) must not print it again.
    """

    def __init__(self, message="", exit_code=1):
        super().__init__(message)
        self.exit_code = int(exit_code)
