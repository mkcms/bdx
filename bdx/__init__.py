import os.path
import sys
import traceback as tb
from multiprocessing import Lock
from pathlib import Path

import click
import tqdm

VERBOSITY = 0

MAIN_PID = os.getpid()

_lock = Lock()


def log(msg, *args):
    """Print ``msg`` to stderr."""
    try:
        pid = os.getpid()

        def prettify_arg(arg):
            if isinstance(arg, Path) and arg.is_absolute():
                return os.path.relpath(arg)

            if isinstance(arg, Exception):
                return "\n".join(
                    tb.format_exception(type(arg), arg, arg.__traceback__)
                )

            return arg

        def format_log_line(line):
            if pid != MAIN_PID:
                line = "[{}] {}".format(pid, line)

            return line

        pretty_args = [prettify_arg(p) for p in args]
        msg = msg.format(*pretty_args)
        msg = "\n".join(format_log_line(line) for line in msg.splitlines())

        with _lock:
            click.echo(msg, file=sys.stderr)

    except Exception as e:
        print(f"Logging error: {e}", file=sys.stderr)
        print(msg, file=sys.stderr)


def info(msg, *args):
    """Log ``msg`` if verbosity level is set high enough."""
    if VERBOSITY >= 1:
        log(msg, *args)


def debug(msg, *args):
    """Log ``msg`` if verbosity level is set high enough."""
    if VERBOSITY >= 2:
        log(msg, *args)


def trace(msg, *args):
    """Log ``msg`` if verbosity level is set high enough."""
    if VERBOSITY >= 3:
        log(msg, *args)


def detail_log(msg, *args):
    """Log ``msg`` if verbosity level is set high enough."""
    if VERBOSITY >= 4:
        log(msg, *args)


def error(msg, *args):
    """Log ``msg`` and then quit the program."""
    log("error: " + msg, *args)
    sys.exit(1)


def make_progress_bar(*args, **kwargs):
    """Return ``tqdm`` progress bar if available."""
    disable = os.getenv("BDX_DISABLE_PROGRESS_BAR") is not None
    try:
        disable |= not os.isatty(sys.stdout.fileno())
    except IOError:
        # In case fileno() is unsupported
        pass
    return tqdm.tqdm(*args, disable=disable, **kwargs)
