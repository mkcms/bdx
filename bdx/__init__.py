import dataclasses
import os.path
import sys
import tomllib
import traceback as tb
from dataclasses import dataclass, field
from multiprocessing import Lock
from pathlib import Path
from typing import Any, Optional, Type, TypeVar

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


T = TypeVar("T")


def _ensure_type(what: str, obj: Any, type: Type[T]) -> T:
    if not isinstance(obj, type):
        msg = f"'{what}' is not of expected type '{type.__name__}': {obj!r}"
        raise TypeError(msg)
    return obj


@dataclass
class ArchConfig:
    """Per-arch configuration."""

    addr2line_program: str = "addr2line"
    dwarfdump_program: str = "dwarfdump"

    def set_from_dict(self, data: dict):
        """Set the values in this config using data from given dict."""
        for k, v in data.items():
            match k:
                case "addr2line":
                    self.addr2line_program = _ensure_type("addr2line", v, str)
                case "dwarfdump":
                    self.dwarfdump_program = _ensure_type("dwarfdump", v, str)
                case _:
                    log("Warning: Unknown 'arch' config key {!r}", k)

    def to_dict(self, skip_defaults=True) -> dict:
        """Serialize this config to a dict.

        If ``skip_defaults``, then don't emit default values.
        """
        optnames = {
            "addr2line_program": "addr2line",
            "dwarfdump_program": "dwarfdump",
        }
        fields = dataclasses.fields(self)
        return {
            optnames[f.name]: getattr(self, f.name)
            for f in fields
            if not skip_defaults or getattr(self, f.name) != f.default
        }


@dataclass
class Config:
    """Holds the global configuration."""

    arch: dict[str, ArchConfig] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize this object after creation."""
        self.arch["default"] = ArchConfig()

    def arch_config(self, arch: str) -> ArchConfig:
        """Get the per-arch config for ``arch``, or the default one."""
        return self.arch.get(arch, self.arch["default"])

    def set_from_dict(self, data: dict):
        """Set the values in this config from data in ``dict``."""
        from bdx.binary import Arch  # noqa: PLC0415

        for k, v in data.items():
            match k:
                case "arch":
                    _ensure_type("arch", v, dict)

                    default_arch_config = v.pop("default", {})
                    self.arch["default"].set_from_dict(default_arch_config)

                    for arch, archv in v.items():
                        _ensure_type(f"arch.{arch}", archv, dict)

                        archs = sorted(dict(Arch.__members__))
                        if arch not in archs:
                            msg = f"Invalid architecture {arch!r}\n"
                            msg += "Valid architectures:\n"
                            for x in range(0, len(archs), 5):
                                members = archs[x : x + 5]
                                msg += "  " + ", ".join(members)
                                msg += ",\n"

                            raise ValueError(msg)
                        cfg = ArchConfig()
                        cfg.set_from_dict({**default_arch_config, **archv})
                        self.arch[arch] = cfg
                case _:
                    log("Warning: Unknown top-level config key {!r}", k)

    def to_dict(self) -> dict:
        """Serialize this config to dict."""
        return {
            "arch": {
                **{
                    k: v.to_dict(skip_defaults=(k != "default"))
                    for k, v in self.arch.items()
                },
            },
        }


DEFAULT_CONFIG_PATH = (
    Path(os.getenv("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"))
    / "bdx.toml"
)

_CONFIG_INSTANCE = Config()


def load_config(path: Optional[Path] = None):
    """Load global config from the one stored in ``path``.

    If ``path`` is None, then load the config from default location.
    """
    cfg = Config()

    if not path:
        if not DEFAULT_CONFIG_PATH.exists():
            debug("Config file does not exist, using defaults")

    path = path or DEFAULT_CONFIG_PATH
    debug("Loading config from path: {}", path)
    if path.exists() and os.getenv("_BDX_DISABLE_CONFIG") is None:
        with open(path, "rb") as f:
            data = tomllib.load(f)
            trace("Parsed config: {}", data)

            cfg.set_from_dict(data)

    debug("Config: {}", cfg)
    global _CONFIG_INSTANCE

    _CONFIG_INSTANCE = cfg


def get_config() -> Config:
    """Get the global config instance."""
    if _CONFIG_INSTANCE is None:
        msg = "Config not initialized"
        raise RuntimeError(msg)

    return _CONFIG_INSTANCE
