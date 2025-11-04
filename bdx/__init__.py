import dataclasses
import os.path
import sys
import tomllib
import traceback as tb
from dataclasses import dataclass, field
from multiprocessing import Lock
from pathlib import Path
from pprint import pformat
from typing import Any, Optional, Type, TypeVar

import click
import tqdm

VERBOSITY = 0

MAIN_PID = os.getpid()

_lock = Lock()


@dataclass
class Pretty:
    """Tag class used to pretty-print any object."""

    obj: Any


def log(msg, *args):
    """Print ``msg`` to stderr."""
    try:
        pid = os.getpid()

        def prettify_arg(arg):
            match arg:
                case Pretty(arg):
                    return pformat(arg)
                case Path():
                    if arg.is_absolute():
                        return os.path.relpath(arg)
                case Exception():
                    return "\n".join(
                        tb.format_exception(type(arg), arg, arg.__traceback__)
                    )
                case _:
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
class IndexingConfig:
    """Config that maps to IndexingOptions."""

    demangle_names: bool = True
    index_relocations: bool = False
    min_symbol_size: int = 1
    use_dwarfdump: bool = True

    def set_from_dict(self, data: dict):
        """Set the values in this config using data from given dict."""
        for k, v in data.items():
            match k:
                case "demangle-names":
                    self.demangle_names = _ensure_type(
                        "demangle-names", v, bool
                    )
                case "index-relocations":
                    self.index_relocations = _ensure_type(
                        "index-relocations", v, bool
                    )
                case "min-symbol-size":
                    self.min_symbol_size = _ensure_type(
                        "min-symbol-size", v, int
                    )
                case "use-dwarfdump":
                    self.use_dwarfdump = _ensure_type("use-dwarfdump", v, bool)
                case _:
                    log("Warning: unknown 'indexing' config key {!r}", k)

    def to_dict(self) -> dict:
        """Serialize this config to a dict."""
        optnames = {
            "demangle_names": "demangle-names",
            "index_relocations": "index-relocations",
            "min_symbol_size": "min-symbol-size",
            "use_dwarfdump": "use-dwarfdump",
        }
        fields = dataclasses.fields(self)
        return {optnames[f.name]: getattr(self, f.name) for f in fields}


@dataclass
class ArchConfig:
    """Per-arch configuration."""

    addr2line_program: str = "addr2line"
    dwarfdump_program: str = "dwarfdump"

    disassembler: str = "objdump"
    disassembler_args: str = " ".join(
        [
            "-dC",
            "--no-show-raw-insn",
            "'{path}'",
            "--section",
            "'{section}'",
            "--start-address",
            "0x{address:x}",
            "--stop-address",
            "0x{endaddress:x}",
        ]
    )

    def set_from_dict(self, data: dict):
        """Set the values in this config using data from given dict."""
        for k, v in data.items():
            match k:
                case "addr2line":
                    self.addr2line_program = _ensure_type("addr2line", v, str)
                case "dwarfdump":
                    self.dwarfdump_program = _ensure_type("dwarfdump", v, str)
                case "disassembler":
                    self.disassembler = _ensure_type("disassembler", v, str)
                case "disassembler-args":
                    self.disassembler_args = _ensure_type(
                        "disassembler-args", v, str
                    )
                case _:
                    log("Warning: Unknown 'arch' config key {!r}", k)

    def to_dict(self, skip_defaults=True) -> dict:
        """Serialize this config to a dict.

        If ``skip_defaults``, then don't emit default values.
        """
        optnames = {
            "addr2line_program": "addr2line",
            "dwarfdump_program": "dwarfdump",
            "disassembler": "disassembler",
            "disassembler_args": "disassembler-args",
        }
        fields = dataclasses.fields(self)
        return {
            optnames[f.name]: getattr(self, f.name)
            for f in fields
            if not skip_defaults or getattr(self, f.name) != f.default
        }

    def disassembly_command(self, symbol_dict: dict) -> str:
        """Get the command to disassemble Symbol (as dict) object."""
        args = self.disassembler_args.format(**symbol_dict)

        return f"{self.disassembler} {args}"


@dataclass
class Config:
    """Holds the global configuration."""

    indexing: IndexingConfig = field(default_factory=IndexingConfig)
    arch: dict[str, ArchConfig] = field(default_factory=dict)
    per_path_configs: dict[Path, dict] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize this object after creation."""
        self.arch["default"] = ArchConfig()

    def apply_path_config(self, path: Path):
        """Apply path-specific configration for ``path``."""
        config = self.per_path_configs.get(path)
        if config is not None:
            debug("Applying config for directory: {}", str(path))
            trace("Per-directory config: {}", Pretty(config))
            self.set_from_dict(config)
        else:
            debug("No directory-specific config for path: {}", str(path))

    def arch_config(self, arch: str) -> ArchConfig:
        """Get the per-arch config for ``arch``, or the default one."""
        return self.arch.get(arch, self.arch["default"])

    def set_from_dict(self, data: dict):
        """Set the values in this config from data in ``dict``."""
        from bdx.binary import Arch  # noqa: PLC0415

        for k, v in data.items():
            match k:
                case "indexing":
                    _ensure_type("indexing", v, dict)
                    self.indexing.set_from_dict(v)

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
                        cfg = self.arch.setdefault(arch, ArchConfig())
                        cfg.set_from_dict({**default_arch_config, **archv})
                case "path":
                    _ensure_type("path", v, dict)

                    for path, pathconfig in v.items():
                        _ensure_type(f"path.{path}", pathconfig, dict)

                        self.per_path_configs[
                            Path(path).absolute().resolve()
                        ] = pathconfig
                case _:
                    log("Warning: Unknown top-level config key {!r}", k)

    def to_dict(self) -> dict:
        """Serialize this config to dict."""
        return {
            "indexing": self.indexing.to_dict(),
            "arch": {
                k: v.to_dict(skip_defaults=(k != "default"))
                for k, v in self.arch.items()
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
            trace("Parsed config: {}", Pretty(data))

            cfg.set_from_dict(data)

    debug("Config: {}", Pretty(cfg))
    global _CONFIG_INSTANCE

    _CONFIG_INSTANCE = cfg


def get_config() -> Config:
    """Get the global config instance."""
    if _CONFIG_INSTANCE is None:
        msg = "Config not initialized"
        raise RuntimeError(msg)

    return _CONFIG_INSTANCE
