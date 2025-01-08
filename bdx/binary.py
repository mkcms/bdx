from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from functools import cache, cached_property, total_ordering
from pathlib import Path
from typing import ClassVar, Iterator, Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import Relocation, RelocationSection
from elftools.elf.sections import Symbol as ELFSymbol
from elftools.elf.sections import SymbolTableSection
from sortedcontainers import SortedList

from bdx import info, trace


class NameDemangler:
    """A class for demangling names with C++ standard library."""

    _INSTANCE: ClassVar[Optional["NameDemangler"]] = None

    def __init__(self):
        """Create a new name demangler."""
        self._libcxx: Optional[ctypes.CDLL] = None
        self._libc: Optional[ctypes.CDLL] = None
        self._demangle_func = None
        self._free_func = None

        # As a fallback, we use c++filt program
        self._cxxfilt = shutil.which("c++filt")

        lib_path = ctypes.util.find_library("c")
        trace("Libc path: {}", lib_path)

        if lib_path:
            lib = ctypes.CDLL(lib_path)
            func = lib.free if lib else None

            if lib and func:
                func.argtypes = [ctypes.c_void_p]
                func.restype = None
                self._free_func = func
                self._libc = lib

        if not self._libc:
            return

        lib_path = ctypes.util.find_library("stdc++")
        trace("Libstdc++ path: {}", lib_path)

        if lib_path:
            lib = ctypes.CDLL(lib_path)
            func = getattr(lib, "__cxa_demangle") if lib else None

            if lib and func:
                func.argtypes = [
                    ctypes.c_char_p,
                    ctypes.c_char_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ]
                func.restype = ctypes.c_void_p

                self._libcxx = lib
                self._demangle_func = func

    @classmethod
    def instance(cls) -> "NameDemangler":
        """Get the singleton instance of this class."""
        inst = cls._INSTANCE or cls()
        cls._INSTANCE = inst
        return inst

    def demangle(self, mangled_name: str) -> Optional[str]:
        """Demangle a symbol name."""
        if self._demangle_func is not None:
            assert self._free_func

            name_ptr = ctypes.c_char_p(mangled_name.encode())
            status = ctypes.c_int()
            status_ptr = ctypes.pointer(status)

            # https://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
            # char* __cxa_demangle (
            #     const char *  mangled_name,
            #     char *        output_buffer,
            #     size_t *      length,
            #     int *         status
            # )
            retval = self._demangle_func(name_ptr, None, None, status_ptr)

            if status.value == 0:
                try:
                    demangled = ctypes.c_char_p(retval).value
                    if demangled:
                        return demangled.decode()
                finally:
                    self._free_func(retval)
        elif self._cxxfilt:
            return (
                subprocess.check_output([self._cxxfilt, mangled_name])
                .decode()
                .strip()
            )

        return None


class SymbolType(Enum):
    """Enumeration for recognized ELF symbol types (STT_* values)."""

    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6
    NUM = 7
    RELC = 8
    SRELC = 9
    LOOS = 10
    LOOS_PLUS_ONE = 11
    HIOS = 12
    LOPROC = 13
    LOPROC_PLUS_ONE = 14
    HIPROC = 15

    @staticmethod
    def of_elf_symbol(symbol: ELFSymbol) -> "SymbolType":
        """Return a symbol type from saved ST_INFO value."""
        stt_type = symbol["st_info"]["type"]  # STT_* of Elf

        # TODO: Recognize LOOS+1 and LOPROC+1

        try:
            return SymbolType[stt_type[len("STT_") :]]
        except Exception:
            return SymbolType.NOTYPE


@total_ordering
@dataclass(frozen=True, order=False)
class Symbol:
    """Represents a symbol in a binary file."""

    path: Path
    source: Optional[Path]
    name: str
    demangled: Optional[str]
    section: str
    address: int
    size: int
    type: SymbolType
    relocations: list[str] = field(hash=False)
    mtime: int

    def __lt__(self, other):
        return self.address < other.address


class CompilationDatabase:
    """Interface for retrieving data from ``compile_commands.json`` file."""

    def __init__(self, path: Path):
        """Construct a compilation database from file located at ``path``."""
        self._path = path
        self._source_to_binary: dict[Path, Path] = {}
        self._binary_to_source: dict[Path, Path] = {}

        self._read()

    def get_source_file_for_binary(self, binary: Path) -> Optional[Path]:
        """Return the source file for given binary file."""
        return self._binary_to_source.get(binary)

    def get_binary_for_source_file(self, source: Path) -> Optional[Path]:
        """Return the binary file for given source file."""
        return self._source_to_binary.get(source)

    def get_all_binary_files(self) -> list[Path]:
        """Get all known binary files."""
        return list(self._binary_to_source.keys())

    def _read(self):
        path = self._path

        with open(path) as f:
            data = json.load(f)

        for entry in data:
            directory = Path(entry.get("directory", path.parent))
            file = None
            source_file = Path(entry["file"])
            trace("For source file {}", source_file)

            if "output" in entry:
                file = Path(entry["output"])
                trace("  Found binary file in 'output': {}", file)
            elif "command" in entry:
                command = entry["command"]
                match = re.match(".* -o *([^ ]+).*", command)
                if match:
                    file = Path(match.group(1))
                    trace("  Found binary file in 'command': {}", file)
            elif "arguments" in entry:
                args = entry["arguments"]
                for prev, next in zip(args, args[1:]):
                    if prev == "-o":
                        file = Path(next)
                        trace("  Found binary file in 'arguments': {}", file)
                        break

            if not file:
                file = directory / (source_file.stem + ".o")
                trace("  Assuming {} is binary", file)
            if not file.is_absolute():
                file = directory / file

            self._source_to_binary[source_file] = file
            self._binary_to_source[file] = source_file


@cache
def _read_compdb(path: Path, _mtime: int) -> CompilationDatabase:
    return CompilationDatabase(path)


def _find_source_file_compdb(elf: ELFFile) -> Optional[Path]:
    binary_path = Path(elf.stream.name)
    compdb_path = find_compilation_database(binary_path.parent)
    if not compdb_path:
        return None

    compdb = _read_compdb(compdb_path, compdb_path.stat().st_mtime_ns)
    return compdb.get_source_file_for_binary(binary_path)


def _find_source_file_dwarfdump(elf: ELFFile) -> Optional[Path]:
    try:
        out = subprocess.check_output(
            ["dwarfdump", "-r", elf.stream.name]
        ).decode()
    except Exception:
        return None

    match = re.match(
        ".*DW_AT_name *([^\n]+).*DW_AT_comp_dir *([^\n]+).*",
        out,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        return None

    dw_at_name, dw_at_comp_dir = match.groups()

    path = Path(dw_at_comp_dir) / Path(dw_at_name)
    if path.exists():
        return path.resolve()
    return None


def _find_source_file(
    elf: ELFFile,
    use_compilation_database: bool,
    use_dwarfdump: bool,
) -> Optional[Path]:
    path = None

    if use_compilation_database:
        path = _find_source_file_compdb(elf)

    if not path and use_dwarfdump:
        path = _find_source_file_dwarfdump(elf)

    if path:
        trace("Found source file for {}: {}", Path(elf.stream.name), path)
    else:
        trace("Could not find source file for {}", Path(elf.stream.name))

    return path


def _read_symbols_in_file(
    file: Path,
    elf: ELFFile,
    demangle_names: bool,
    min_symbol_size: int,
    use_compilation_database: bool,
    use_dwarfdump: bool,
) -> list[Symbol]:
    symtab = elf.get_section_by_name(".symtab")
    if not isinstance(symtab, SymbolTableSection):
        msg = ".symtab is not a SymbolTableSection"
        raise RuntimeError(msg)

    mtime = os.stat(elf.stream.fileno()).st_mtime_ns
    source = _find_source_file(
        elf,
        use_compilation_database,
        use_dwarfdump,
    )

    demangler = NameDemangler.instance()

    symbols = []
    for symbol in symtab.iter_symbols():
        size = symbol["st_size"]
        if size < min_symbol_size:
            continue

        try:
            section = elf.get_section(symbol["st_shndx"]).name
        except Exception:
            section = ""

        demangled = demangler.demangle(symbol.name) if demangle_names else None

        symbols.append(
            Symbol(
                path=Path(file),
                source=source,
                name=symbol.name,
                demangled=demangled,
                section=section,
                address=symbol["st_value"],
                size=size,
                type=SymbolType.of_elf_symbol(symbol),
                relocations=list(),
                mtime=mtime,
            )
        )

    return symbols


def _find_relocation_target(
    reloc: Relocation, symlist: SortedList[Symbol]
) -> Optional[Symbol]:
    if not symlist:
        return None

    address = reloc["r_offset"]
    index = symlist.bisect_left(replace(symlist[0], address=address))

    possibilities = symlist[max(index - 1, 0) : index + 1]
    for symbol in possibilities:
        start = symbol.address
        end = start + symbol.size
        if start <= address < end:
            return symbol

    return None


def _read_relocations(elf: ELFFile, symbols: list[Symbol]):
    symbols_by_section: dict[str, SortedList[Symbol]] = defaultdict(SortedList)
    for sym in symbols:
        symbols_by_section[sym.section].add(sym)

    for reloc_section in elf.iter_sections():
        if not isinstance(reloc_section, RelocationSection):
            continue

        section = elf.get_section(reloc_section["sh_info"])
        symtable = elf.get_section(reloc_section["sh_link"])
        symlist = symbols_by_section[section.name]

        if not isinstance(symtable, SymbolTableSection):
            msg = (
                f"Section {symtable.name} linked to relocation section "
                f"{reloc_section.name} is not a valid SymbolTableSection"
            )
            raise RuntimeError(msg)

        for reloc in reloc_section.iter_relocations():
            symbol = _find_relocation_target(reloc, symlist)
            if symbol is None:
                continue

            relocated_symbol_name = symtable.get_symbol(
                reloc["r_info_sym"]
            ).name
            symbol.relocations.append(relocated_symbol_name)

    for symbol in symbols:
        refs = list(set(symbol.relocations))
        refs.sort()
        symbol.relocations.clear()
        symbol.relocations.extend(refs)


def read_symbols_in_file(
    file: str | Path,
    demangle_names: bool = True,
    with_relocations: bool = True,
    min_symbol_size=1,
    use_compilation_database: bool = True,
    use_dwarfdump: bool = True,
) -> list[Symbol]:
    """Get a symtable from the given file.

    Args:
        file: The binary file to read.
        demangle_names: If True, demangle names of each Symbol.
            Setting this to False can speed up reading.
        with_relocations: If True, populate ``relocations`` of each Symbol.
            Setting this to False can significantly speed up reading.
        min_symbol_size: Only return symbols whose size is greater or equal
            to this.
        use_compilation_database: If True, then use compile_commands.json
            file (if it exists) to get the source files for each symbol.
        use_dwarfdump: If True, then use the ``dwarfdump`` program (if it
            exists) to get the source files for each symbol (if available).

    """
    with open(file, "rb") as f, ELFFile(f) as elf:
        symbols = _read_symbols_in_file(
            Path(file),
            elf,
            demangle_names=demangle_names,
            min_symbol_size=min_symbol_size,
            use_compilation_database=use_compilation_database,
            use_dwarfdump=use_dwarfdump,
        )

        if with_relocations:
            _read_relocations(elf, symbols)

        return symbols


@cache
def find_compilation_database(path: Path) -> Optional[Path]:
    """Find the compilation db file in ``path`` or any of it's parent dirs."""
    for dir in [path, *path.parents]:
        file = dir / "compile_commands.json"
        if file.exists():
            return file
    return None


def is_readable_elf_file(path: Path) -> bool:
    """Return true if ``path`` points to an ELF file with read permissions."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except IOError:
        return False


@dataclass(frozen=True)
class BinaryDirectory:
    """Represents a directory containing zero or more binary files."""

    path: Path
    last_mtime: datetime = datetime.fromtimestamp(0)
    previous_file_list: list[Path] = field(repr=False, default_factory=list)
    use_compilation_database: bool = False

    _file_list: list[Path] = field(repr=False, default_factory=list)

    class CompilationDatabaseNotFoundError(FileNotFoundError):
        """Could not find the compilation database."""

    def __post_init__(self):
        self._file_list.extend(self._find_files())

    @cached_property
    def compilation_database(self):
        """The nearest compilation database for this directory."""
        compdb = find_compilation_database(self.path)
        if compdb is not None:
            info("Found compilation database: {}", compdb)
        return compdb

    def changed_files(self) -> Iterator[Path]:
        """Yield files that were changed/created since last run."""
        files = self._file_list
        previous_state = set(self.previous_file_list)

        for path in sorted(files):
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            is_new = path not in previous_state
            is_changed = not is_new and self.last_mtime < mtime

            trace(
                "{}: is_new={} is_changed={} mtime={}",
                path,
                is_new,
                is_changed,
                mtime,
            )

            if is_new or is_changed:
                yield path

    def deleted_files(self) -> Iterator[Path]:
        """Yield files that were deleted since last run."""
        files = set(self._file_list)
        previous_state = set(self.previous_file_list)

        deleted = previous_state.difference(files)
        yield from sorted(deleted)

    def _find_files(self) -> Iterator[Path]:
        if self.use_compilation_database:
            yield from self._find_files_from_compilation_database()
        else:
            for file in self.path.rglob("*.o"):
                if is_readable_elf_file(file):
                    yield file
                else:
                    trace("{}: Ignoring, Not a readable ELF file", file)

    def _find_files_from_compilation_database(self) -> Iterator[Path]:
        path = self.compilation_database
        if not path:
            msg = (
                f"compile_commands.json file not found in {path} "
                "or any of the parent directories"
            )
            raise BinaryDirectory.CompilationDatabaseNotFoundError(msg)

        compdb = _read_compdb(path, path.stat().st_mtime_ns)

        for file in compdb.get_all_binary_files():
            if is_readable_elf_file(file):
                yield file
