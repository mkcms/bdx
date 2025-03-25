from __future__ import annotations

import json
import multiprocessing as mp
import os
import pickle
import re
import signal
import threading
from collections import defaultdict
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from functools import cache
from pathlib import Path
from queue import Empty as QueueEmpty
from queue import Queue

# isort: off
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    Iterator,
    List,
    Optional,
    Type,
)

# isort: on
import xapian

from bdx import debug, detail_log, error, log, make_progress_bar, trace

# isort: off
from bdx.binary import (
    BinaryDirectory,
    Symbol,
    SymbolType,
    read_symbols_in_file,
)

# isort: on
MAX_TERM_SIZE = 244


@dataclass
class IndexingOptions:
    """User settings for indexing."""

    num_processes: int = os.cpu_count() or 1
    demangle_names: bool = True
    index_relocations: bool = False
    min_symbol_size: int = 1
    use_dwarfdump: bool = True


@dataclass(frozen=True)
class DatabaseField:
    """Contains information about a schema field."""

    name: str
    prefix: str

    # This DatabaseField will be responsible for indexing the
    # following key/attribute of each document (Symbol) added to the
    # index.
    key: str

    def index(self, document: xapian.Document, value: Any):
        """Index ``value`` in the ``document``."""
        value = self.preprocess_value(value)
        prefix = self.prefix.encode()

        term = prefix + value
        term = term[:MAX_TERM_SIZE]

        document.add_term(term)

    def preprocess_value(self, value: Any) -> bytes:
        """Preprocess the value before indexing it."""
        if not isinstance(value, (str, bytes)):
            value = str(value)
        if isinstance(value, str):
            value = value.encode()
        return value

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for the given value.

        Args:
            value: The string to search for in the query.
            wildcard: If true, make a wildcard query.

        """
        value = self.preprocess_value(value).decode()
        term = f"{self.prefix}{value}"
        if len(term) > MAX_TERM_SIZE:
            msg = (
                f"Term for '{self.name}' field is too long, max size "
                f"is {MAX_TERM_SIZE-len(self.prefix)}: '{value[:30]}'..."
            )
            raise ValueError(msg)

        if wildcard:
            return xapian.Query(
                xapian.Query.OP_WILDCARD,
                term,
                0,
                xapian.Query.WILDCARD_LIMIT_FIRST,
            )
        else:
            return xapian.Query(term)


class TextField(DatabaseField):
    """A database field that indexes text."""

    def index(self, document: xapian.Document, value: Any):
        """Index ``value`` in the ``document``."""
        termgen = xapian.TermGenerator()
        termgen.set_document(document)
        termgen.set_max_word_length(MAX_TERM_SIZE - len(self.prefix) - 1)
        termgen.index_text_without_positions(
            self.preprocess_value(value), 1, self.prefix
        )


@dataclass(frozen=True)
class IntegerField(DatabaseField):
    """A database field that indexes integers."""

    slot: int

    def preprocess_value(self, value: Any) -> bytes:
        """Preprocess the value before indexing it."""
        if not isinstance(value, int):
            msg = f"Invalid type for {self.__class__.__name__}: {value}"
            raise TypeError(msg)
        return xapian.sortable_serialise(value)

    def index(self, document: xapian.Document, value: Any):
        """Index ``value`` in the ``document``."""
        document.add_value(self.slot, self.preprocess_value(value))

    @staticmethod
    def _value_to_int(value: str) -> int:
        if value.startswith("0x"):
            return int(value[2:], base=16)
        else:
            return int(value, base=10)

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for the given value.

        Args:
            value: The string to search for in the query.  It must hold an
                integer or a xapian range expression: FROM..TO.
            wildcard: Unused.

        """
        hex_number = "(?:0x(?:[0-9a-fA-F])+)"
        dec_number = "(?:[0-9]+)"
        number = f"({hex_number}|{dec_number})"

        match = re.match(
            f"^{number}?[.][.]{number}?|{number}?$",
            value,
        )
        if not match:
            msg = f"Invalid integer range value: {value}"
            raise ValueError(msg)

        start, end, eq = match.groups()

        if eq is not None:
            # Exact value
            v = self.preprocess_value(self._value_to_int(eq))
            return xapian.Query(
                xapian.Query.OP_VALUE_RANGE,
                self.slot,
                v,
                v,
            )
        elif start is not None and end is not None:
            return xapian.Query(
                xapian.Query.OP_VALUE_RANGE,
                self.slot,
                (self.preprocess_value(self._value_to_int(start))),
                (self.preprocess_value(self._value_to_int(end))),
            )
        elif start is not None:
            return xapian.Query(
                xapian.Query.OP_VALUE_GE,
                self.slot,
                (self.preprocess_value(self._value_to_int(start))),
            )
        elif end is not None:
            return xapian.Query(
                xapian.Query.OP_VALUE_LE,
                self.slot,
                (self.preprocess_value(self._value_to_int(end))),
            )
        else:
            msg = f"Invalid integer range query: {value}"
            raise ValueError(msg)


class PathField(DatabaseField):
    """Represents a path field in the database."""

    def preprocess_value(self, value: Any) -> bytes:
        """Normalize the path in given value."""
        try:
            if value:
                # Normalize the path
                value = str(Path(value))
            return value.encode()
        except ValueError:
            # Accept anything the user provides
            pass
        return value

    def index(self, document: xapian.Document, value: Any):
        """Index ``value`` in the ``document``."""
        path = Path(value)
        super().index(document, path)

        # Also index the basename
        super().index(document, path.name)

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for the path in ``value``."""
        query = super().make_query(value, wildcard)

        if not value.startswith("/"):
            try:
                value = str((Path() / value).absolute().resolve())
                rhs_query = super().make_query(value, wildcard)

                query = xapian.Query(xapian.Query.OP_OR, query, rhs_query)

            except ValueError:
                pass

        return query


class RelocationsField(DatabaseField):
    """Represents a field for the list of relocations in a given symbol."""

    def index(self, document: xapian.Document, value: Any):
        """Index ``value`` in the ``document``."""
        if isinstance(value, list):
            for v in value:
                self.index(document, v)
        else:
            return super().index(document, value)


class SymbolNameField(TextField):
    """DatabaseField that indexes symbol names specially."""

    @staticmethod
    def tokenize_value(value: str) -> set[str]:
        """Split given value into tokens for indexing."""
        letters_only = re.findall("[a-zA-Z]{2,}", value)

        # Split "CamelCaseWord" into "Camel Case Word"
        camel_case_words = re.findall("[A-Z][a-z]+", " ".join(letters_only))

        # Find uppercase words
        upper_case_words = re.findall("[A-Z]{2,}", " ".join(letters_only))

        # Find lowercase words
        lower_case_words = re.findall("[a-z]{2,}", " ".join(letters_only))

        numbers = re.findall("[0-9]+", value)
        words_with_numbers = re.findall("[a-zA-Z]+[0-9]+", value)

        tokens = set()
        for tokenlist in [
            letters_only,
            camel_case_words,
            upper_case_words,
            lower_case_words,
            numbers,
            words_with_numbers,
        ]:
            tokens.update(tokenlist)

        return set(tokens)

    def index(self, document, value: Any):
        """Index ``value`` in the ``document``."""
        DatabaseField.index(self, document, value)
        DatabaseField.index(self, document, value.lower())

        if isinstance(value, bytes):
            value = value.decode()

        tokens = self.tokenize_value(value)
        value = " ".join(tokens)

        super().index(document, value)
        super().index(document, value.lower())

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for the given value.

        Args:
            value: The string to search for in the query.
            wildcard: If true, make a wildcard query.

        """
        if value.islower():
            return super().make_query(value, wildcard)

        return xapian.Query(
            xapian.Query.OP_OR,
            super().make_query(value, wildcard),
            xapian.Query(
                xapian.Query.OP_SCALE_WEIGHT,
                super().make_query(value.lower(), wildcard),
                0.6667,
            ),
        )


@dataclass(frozen=True)
class EnumField(DatabaseField):
    """DatabaseField that indexes values in an enumeration."""

    enum: type[Enum]

    def preprocess_value(self, value: Any) -> bytes:
        """Preprocess the value before indexing it."""
        if isinstance(value, self.enum):
            return str(value.name).encode()
        else:
            return super().preprocess_value(value)

    def index(self, document, value: Any):
        """Index ``value`` in the ``document``."""
        DatabaseField.index(self, document, value)

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for ``value``."""
        if wildcard:
            is_recognized_value = any(
                [x.startswith(value) for x in self.enum.__members__]
            )
        else:
            is_recognized_value = value in self.enum.__members__

        if not is_recognized_value:
            supported_values = ",".join(self.enum.__members__)
            msg = (
                f"Invalid {'prefix' if wildcard else 'value'} "
                f"for '{self.name}' field: '{value}'"
                f" (supported: {supported_values})"
            )
            raise ValueError(msg)

        query = super().make_query(value, wildcard)

        return query


@dataclass(frozen=True)
class _OptionalField(DatabaseField):
    field: DatabaseField

    def preprocess_value(self, value: Any) -> bytes:
        """Preprocess the value before indexing it."""
        if value is None:
            return b""

        return self.field.preprocess_value(value)

    def index(self, document, value: Any):
        """Index ``value`` in the ``document``."""
        if value is None:
            return

        self.field.index(document, value)

    def make_query(self, value: str, wildcard: bool = False) -> xapian.Query:
        """Make a query for ``value``."""
        return self.field.make_query(value, wildcard)


def optional_field(field: DatabaseField) -> DatabaseField:
    """Return a field that accepts ``None`` for indexing."""
    return _OptionalField(
        name=field.name,
        prefix=field.prefix,
        key=field.key,
        field=field,
    )


@dataclass(frozen=True)
class Schema(Mapping):
    """Contains information about database fields."""

    fields: List[DatabaseField] = field(default_factory=list)
    _field_dict: Dict[str, DatabaseField] = field(
        default_factory=dict, init=False, repr=False
    )
    _handlers: Dict[str, list[DatabaseField]] = field(
        default_factory=lambda: defaultdict(list), init=False, repr=False
    )

    def __post_init__(self):
        """Initialize internals."""
        for db_field in self.fields:
            if db_field.name in self._field_dict:
                msg = f"'{db_field.name}' is duplicated in the schema"
                raise ValueError(msg)
            self._field_dict[db_field.name] = db_field
            self._handlers[db_field.key].append(db_field)

    def __getitem__(self, key):
        if not self.fields:
            return DatabaseField(
                name=key,
                prefix=f"X{key.upper()}",
                key=key,
            )
        return self._field_dict[key]

    def __iter__(self):
        return iter(self._field_dict)

    def __len__(self):
        return len(self.fields)

    def index_document(self, document: xapian.Document, **data: str):
        """Index the ``data`` in given ``document``."""
        for key, val in data.items():
            if key not in self._handlers:
                continue

            handlers = self._handlers[key]
            for handler in handlers:
                handler.index(document, val)


class SymbolIndex:
    """Easy interface for a xapian database, with schema support."""

    @dataclass(frozen=True)
    class MatchResults:
        """Contains match results for search operation."""

        count: int
        mset: xapian.MSet = field(repr=False)

        def __iter__(self) -> Iterator[Symbol]:
            for match in self.mset:  # pyright: ignore
                document = match.document
                pickled_data = document.get_data()
                yield pickle.loads(pickled_data)

    SCHEMA = Schema(
        [
            PathField("path", "XP", key="path"),
            optional_field(PathField("source", "XSRC", key="source")),
            SymbolNameField("name", "XN", key="name"),
            optional_field(
                SymbolNameField("demangled", "XD", key="demangled")
            ),
            DatabaseField("fullname", "XFN", key="name"),
            DatabaseField("section", "XSN", key="section"),
            IntegerField("address", "XA", slot=0, key="address"),
            IntegerField("size", "XSZ", slot=1, key="size"),
            EnumField("type", "XT", key="type", enum=SymbolType),
            RelocationsField("relocations", "XR", key="relocations"),
            IntegerField("mtime", "XM", slot=2, key="mtime"),
        ]
    )

    class Error(RuntimeError):
        """General SymbolIndex error."""

    class ClosedError(Error):
        """SymbolIndex is closed error."""

    class TransactionInProgressError(Error):
        """Already in a transaction error."""

    class ReadOnlyError(Error):
        """SymbolIndex is read-only error."""

    class DoesNotExistError(Error):
        """SymbolIndex does not exist error."""

    class SchemaError(Error):
        """SymbolIndex schema error."""

    class ModifiedError(Error):
        """SymbolIndex was modified and should be reopened."""

    def __init__(
        self,
        path: Path,
        readonly: bool,
        is_shard: bool,
    ):
        """Construct a SymbolIndex at given ``path``.

        Do not use this constructor directly - instead, use one of the
        factory functions.

        """
        if not readonly:
            path.mkdir(exist_ok=True, parents=True)

        self._path = path

        try:
            if readonly:
                self._db = xapian.Database(str(path))
            else:
                self._db = xapian.WritableDatabase(str(path))

            trace("Opened xapian database (is_shard={}): {}", is_shard, path)
        except xapian.DatabaseOpeningError as e:
            if not path.is_dir():
                msg = f"SymbolIndex does not exist: {path}"
                raise SymbolIndex.DoesNotExistError(msg) from e
            if not os.access(path, os.R_OK):
                msg = f"SymbolIndex is not readable: {path}"
                raise SymbolIndex.Error(msg) from e
            raise SymbolIndex.Error(e) from e

        schema = self.SCHEMA
        pickled_schema = self.get_metadata("__schema__")
        if pickled_schema:
            saved_schema = pickle.loads(pickled_schema)
            if schema and schema != saved_schema:
                self._db.close()
                raise SymbolIndex.SchemaError(
                    "Schema on disk is different "
                    f"than the one in constructor ({saved_schema} != {schema})"
                )
            schema = saved_schema

        self._shards: list[xapian.Database | xapian.WritableDatabase] = []
        self._is_shard = is_shard
        if not is_shard:
            for shard in self.shards():
                trace("Adding shard: {}", shard)
                if readonly:
                    db = xapian.Database(str(shard))
                else:
                    db = xapian.WritableDatabase(str(shard))
                self._shards.append(db)
                self._db.add_database(db)

        self._schema = schema or Schema()

        if not readonly:
            self.set_metadata("__schema__", pickle.dumps(schema))

    @staticmethod
    def open(directory: Path | str, readonly: bool = False) -> "SymbolIndex":
        """Open a SymbolIndex.

        Args:
            directory: Path to the database directory.
                It will be created if it doesn't exist, except
                if ``readonly``.
            readonly: If False, create a writable database,
                otherwise the database will be read-only.

        """
        index = SymbolIndex(
            Path(directory) / "db", readonly=readonly, is_shard=False
        )

        debug("Opened index: {}", index.path)
        debug("Index has saved binary directory: {}", index.binary_dir())
        debug("Index mtime: {}", index.mtime())
        trace("Index schema: {}", index.schema)

        return index

    @staticmethod
    def open_shard(directory: Path | str) -> "SymbolIndex":
        """Open a writable shard for index in given directory."""
        for path in SymbolIndex.generate_shard_paths(Path(directory) / "db"):
            try:
                return SymbolIndex(path, readonly=False, is_shard=True)
            except Exception:
                pass

        msg = f"Could not open shard for {directory}"
        raise SymbolIndex.Error(msg)

    @staticmethod
    def generate_shard_paths(directory: Path | str) -> Iterator[Path]:
        """Infinitely yield paths to possible shards of this database.

        The shards reside in the same directory, but with different suffix.

        """
        directory = Path(directory).absolute()
        i = 0
        while True:
            yield directory.parent / f"{directory.name}.{i:0>3}"
            i += 1

    def shards(self) -> Iterator[Path]:
        """Yield the shards of this database."""
        for x in self.generate_shard_paths(self.path):
            if x.exists():
                yield x
            else:
                break

    @staticmethod
    def default_path(directory: Path | str) -> Path:
        """Return a default index path for binary ``directory``."""
        parts = Path(directory).absolute().parts[1:]
        global_cache_dir = Path(
            os.getenv("XDG_CACHE_HOME", "~/.cache")
        ).expanduser()
        basename = "!".join(parts)
        return global_cache_dir / "bdx" / "index" / basename

    @property
    def path(self) -> Path:
        """The path of this SymbolIndex."""
        return self._path

    @property
    def schema(self) -> Schema:
        """The schema of this SymbolIndex."""
        return self._schema

    def close(self):
        """Close this SymbolIndex."""
        if self._is_shard:
            trace("Closing shard: {}", self.path)
        else:
            debug("Closing index: {}", self.path)
        self._live_db().close()
        self._db = None

    def __enter__(self):
        self._live_db()
        return self

    def __exit__(self, *_args):
        self.close()

    def get_metadata(self, key: str) -> bytes:
        """Get the metadata associated with given key, or empty bytes obj."""
        if not key:
            msg = "Key must be a non-empty string"
            raise ValueError(msg)
        return self._live_db().get_metadata(key)

    def get_metadata_keys(self) -> Iterator[str]:
        """Yield all metadata keys in this SymbolIndex."""
        for key in self._live_db().metadata_keys():  # pyright: ignore
            yield key.decode()

    def set_metadata(self, key: str, metadata: bytes):
        """Set metadata for the given key."""
        if not key:
            msg = "Key must be a non-empty string"
            raise ValueError(msg)
        self._live_writable_db().set_metadata(key, metadata)

    def mtime(self) -> datetime:
        """Return the max modification time of this index."""
        db = self._live_db()
        field_data = self.schema["mtime"]
        val = db.get_value_upper_bound(field_data.slot)  # pyright: ignore
        if not val:
            return datetime.fromtimestamp(0)

        val_int = xapian.sortable_unserialise(val)
        return datetime.fromtimestamp(val_int / 1e9)

    def binary_dir(self) -> Optional[Path]:
        """Get binary directory of this index, set by ``set_binary_dir``."""
        if "binary_dir" in set(self.get_metadata_keys()):
            return Path(self.get_metadata("binary_dir").decode())
        return None

    def set_binary_dir(self, binary_dir: Path):
        """Set the modification time of this index."""
        self.set_metadata("binary_dir", str(binary_dir).encode())

    @contextmanager
    def transaction(self):
        """Return a context manager for transactions in this SymbolIndex."""
        try:
            self._live_writable_db().begin_transaction()
        except xapian.InvalidOperationError as e:
            msg = "Already inside a transaction"
            raise SymbolIndex.TransactionInProgressError(msg) from e

        try:
            yield None
            self._live_writable_db().commit_transaction()
        except Exception as e:
            debug("Cancel transaction due to error: {}", e)
            self._live_writable_db().cancel_transaction()
            raise

    def add_symbol(self, symbol: Symbol):
        """Add a document to the SymbolIndex."""
        db = self._live_writable_db()
        document = xapian.Document()
        self.schema.index_document(document, **asdict(symbol))
        document.set_data(pickle.dumps(symbol))
        db.add_document(document)

    def delete_file(self, file: Path):
        """Delete all documents for the given file path."""
        term_with_prefix = self.schema["path"].prefix + str(file)
        self._live_writable_db().delete_document(term_with_prefix)

    def all_files(self) -> Iterator[Path]:
        """Yield all the files indexed in this SymbolIndex."""
        for value in self.iter_prefix("path", ""):
            path = Path(value)
            if path.is_absolute():
                yield path

    def iter_prefix(self, field: str, value_prefix: str) -> Iterator[str]:
        """Return all the possible values for ``field`` with given prefix."""
        db = self._live_db()
        field_data = self.schema[field]
        all_terms = db.allterms(  # pyright: ignore
            field_data.prefix + value_prefix
        )

        for term in all_terms:
            value = term.term[len(field_data.prefix) :]
            yield value.decode()

    def search(
        self,
        query: str | xapian.Query,
        first: int = 0,
        limit: Optional[int] = None,
    ) -> "SymbolIndex.MatchResults":
        """Find symbols matching the given ``query``."""
        db = self._live_db()

        if limit is None:
            limit = db.get_doccount()

        if isinstance(query, str):
            query = self.parse_query(query)

        enquire = xapian.Enquire(db)
        enquire.set_query(query)

        try:
            mset = enquire.get_mset(first, limit)
            return self.MatchResults(mset.size(), mset)
        except xapian.InvalidArgumentError:
            return self.MatchResults(0, xapian.MSet())
        except xapian.DatabaseModifiedError as e:
            raise SymbolIndex.ModifiedError from e

    def make_query_parser(self):
        """Return a query parser object for this index."""
        from bdx.query_parser import QueryParser

        return QueryParser(
            SymbolIndex.SCHEMA,
            default_fields=["name", "demangled"],
            auto_wildcard=True,
        )

    def parse_query(self, query: str) -> xapian.Query:
        """Parse the given query string, returning a Query object."""
        return self.make_query_parser().parse_query(query)

    def _live_db(self) -> xapian.Database | xapian.WritableDatabase:
        if self._db is None:
            msg = "SymbolIndex is not open"
            raise SymbolIndex.ClosedError(msg)
        return self._db

    def _live_writable_db(self) -> xapian.WritableDatabase:
        db = self._live_db()
        if not isinstance(db, xapian.WritableDatabase):
            msg = "SymbolIndex is open for reading only"
            raise SymbolIndex.ReadOnlyError(msg)
        return db


@dataclass
class IndexingStats:
    """Contains stats about indexing operation."""

    num_files_indexed: int = 0
    num_files_changed: int = 0
    num_files_deleted: int = 0
    num_symbols_indexed: int = 0


@contextmanager
def sigint_catcher() -> Iterator[Callable[[], bool]]:
    """Context manager that temporarily disables SIGINT exceptions.

    The yielded value is callable.  It returns true if SIGINT was
    signalled.

    """
    original_handler = signal.getsignal(signal.SIGINT)

    called = False

    def handler(*_args):
        nonlocal called
        called = True
        log("Interrupted, press C-c again to exit")
        signal.signal(signal.SIGINT, original_handler)

    def checker():
        return called

    try:
        signal.signal(signal.SIGINT, handler)
        yield checker
    finally:
        signal.signal(signal.SIGINT, original_handler)


def _index_single_file(
    index: SymbolIndex,
    file: Path,
    options: IndexingOptions,
    use_compilation_database: bool,
) -> int:
    try:
        symtab = read_symbols_in_file(
            file,
            demangle_names=options.demangle_names,
            with_relocations=options.index_relocations,
            min_symbol_size=options.min_symbol_size,
            use_compilation_database=use_compilation_database,
            use_dwarfdump=options.use_dwarfdump,
        )
    except Exception as e:
        log("{}: {}: {}", file, e.__class__.__name__, str(e))
        debug("{}", e)
        return 0

    num = 0

    for symbol in symtab:
        detail_log(
            "Got symbol '{}' in {}, section '{}', size {}, mtime {}",
            symbol.name,
            symbol.path,
            symbol.section,
            symbol.size,
            symbol.mtime,
        )

        index.add_symbol(symbol)

        num += 1

    if num == 0:
        trace("{}: No symbols found", file)
        # Add a single document if there are no symbols.  Otherwise,
        # we would always treat it as unindexed.
        index.add_symbol(
            Symbol(
                path=file,
                source=None,
                name="",
                demangled=None,
                section="",
                address=0,
                size=0,
                type=SymbolType.NOTYPE,
                relocations=list(),
                mtime=file.stat().st_mtime_ns,
            )
        )
        num += 1

    trace("{}: Adding {} symbol(s) to index", file, num)

    return num


class _WorkerPool:
    """Runs indexing jobs in parallel."""

    def __init__(
        self,
        options: IndexingOptions,
        should_quit: Callable[[], bool],
        index_path: Path,
        use_compilation_database: bool,
    ):
        self.options = options
        self.should_quit = should_quit
        self.index_path = index_path
        self.use_compilation_database = use_compilation_database

        self._job_queue: Queue[Path]
        self._result_queue: Queue[int]
        self._worker_class: Type
        self._workers: list[mp.Process]

        if os.getenv("_BDX_NO_MULTIPROCESSING"):
            self._job_queue = Queue()
            self._result_queue = Queue()
            self._stop_event = threading.Event()
            self._worker_class = threading.Thread  # type: ignore
            self._workers = []
            self._num_processes = 1
        else:
            self._job_queue = mp.Queue()  # type: ignore
            self._result_queue = mp.Queue()  # type: ignore
            self._stop_event = mp.Event()  # type: ignore
            self._worker_class = mp.Process
            self._workers = []
            self._num_processes = options.num_processes

    def __enter__(self):
        if self._workers:
            msg = "Pool already running"
            raise RuntimeError(msg)

        for _ in range(self._num_processes):
            worker = self._worker_class(target=self._worker)
            self._workers.append(worker)

        for worker in self._workers:
            worker.start()

        return self

    def __exit__(self, *_args):
        self._stop_event.set()
        for worker in self._workers:
            worker.join()
        self._workers.clear()
        self._stop_event.clear()
        while True:
            try:
                self._job_queue.get_nowait()
            except QueueEmpty:
                break

    def index_files(self, files: Collection[Path]) -> Iterator[int]:
        if not self._workers:
            msg = "Pool is not running"
            raise RuntimeError(msg)
        if not files:
            return
        for file in files:
            self._job_queue.put(file)

        num_done = 0

        while not self.should_quit():
            try:
                result = self._result_queue.get(timeout=0.1)
                yield result
                num_done += 1

                if num_done == len(files):
                    break
            except QueueEmpty:
                pass

            some_workers_failed = not all(
                [x.is_alive() for x in self._workers]
            )

            if some_workers_failed:
                log("error: Some workers failed")
                break

    def _worker(self):
        with (
            SymbolIndex.open_shard(self.index_path) as index,
            index.transaction(),
        ):
            while not self._stop_event.is_set():
                parent = mp.parent_process()
                if parent is not None and not parent.is_alive():
                    error("Parent process died")

                try:
                    path = self._job_queue.get(timeout=0.1)
                except QueueEmpty:
                    continue

                result = _index_single_file(
                    index, path, self.options, self.use_compilation_database
                )

                self._result_queue.put(result)


def index_binary_directory(
    directory: str | Path,
    index_path: Path,
    options: IndexingOptions,
    use_compilation_database: bool = False,
    reindex: bool = False,
) -> IndexingStats:
    """Index the given directory."""
    stats = IndexingStats()
    debug("Options: {}", options)

    bindir_path = Path(directory)

    with SymbolIndex.open(index_path, readonly=False) as index:
        if index.binary_dir() is None:
            index.set_binary_dir(bindir_path)

        if reindex:
            mtime = datetime.fromtimestamp(0)
        else:
            mtime = index.mtime()
        existing_files = list(index.all_files())
        bdir = BinaryDirectory(
            bindir_path,
            mtime,
            existing_files,
            use_compilation_database=use_compilation_database,
        )

        changed_files = list(bdir.changed_files())
        deleted_files = list(bdir.deleted_files())

        changed_files.sort()
        deleted_files.sort()

        stats.num_files_changed = len(changed_files)
        stats.num_files_deleted = len(deleted_files)

        for file in make_progress_bar(
            changed_files,
            desc="Removing outdated files",
            leave=False,
        ):
            index.delete_file(file)
            debug("File modified: {}", file)
        for file in make_progress_bar(
            deleted_files,
            desc="Removing deleted files",
            leave=False,
        ):
            index.delete_file(file)
            debug("File deleted: {}", file)

    with (
        sigint_catcher() as interrupted,
        _WorkerPool(
            options,
            interrupted,
            index_path,
            use_compilation_database=use_compilation_database,
        ) as pool,
    ):
        perfile_iterator = pool.index_files(changed_files)

        iterator = make_progress_bar(
            perfile_iterator, unit="file", total=len(changed_files)
        )

        for num in iterator:
            stats.num_files_indexed += 1
            stats.num_symbols_indexed += num

            if interrupted():
                log("Interrupted, exiting")
                break

    return stats


def delete_index(index_path: Path):
    """Delete index at given path."""
    if not index_path.exists():
        log("Index does not exist - not deleting")
        return

    files_to_remove: list[Path] = []
    dirs_to_remove: list[Path] = []

    with SymbolIndex.open(index_path, readonly=False) as index:
        for shard_path in [index.path, *index.shards()]:
            required_files = [
                shard_path / "flintlock",
                shard_path / "iamglass",
                shard_path / "postlist.glass",
                shard_path / "termlist.glass",
            ]
            optional_files = [
                shard_path / "docdata.glass",
            ]

            for file in required_files:
                if not file.exists():
                    error(
                        "Shard file {} does not exist - not deleting database",
                        file,
                    )

                files_to_remove.append(file)

            for file in optional_files:
                if file.exists():
                    files_to_remove.append(file)

            dirs_to_remove.append(shard_path)

    for file in files_to_remove:
        debug("Deleting db file: {}", file)
        file.unlink()

    for dir in dirs_to_remove:
        debug("Deleting db directory: {}", dir)
        dir.rmdir()

    debug("Deleting index directory: {}", index_path)
    index_path.rmdir()


@dataclass(frozen=True)
class SearchResult:
    """A single symbol retrieved from index."""

    i: int  # Index within all results
    total: int

    symbol_outdated: bool
    binary_outdated: bool

    symbol: Symbol

    def asdict(self) -> dict[str, Any]:
        """Serialize this object to a dict."""

        def valueconv(v):
            if isinstance(v, Enum):
                return v.name

            try:
                json.dumps(v)
                return v
            except Exception:
                return str(v)

        data = asdict(self.symbol)

        return {
            "outdated": {
                "binary": self.binary_outdated,
                "symbol": self.symbol_outdated,
            },
            "index": self.i,
            "total": self.total,
            **{k: valueconv(v) for k, v in data.items()},
        }

    def dynamic_fields(self) -> dict[str, Any]:
        """Return useful additional fields that are set dynamically."""
        return {
            "basename": self.symbol.path.name,
            "endaddress": self.symbol.address + self.symbol.size,
        }


def _parse_query(index: SymbolIndex, query: str) -> xapian.Query:
    try:
        return index.parse_query(query)
    except Exception as e:
        msgs = [f"Invalid query: {str(e)}"]

        quoted = json.dumps(query)
        parsed_quoted = index.parse_query(quoted + "*")
        if index.search(parsed_quoted, limit=1).count > 0:
            msgs.append("Did you forget to quote the demangled symbol name?")

        error("\n".join(msgs))
        exit(1)


def search_index(
    index_path: Path,
    query: str,
    limit: Optional[int] = None,
) -> Iterator[SearchResult]:
    """Search the given index.

    Args:
        index_path: The index to search.
        query: The query to search for.
        limit: Optional limit of search results.

    """
    outdated_paths_in_index = set()
    outdated_binaries = set()  # need recompilation for these

    @cache
    def stat_mtime(path: Path):
        try:
            return path.stat().st_mtime_ns
        except Exception:
            return 0

    def is_symbol_outdated(symbol: Symbol):
        return stat_mtime(symbol.path) != symbol.mtime

    def is_binary_outdated(symbol: Symbol):
        return symbol.source is not None and stat_mtime(
            symbol.path
        ) < stat_mtime(symbol.source)

    if not query:
        query = "*:*"

    with SymbolIndex.open(index_path, readonly=True) as index:
        parsed_query = _parse_query(index, query)
        debug("Search query: {}", parsed_query)

        results = index.search(parsed_query, limit=limit)
        debug("Number of results: {}", results.count)

        for i, symbol in enumerate(results):

            res = SearchResult(
                i=i,
                total=results.count,
                symbol_outdated=is_symbol_outdated(symbol),
                binary_outdated=is_binary_outdated(symbol),
                symbol=symbol,
            )

            if res.symbol_outdated:
                outdated_paths_in_index.add(symbol.path)

            if res.binary_outdated:
                outdated_binaries.add(symbol.path)

            yield res

    if outdated_paths_in_index:
        for file in outdated_paths_in_index:
            trace("Outdated in index: {}", file)

        log(
            (
                "Warning: Indexed information is outdated for {} file(s),"
                " run `index` command to re-index"
            ),
            len(outdated_paths_in_index),
        )

    if outdated_binaries:
        for file in outdated_binaries:
            trace("Outdated binary: {}", file)

        log(
            (
                "Warning: Binary file(s) older than source: {},"
                " re-compile and run `index` command to re-index"
            ),
            len(outdated_binaries),
        )
