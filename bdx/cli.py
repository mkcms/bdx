from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from functools import wraps
from pathlib import Path
from sys import exit
from typing import Any, Optional

import click
from click.shell_completion import CompletionItem
from click.types import BoolParamType, IntRange

import bdx
from bdx import debug, error, info, log, make_progress_bar, trace
# fmt: off
from bdx.binary import BinaryDirectory, find_compilation_database
from bdx.index import (IndexingOptions, PathField, SymbolIndex, _OptionalField,
                       delete_index, index_binary_directory, search_index)
from bdx.query_parser import QueryParser

# fmt: on

try:
    import bdx.graph

    have_graphs = True
except ImportError:
    have_graphs = False


def sexp_format(data: Any) -> str:
    """Format data as a Lisp S-expression.

    Dicts are formatted as plists, with keys formatted in ``:key`` format.
    """
    if data is None:
        return "nil"
    elif isinstance(data, list):
        return "({})".format(" ".join([sexp_format(x) for x in data]))
    elif isinstance(data, dict):

        def fmt(item):
            key, value = item
            return f":{key} {sexp_format(value)}"

        return "({})".format(" ".join([fmt(x) for x in data.items()]))
    elif isinstance(data, bool):
        return "t" if data else "nil"
    elif isinstance(data, (str, int, float)):
        return json.dumps(data)
    msg = f"Invalid value: {data}"
    raise ValueError(msg)


def guess_directory_from_index_path(
    index_path: Optional[Path],
) -> Optional[Path]:
    """Return the path to the binary directory for given index path."""
    if index_path is not None and Path(index_path).exists():
        try:
            with SymbolIndex.open(index_path, readonly=True) as index:
                binary_dir = index.binary_dir()
                if binary_dir is not None:
                    return binary_dir
        except SymbolIndex.Error:
            return None
    return None


def default_directory(ctx: click.Context) -> Path:
    """Return the default binary directory using given CLI context."""
    cwd = Path().absolute()
    if "use_compilation_database" in ctx.params:
        compdb = find_compilation_database(cwd)
        if compdb is not None:
            return compdb.parent

    possible_index_paths = []
    possible_index_paths.append(ctx.params.get("index_path"))
    possible_index_paths.append(SymbolIndex.default_path(Path(".")))
    possible_index_paths.extend(
        [SymbolIndex.default_path(x) for x in cwd.parents]
    )
    for index_path in possible_index_paths:
        directory = guess_directory_from_index_path(index_path)
        if directory:
            return directory

    return cwd


def _common_options(index_must_exist=False):

    def decorator(f):

        @click.option(
            "-d",
            "--directory",
            type=click.Path(
                exists=True,
                dir_okay=True,
                file_okay=False,
                resolve_path=True,
            ),
            help="Path to the binary directory.",
        )
        @click.option(
            "--index-path",
            type=click.Path(
                exists=index_must_exist,
                dir_okay=True,
                file_okay=False,
                resolve_path=True,
            ),
            help="Path to the index.  By default, it is located in ~/.cache.",
        )
        @click.option(
            "-v",
            "--verbose",
            count=True,
            help=(
                "Be verbose.  Can be provided multiple times "
                " for increased verbosity."
            ),
        )
        @click.pass_context
        @wraps(f)
        def inner(
            ctx: click.Context,
            *args,
            directory: str | Path,
            index_path: str | Path,
            verbose: int,
            **kwargs,
        ):
            did_guess_directory = False

            if not directory:
                directory = default_directory(ctx)
                did_guess_directory = True
            if not index_path:
                index_path = SymbolIndex.default_path(directory)

            index_path = Path(index_path)
            directory = Path(directory)

            if index_path.exists():
                try:
                    with SymbolIndex.open(index_path, readonly=True) as index:
                        indexed_dir = index.binary_dir()
                        if (
                            indexed_dir is not None
                            and indexed_dir != directory
                        ):
                            msg = (
                                "Index is for different "
                                f"directory: {indexed_dir}"
                            )
                            raise click.BadParameter(msg)
                except SymbolIndex.Error as e:
                    msg = f"Invalid index: {index_path}"
                    raise click.BadParameter(msg) from e
            elif index_must_exist:
                msg = f"Directory is not indexed: {directory}"
                raise click.UsageError(msg)

            bdx.VERBOSITY = verbose

            if did_guess_directory:
                info(f"note: Using {directory} as binary directory")

            debug("Binary directory: {}", str(directory.absolute()))
            debug("PWD: {}", str(Path().absolute()))

            f(*args, directory, index_path, **kwargs)

        return inner

    return decorator


class IndexingOptionParamType(click.ParamType):
    """Click parameter type for indexing --opt."""

    name = "option"

    OPTIONS = [x for x in dir(IndexingOptions) if not x.startswith("_")]

    CONVERTERS = {
        "num_processes": IntRange(min=1, max=(os.cpu_count() or 1) * 2),
        "demangle_names": BoolParamType(),
        "index_relocations": BoolParamType(),
        "min_symbol_size": IntRange(min=0),
        "use_dwarfdump": BoolParamType(),
    }

    def convert(self, value, param, ctx):
        """Convert the given value to correct type, or error out."""
        try:
            k, v = value.split("=", maxsplit=1)
        except ValueError:
            self.fail(f"Argument '{value}' should be of the form 'key=value'")

        if k not in self.OPTIONS:
            self.fail(f"Unknown option '{k}'")

        try:
            return (k, self.CONVERTERS[k].convert(v, param, ctx))
        except click.BadParameter as e:
            raise click.BadParameter(f"{k}: {e}") from e

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ) -> list[CompletionItem]:
        """Complete choices that start with the incomplete value."""
        if "=" not in incomplete:
            matched = (
                c + "=" for c in self.OPTIONS if c.startswith(incomplete)
            )
        else:
            k, v = incomplete.split("=", maxsplit=1)

            if k not in self.OPTIONS:
                return []

            items = self.CONVERTERS[k].shell_complete(ctx, param, v)
            matched = (f"{k}={i.value}" for i in items)

        return [CompletionItem(c) for c in matched]

    def get_metavar(self, param: click.Parameter) -> str:
        """Get the metavar for this option."""
        return "|".join([f"{o}=VALUE" for o in self.OPTIONS])


@click.group()
def cli():
    """Binary indexer."""
    pass


@cli.command()
@_common_options(index_must_exist=False)
@click.option("-c", "--use-compilation-database", is_flag=True)
@click.option(
    "-o",
    "--opt",
    multiple=True,
    type=IndexingOptionParamType(),
    help="Set indexing options (key=value).",
)
@click.option(
    "-r",
    "--reindex",
    is_flag=True,
    help="Treat all files as outdated to reindex them.",
)
@click.option(
    "--delete",
    is_flag=True,
    help=(
        "Delete the entire Xapian database before indexing. "
        "This can significantly speed up indexing if a lot of files "
        " have been modified/removed."
    ),
)
def index(
    directory, index_path, opt, use_compilation_database, reindex, delete
):
    """Index the specified directory."""
    if delete:
        delete_index(index_path)

    options = IndexingOptions(**dict(opt))

    try:
        stats = index_binary_directory(
            directory,
            index_path,
            options=options,
            use_compilation_database=use_compilation_database,
            reindex=reindex,
        )
    except BinaryDirectory.CompilationDatabaseNotFoundError as e:
        error(str(e))
        exit(1)

    log(
        f"Files indexed: {stats.num_files_indexed} "
        f"(out of {stats.num_files_changed} changed files)"
    )
    log(f"Files removed from index: {stats.num_files_deleted}")
    log(f"Symbols indexed: {stats.num_symbols_indexed}")


class SearchOutputFormatParamType(click.Choice):
    """Click parameter type for search --format."""

    OPTIONS = [
        "json",
        "sexp",
        # Add the default Python format as an example
        "{basename}: {name}",
    ]

    def __init__(self):
        """Initialize this param type instance."""
        super().__init__(list(self.OPTIONS))

    def convert(self, value, param, ctx):
        """Convert the given value to correct type, or error out."""
        return value


def _complete_query(
    ctx: click.Context, param: click.Parameter, incomplete: str
) -> list[CompletionItem]:
    """Generate a list of completions for ``incomplete`` query string."""
    directory = ctx.params["directory"]
    index_path = ctx.params["index_path"]

    if not directory:
        directory = default_directory(ctx)
    if not index_path:
        index_path = SymbolIndex.default_path(directory)

    query = ctx.params[param.name or "query"] or []
    shell = os.environ.get("_BDX_COMPLETE", "").lower()

    if not isinstance(query, (list, tuple)):
        query = [query]

    try:
        index = SymbolIndex.open(index_path, readonly=True)
    except Exception:
        return []

    query_parser = index.make_query_parser()

    if "bash" in shell:
        search_field = None
        term = ""

        if len(query) >= 2 and query[-1] == ":":
            # Searching specific fields
            search_field = query[-2]
            term = incomplete
        elif query and incomplete == ":":
            # Also searching specific fields (no value char is present yet)
            search_field = query[-1]
            term = ""

        if search_field:
            with index:
                try:
                    completions = [
                        CompletionItem(i)
                        for i in index.iter_prefix(search_field, term)
                    ]

                    field_obj = index.schema[search_field]
                    if isinstance(field_obj, _OptionalField):
                        field_obj = field_obj.field
                    if isinstance(field_obj, PathField):
                        path_completions = [
                            comp[len(search_field + ":") :]
                            for comp in query_parser.complete_query(
                                index, f"{search_field}:{term}"
                            )
                        ]
                        completions += [
                            CompletionItem(i) for i in path_completions
                        ]

                    return completions
                except Exception:
                    return []

    with index:
        results = query_parser.complete_query(index, incomplete)
        results = list(results)

    if "zsh" in shell:
        # Zsh completion in Click does not always work properly if the
        # completions don't share a common prefix with what was typed
        # by the user
        results = [i for i in results if i.startswith(incomplete)]

    return [CompletionItem(i) for i in results]


@cli.command()
@_common_options(index_must_exist=True)
@click.argument(
    "query",
    nargs=-1,
    shell_complete=_complete_query,
)
@click.option(
    "-n",
    "--num",
    help="Limit the number of results",
    type=click.IntRange(1),
    metavar="LIMIT",
    default=None,
)
@click.option(
    "-f",
    "--format",
    help=(
        "Output format (json, sexp, or Python string format). "
        "'{}'-placeholders are replaced with symbol fields."
    ),
    type=SearchOutputFormatParamType(),
    nargs=1,
    default=None,
)
def search(_directory, index_path, query, num, format):
    """Search binary directory for symbols."""
    results = search_index(
        index_path=index_path, query=" ".join(query), limit=num
    )

    if format is None:
        fmt = "{basename}: {name}"
    else:
        fmt = format

    while True:
        try:
            res = next(results)
        except QueryParser.Error as e:
            error(f"Invalid query: {str(e)}")
            exit(1)
        except StopIteration:
            break

        data = res.asdict()

        if fmt == "json":
            click.echo(json.dumps(data))
        elif fmt == "sexp":
            click.echo(sexp_format(data))
        else:
            data.update(res.dynamic_fields())

            try:
                click.echo(fmt.format(**data))
            except (KeyError, ValueError, TypeError) as e:
                error(
                    "Invalid format: {!r} in {!r}\nAvailable keys: {}",
                    str(e),
                    fmt,
                    list(data.keys()),
                )
                exit(1)


@cli.command()
@_common_options(index_must_exist=True)
@click.argument(
    "query",
    nargs=-1,
    shell_complete=_complete_query,
)
@click.option(
    "-n",
    "--num",
    help="Limit the number of results",
    type=click.IntRange(1),
    metavar="LIMIT",
    default=None,
)
@click.option(
    "-D",
    "--disassembler",
    help=(
        "The command to run to disassemble a symbol. "
        "'{}'-placeholders are replaced with search keys."
    ),
    nargs=1,
    default=(
        "objdump -dC "
        "--no-show-raw-insn "
        "'{path}' "
        "--section '{section}' "
        "--start-address 0x{address:x} --stop-address 0x{endaddress:x}"
    ),
    show_default=True,
    metavar="COMMAND",
)
@click.option(
    "-M",
    "--disassembler-options",
    help=(
        "Additional string to append to command given by -D. "
        "'{}'-placeholders can also be present here."
    ),
    nargs=1,
    default="",
    show_default=True,
    metavar="OPTS",
)
def disass(
    _directory, index_path, query, num, disassembler, disassembler_options
):
    """Search binary directory for symbols."""
    results = search_index(
        index_path=index_path, query=" ".join(query), limit=num
    )

    if disassembler_options:
        disassembler += " " + disassembler_options

    while True:
        try:
            res = next(results)
        except QueryParser.Error as e:
            error(f"Invalid query: {str(e)}")
            exit(1)
        except StopIteration:
            break

        if res.symbol_outdated:
            error("Information outdated, re-index needed")

        data = res.asdict()
        data.update(res.dynamic_fields())

        try:
            cmd = disassembler.format(**data)
        except (KeyError, ValueError, TypeError) as e:
            error(
                "Invalid format: {!r} in {!r}\nAvailable keys: {}",
                str(e),
                disassembler,
                list(data.keys()),
            )
            exit(1)

        trace("Symbol: {}", res)
        debug("Running command: {}", cmd)
        subprocess.check_call(cmd, shell=True)


@cli.command()
@_common_options(index_must_exist=True)
def files(_directory, index_path):
    """List all indexed files in a binary directory."""
    with SymbolIndex.open(index_path, readonly=True) as index:
        for path in index.all_files():
            click.echo(path)


@cli.command()
@click.argument("query")
@_common_options(index_must_exist=True)
def complete_query(_directory, index_path, query):
    """Print possible completions of the given query."""
    with SymbolIndex.open(index_path, readonly=True) as index:
        parser = index.make_query_parser()
        for completion in parser.complete_query(index, query):
            print(completion)


if have_graphs:
    from bdx.graph import GraphAlgorithm, generate_graph

    class GraphAlgorithmParamType(click.Choice):
        """Click parameter type for graph --algorithm."""

        OPTIONS = GraphAlgorithm.__members__

        def __init__(self):
            """Initialize this param type instance."""
            super().__init__(list(self.OPTIONS))

        def convert(self, value, param, ctx):
            """Convert the given value to correct type, or error out."""
            return GraphAlgorithm(super().convert(value, param, ctx))

    @cli.command()
    @_common_options(index_must_exist=True)
    @click.argument(
        "start_query",
        nargs=1,
        shell_complete=_complete_query,
    )
    @click.argument(
        "goal_query",
        nargs=1,
        shell_complete=_complete_query,
    )
    @click.option(
        "-n",
        "--num-routes",
        type=click.IntRange(min=0),
        default=1,
        help="Generate at most N routes (0=infinity)",
    )
    @click.option(
        "-a",
        "--algorithm",
        type=GraphAlgorithmParamType(),
        default="ASTAR",
        help="The algorithm to choose",
    )
    @click.option(
        "--json-progress",
        is_flag=True,
        help=(
            "Print progress to stderr using json"
            " instead of using a progress bar."
        ),
    )
    def graph(
        _directory,
        index_path,
        start_query,
        goal_query,
        num_routes,
        algorithm,
        json_progress,
    ):
        """Generate a reference graph in DOT format from two queries.

        For all symbols that match START_QUERY, this command will find
        paths to symbols that match GOAL_QUERY, and generate a graph
        with these two groups as clusters, connected by intermediate
        nodes.

        This can be used to visualize how a symbol is referenced
        throughout a codebase.

        """
        if json_progress:

            num_symbols_visited = 0
            num_routes_found = 0
            last_symbol_print_time = 0.0

            def print_symbols_visited():
                nonlocal last_symbol_print_time

                json.dump(
                    {"visited": num_symbols_visited},
                    sys.stderr,
                )
                log("")
                last_symbol_print_time = time.time()

            def on_symbol_visited():
                nonlocal num_symbols_visited

                num_symbols_visited += 1
                if time.time() - last_symbol_print_time >= 1:
                    print_symbols_visited()

            def on_route_found():
                nonlocal num_routes_found
                num_routes_found += 1
                json.dump(
                    {"found": num_routes_found},
                    sys.stderr,
                )
                log("")

            def on_progress(num_done, num_total):
                json.dump(
                    {"done": num_done, "total": num_total},
                    sys.stderr,
                )
                log("")
                if num_done == num_total:
                    print_symbols_visited()

        else:
            progress_bar = make_progress_bar(unit="nodes")
            visit_progress_bar = make_progress_bar(
                desc="Nodes visited", unit="symbols"
            )
            found_routes_progress_bar = make_progress_bar(
                desc="Found", unit="routes"
            )

            on_symbol_visited = visit_progress_bar.update
            on_route_found = found_routes_progress_bar.update

            def on_progress(num_done, num_total):
                progress_bar.total = num_total
                progress_bar.update()

        graph = generate_graph(
            index_path,
            start_query,
            goal_query,
            num_routes=num_routes if num_routes else None,
            algo=algorithm,
            on_progress=on_progress,
            on_symbol_visited=on_symbol_visited,
            on_route_found=on_route_found,
        )
        print(graph)


if __name__ == "__main__":
    cli()
