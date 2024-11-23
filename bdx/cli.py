from __future__ import annotations

import json
import os
from dataclasses import asdict
from functools import wraps
from pathlib import Path
from sys import exit, stdout
from typing import Optional

import click
from click.shell_completion import CompletionItem
from click.types import BoolParamType, IntRange
from tqdm import tqdm

import bdx
from bdx import debug, error, info, log
from bdx.binary import BinaryDirectory, Symbol, find_compilation_database
# fmt: off
from bdx.graph import GraphAlgorithm
from bdx.index import (IndexingOptions, SymbolIndex, index_binary_directory,
                       search_index)
from bdx.query_parser import QueryParser

# fmt: on


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
                raise click.BadParameter(msg)

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
        "index_relocations": BoolParamType(),
        "min_symbol_size": IntRange(min=0),
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
def index(directory, index_path, opt, use_compilation_database):
    """Index the specified directory."""
    options = IndexingOptions(**dict(opt))

    try:
        stats = index_binary_directory(
            directory,
            index_path,
            options=options,
            use_compilation_database=use_compilation_database,
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


@cli.command()
@_common_options(index_must_exist=True)
@click.argument(
    "query",
    nargs=-1,
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
    help="Output format",
    nargs=1,
    default=None,
)
def search(_directory, index_path, query, num, format):
    """Search binary directory for symbols."""

    def callback(symbol: Symbol):
        def valueconv(v):
            try:
                json.dumps(v)
                return v
            except Exception:
                return str(v)

        data = {
            k: valueconv(v)
            for k, v in {
                "basename": symbol.path.name,
                **asdict(symbol),
            }.items()
        }

        if format is None:
            fmt = "{basename}: {name}"
        else:
            fmt = format

        if fmt == "json":
            del data["basename"]
            json.dump(data, stdout)
            print()
        else:
            try:
                print(fmt.format(**data))
            except (KeyError, ValueError, TypeError):
                error(
                    f"Invalid format: '{fmt}'\n"
                    f"Available keys: {list(data.keys())}"
                )
                exit(1)

    try:
        search_index(
            index_path=index_path,
            query=" ".join(query),
            limit=num,
            consumer=callback,
        )
    except QueryParser.Error as e:
        error(f"Invalid query: {str(e)}")
        exit(1)


@cli.command()
@_common_options(index_must_exist=True)
def files(_directory, index_path):
    """List all indexed files in a binary directory."""
    with SymbolIndex.open(index_path, readonly=True) as index:
        for path in index.all_files():
            print(path)


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
    "from_query",
    nargs=1,
)
@click.argument(
    "to_query",
    nargs=1,
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
    default="BFS",
    help="The algorithm to choose",
)
@click.option(
    "-d",
    "--demangle-names/--no-demangle-names",
    default=True,
    help="Use c++filt to demangle C++ names and use them as node labels.",
)
def graph(
    _directory,
    index_path,
    from_query,
    to_query,
    num_routes,
    algorithm,
    demangle_names,
):
    """Generate a reference graph in DOT format from two queries.

    For all symbols that match TO_QUERY, this command will find all
    direct and indirect references that match FROM_QUERY, and
    generate a graph with these two groups as clusters, connected by
    intermediate nodes.

    This can be used to visualize how a symbol is referenced
    throughout a codebase.

    """
    from bdx.graph import generate_graph

    visit_progress_bar = tqdm(desc="Nodes visited", unit="symbols")
    found_routes_progress_bar = tqdm(desc="Found", unit="routes")

    graph = generate_graph(
        index_path,
        from_query,
        to_query,
        num_routes=num_routes if num_routes else None,
        algo=algorithm,
        demangle_names=demangle_names,
        on_symbol_visited=visit_progress_bar.update,
        on_route_found=found_routes_progress_bar.update,
    )
    print(graph)


if __name__ == "__main__":
    cli()
