import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from bdx.index import (
    IndexingOptions,
    SymbolIndex,
    index_binary_directory,
)

FIXTURE_PATH = Path(__file__).parent / "fixture"


@pytest.fixture
def chdir():
    @contextmanager
    def changer(dir):
        old = os.getcwd()
        try:
            os.chdir(dir)
            yield
        finally:
            os.chdir(old)

    yield changer


@pytest.fixture(scope="session")
def empty_index(tmp_path_factory):
    index_path = tmp_path_factory.mktemp(f"index{uuid4()}")
    empty_path = tmp_path_factory.mktemp(f"dir")
    index_binary_directory(
        empty_path,
        index_path,
        IndexingOptions(),
    )

    with SymbolIndex.open(index_path, readonly=True) as index:
        yield index


@pytest.fixture(scope="session")
def readonly_index(tmp_path_factory):
    index_path = tmp_path_factory.mktemp(f"index{uuid4()}")
    index_binary_directory(
        FIXTURE_PATH,
        index_path,
        IndexingOptions(
            index_relocations=True,
        ),
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        yield index


@pytest.fixture(scope="session")
def fixture_path():
    return FIXTURE_PATH


@pytest.fixture(autouse=True)
def run_around_tests():
    # Simplify debugging by indexing in this process only for tests
    os.environ["_BDX_NO_MULTIPROCESSING"] = "1"
    os.environ["BDX_DISABLE_PROGRESS_BAR"] = "1"
