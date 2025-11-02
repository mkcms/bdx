import os
import shutil
from pathlib import Path
from shutil import rmtree
from subprocess import check_call

import pytest

from bdx.binary import Arch, Exclusion, SymbolType
from bdx.index import (
    MAX_TERM_SIZE,
    IndexingOptions,
    SymbolIndex,
    SymbolNameField,
    index_binary_directory,
)
from bdx.query_parser import QueryParser


def _compile_file(output_file: Path, source: str, flags: list[str], ext="c"):
    source_file = output_file.parent / f"{output_file.stem}.{ext}"
    source_file.write_text(source)
    check_call(["gcc", str(source_file), "-o", str(output_file), *flags])


X86_64 = Arch.X86_64  # pyright: ignore


def test_indexing(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path, index_path, IndexingOptions(index_relocations=True)
    )

    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = index.search("*:*")
        assert symbols.count == 22
        by_name = {x.name: x for x in symbols}

        top_level_symbol = by_name["top_level_symbol"]
        other_top_level_symbol = by_name["other_top_level_symbol"]
        bar = by_name["bar"]
        cxx_function = by_name["_Z12cxx_functionSt6vectorIiSaIiEE"]
        foo = by_name["foo"]
        c_function = by_name["c_function"]
        camel_case_symbol = by_name["CamelCaseSymbol"]
        cpp_camel_case_symbol = by_name["_Z18CppCamelCaseSymbolPKc"]
        main = by_name["main"]
        uses_c_function = by_name["uses_c_function"]
        foo_ = by_name["foo_"]
        foo__ = by_name["foo__"]
        uses_foo = by_name["uses_foo"]
        global_integer = by_name["_ZL14global_integer"]
        long_name = by_name["name_has_256_chars_" + "0" * 237]
        shared_object = by_name["shared_object"]
        completed = by_name["completed.0"]

        assert top_level_symbol.arch == X86_64
        assert top_level_symbol.path == fixture_path / "toplev.c.o"
        assert top_level_symbol.name == "top_level_symbol"
        assert top_level_symbol.demangled is None
        assert top_level_symbol.section == ".rodata"
        assert top_level_symbol.address == 0
        assert top_level_symbol.size == 64
        assert top_level_symbol.type == SymbolType.OBJECT
        assert top_level_symbol.relocations == []
        assert top_level_symbol.mtime > 0

        assert other_top_level_symbol.arch == X86_64
        assert other_top_level_symbol.path == fixture_path / "toplev.c.o"
        assert other_top_level_symbol.name == "other_top_level_symbol"
        assert other_top_level_symbol.demangled is None
        assert other_top_level_symbol.section == ".data.rel.ro.local"
        assert other_top_level_symbol.address == 0
        assert other_top_level_symbol.size == 8
        assert other_top_level_symbol.type == SymbolType.OBJECT
        assert other_top_level_symbol.relocations == ["top_level_symbol"]
        assert other_top_level_symbol.mtime > 0

        assert bar.arch == X86_64
        assert bar.path == fixture_path / "subdir" / "bar.cpp.o"
        assert bar.name == "bar"
        assert bar.section == ".bss"
        assert bar.type == SymbolType.OBJECT
        assert bar.relocations == []

        assert cxx_function.arch == X86_64
        assert cxx_function.path == fixture_path / "subdir" / "bar.cpp.o"
        assert cxx_function.name == "_Z12cxx_functionSt6vectorIiSaIiEE"
        assert (
            cxx_function.demangled
            == "cxx_function(std::vector<int, std::allocator<int> >)"
        )
        assert cxx_function.section == ".text"
        assert cxx_function.type == SymbolType.FUNC
        assert cxx_function.relocations == [
            "bar",
            "foo",
        ]

        assert foo.arch == X86_64
        assert foo.path == fixture_path / "subdir" / "foo.c.o"
        assert foo.name == "foo"
        assert foo.section == ".bss"
        assert foo.type == SymbolType.OBJECT
        assert foo.relocations == []

        assert c_function.arch == X86_64
        assert c_function.path == fixture_path / "subdir" / "foo.c.o"
        assert c_function.name == "c_function"
        assert c_function.section == ".text"
        assert c_function.type == SymbolType.FUNC
        assert c_function.relocations == [
            "foo",
        ]

        for i in range(5):
            symbol = by_name[f"a_name{i}"]
            assert symbol.arch == X86_64
            assert symbol.path == fixture_path / "subdir" / "foo.c.o"
            assert symbol.name == f"a_name{i}"
            assert symbol.section == ".bss"
            assert symbol.type == SymbolType.OBJECT
            assert symbol.relocations == []

        assert camel_case_symbol.arch == X86_64
        assert camel_case_symbol.path == fixture_path / "subdir" / "foo.c.o"
        assert camel_case_symbol.name == "CamelCaseSymbol"
        assert camel_case_symbol.section == ".text"
        assert camel_case_symbol.type == SymbolType.FUNC
        assert camel_case_symbol.relocations == []

        assert (
            cpp_camel_case_symbol.path == fixture_path / "subdir" / "bar.cpp.o"
        )
        assert cpp_camel_case_symbol.name == "_Z18CppCamelCaseSymbolPKc"
        assert cpp_camel_case_symbol.section == ".text"
        assert cpp_camel_case_symbol.type == SymbolType.FUNC
        assert cpp_camel_case_symbol.relocations == []

        assert main.path == fixture_path / "toplev.c.o"
        assert main.name == "main"
        assert main.section == ".text"
        assert main.type == SymbolType.FUNC
        assert main.relocations == ["uses_c_function"]

        assert uses_c_function.path == fixture_path / "subdir" / "bar.cpp.o"
        assert uses_c_function.name == "uses_c_function"
        assert uses_c_function.section == ".text"
        assert uses_c_function.type == SymbolType.FUNC
        assert uses_c_function.relocations == ["c_function"]

        assert foo_.path == fixture_path / "subdir" / "foo.c.o"
        assert foo_.section == ".bss"
        assert foo_.type == SymbolType.OBJECT
        assert foo_.size == 8

        assert foo__.path == fixture_path / "subdir" / "foo.c.o"
        assert foo__.section == ".bss"
        assert foo__.type == SymbolType.OBJECT
        assert foo__.size == 4

        assert uses_foo.path == fixture_path / "subdir" / "foo.c.o"
        assert uses_foo.section == ".text"
        assert uses_foo.type == SymbolType.FUNC
        assert uses_foo.size == 13

        assert global_integer.path == fixture_path / "subdir" / "bar.cpp.o"
        assert global_integer.section == ".bss"
        assert global_integer.type == SymbolType.OBJECT
        assert global_integer.size == 4

        assert long_name.path == fixture_path / "toplev.c.o"
        assert long_name.section == ".bss"
        assert long_name.type == SymbolType.OBJECT

        assert shared_object.path == fixture_path / "shared.c.so"
        assert shared_object.section == ".data"
        assert shared_object.type == SymbolType.OBJECT

        assert completed.path == fixture_path / "shared.c.so"


def test_reindexing(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    bin_path = tmp_path / "bin"
    file = bin_path / "file.c.o"
    bin_path.mkdir()

    shutil.copy(fixture_path / "toplev.c.o", file)
    index_binary_directory(bin_path, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = set(index.search("*:*"))
        by_name = {x.name: x for x in symbols}
        assert "top_level_symbol" in by_name
        assert "CamelCaseSymbol" not in by_name

    shutil.copy(fixture_path / "subdir" / "foo.c.o", file)
    index_binary_directory(bin_path, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = set(index.search("*:*"))
        by_name = {x.name: x for x in symbols}
        assert "top_level_symbol" not in by_name
        assert "CamelCaseSymbol" in by_name

    file.unlink()
    index_binary_directory(bin_path, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = set(index.search("*:*"))
        assert not symbols


def test_indexing_min_symbol_size(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    for msize in [0, 1, 64, 65]:
        try:
            rmtree(index_path)
        except FileNotFoundError:
            pass

        index_binary_directory(
            fixture_path, index_path, IndexingOptions(min_symbol_size=msize)
        )

        with SymbolIndex.open(index_path, readonly=True) as index:
            symbols = set(index.search("*:*"))
            by_name = {x.name: x for x in symbols}
            assert symbols

            for sym in symbols:
                # One entry (with an empty name) per file is when
                # no regular symbols were added
                if sym.name:
                    assert sym.size >= msize

            if msize <= 64:
                assert "top_level_symbol" in by_name
            else:
                assert "top_level_symbol" not in by_name


def test_indexing_without_relocations(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path, index_path, IndexingOptions(index_relocations=False)
    )

    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        assert symbols

        for symbol in symbols:
            assert not symbol.relocations


def test_indexing_adds_source_field_with_dwarfdump(fixture_path, tmp_path):
    """Check that ``source`` is set when using dwarfdump program."""
    if not shutil.which("dwarfdump"):
        pytest.skip(reason=("dwarfdump program not available"))

    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path, index_path, IndexingOptions(use_dwarfdump=True)
    )

    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("path:toplev.c.o"))
        assert symbols
        for symbol in symbols:
            assert symbol.source == Path("/src") / "toplev.c"

        symbols = list(index.search("path:foo.c.o"))
        assert symbols
        for symbol in symbols:
            assert symbol.source == Path("/src") / "subdir" / "foo.c"


def test_indexing_adds_source_field_with_compilation_database(
    fixture_path, tmp_path
):
    """Check that ``source`` is set when using compile_commands.json."""
    if not (fixture_path / "compile_commands.json").exists():
        pytest.skip(
            reason=(
                "compile_commands.json not generated, do: "
                f"`make -C {fixture_path} compile_commands.json`"
            )
        )

    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(use_dwarfdump=False),
        use_compilation_database=True,
    )

    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("path:toplev.c.o"))
        assert symbols
        for symbol in symbols:
            assert symbol.source == fixture_path / "toplev.c"

        symbols = list(index.search("path:foo.c.o"))
        assert symbols
        for symbol in symbols:
            assert symbol.source == fixture_path / "subdir" / "foo.c"


def test_indexing_exclusions(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(),
        exclusions=[Exclusion("**/*.cpp.o")],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        assert symbols

        for symbol in symbols:
            assert not symbol.path.name.endswith(".cpp.o")
    rmtree(index_path)

    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(),
        exclusions=[Exclusion("**/*.c.o"), Exclusion("**/*.c.so")],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        assert symbols

        for symbol in symbols:
            assert symbol.path.name.endswith(".cpp.o")
    rmtree(index_path)

    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(),
        exclusions=[Exclusion("**/toplev.*"), Exclusion("**/subdir/*.cpp.o")],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        assert symbols

        paths = set([x.path for x in symbols])

        assert fixture_path / "toplev.c.o" not in paths
        assert fixture_path / "subdir" / "bar.cpp.o" not in paths
    rmtree(index_path)


def test_indexing_persistent_exclusions(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(save_filters=True),
        exclusions=[Exclusion("**/*.cpp.o")],
    )
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(save_filters=True),
        exclusions=[Exclusion("**/*.c.o")],
    )
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(save_filters=False),
        exclusions=[
            Exclusion("Will not save this one"),
            Exclusion("And this one"),
        ],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        exclusions = index.exclusions()
        assert set(exclusions) == set(
            [Exclusion("**/*.cpp.o"), Exclusion("**/*.c.o")]
        )


def test_indexing_uses_persistent_exclusions(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(save_filters=True),
        exclusions=[Exclusion("**/*.cpp.o")],
    )
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(),
        exclusions=[],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        paths = [s.path for s in symbols]
        assert all([not p.name.endswith(".cpp.o") for p in paths])


def test_indexing_delete_saved_filters(fixture_path, tmp_path):
    index_path = tmp_path / "index"
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(save_filters=True),
        exclusions=[Exclusion("**/*.cpp.o")],
    )
    index_binary_directory(
        fixture_path,
        index_path,
        IndexingOptions(delete_saved_filters=True),
        exclusions=[],
    )
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = list(index.search("*:*"))
        paths = [s.path for s in symbols]
        assert any([p.name.endswith(".cpp.o") for p in paths])


def test_indexing_triggered_after_file_was_updated(tmp_path):
    dir = tmp_path / "build"
    dir.mkdir()

    file: Path = dir / "foo.o"
    index_path = tmp_path / "index"

    _compile_file(file, "void foo() {}", ["-c"])
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = {s.name: s for s in index.search("*:*")}
        assert "foo" in symbols

    _compile_file(file, "void bar() {}", ["-c"])
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = {s.name: s for s in index.search("*:*")}
        assert "foo" not in symbols
        assert "bar" in symbols

    st = file.stat()
    _compile_file(file, "void quux() {}", ["-c"])
    os.utime(file, ns=(st.st_atime_ns + 1, st.st_mtime_ns + 1))
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = {s.name: s for s in index.search("*:*")}
        assert "foo" not in symbols
        assert "bar" not in symbols
        assert "quux" in symbols


def test_indexing_not_triggered_if_mtime_not_changed(tmp_path):
    dir = tmp_path / "build"
    dir.mkdir()

    file: Path = dir / "foo.o"
    index_path = tmp_path / "index"

    _compile_file(file, "void foo() {}", ["-c"])
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = {s.name: s for s in index.search("*:*")}
        assert "foo" in symbols

    st = file.stat()
    _compile_file(file, "void quux() {}", ["-c"])
    os.utime(file, ns=(st.st_atime_ns, st.st_mtime_ns))
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        symbols = {s.name: s for s in index.search("*:*")}
        assert "foo" in symbols
        assert "quux" not in symbols


def test_indexing_very_long_path(tmp_path):
    index_path = tmp_path / "index"
    dir = tmp_path / "build"
    dir.mkdir()

    filename = "0" * (os.pathconf(tmp_path, "PC_NAME_MAX") - 2) + ".o"
    file: Path = dir / filename
    short_file: Path = dir / "short.o"

    assert (
        len(str(file)) + len(SymbolIndex.SCHEMA["path"].prefix) > MAX_TERM_SIZE
    )

    _compile_file(file, "void foo() {}", ["-c"])
    _compile_file(short_file, "void shortfile() {}", ["-c"])
    index_binary_directory(dir, index_path, IndexingOptions())
    with SymbolIndex.open(index_path, readonly=True) as index:
        all_files = sorted(index.all_files())
        assert all_files == [file, short_file]


def test_searching_by_wildcard(readonly_index):
    symbols = set(readonly_index.search("name:a_*"))
    assert symbols
    for sym in symbols:
        assert sym.name.startswith("a_")

    # Wildcard not provided
    assert not set(readonly_index.search("name:a_"))

    # Automatically search by name
    assert set(readonly_index.search("a_*")) == symbols

    # Automatically append a wildcard if a field is not specified
    assert set(readonly_index.search("a_")) == symbols


def test_searching_by_exact_name(fixture_path, readonly_index):
    all_symbols = list(readonly_index.search("name:foo"))

    symbols = list(readonly_index.search("fullname:foo"))
    assert len(symbols) == 1

    symbol = symbols[0]

    assert symbol.name == "foo"
    assert symbol.path == fixture_path / "subdir" / "foo.c.o"

    not_matching_exactly = list(
        sorted(set(all_symbols).difference(set(symbols)), key=lambda s: s.name)
    )
    assert len(not_matching_exactly) == 3

    assert not_matching_exactly[0].name == "foo_"
    assert not_matching_exactly[1].name == "foo__"
    assert not_matching_exactly[2].name == "uses_foo"


def test_searching_by_exact_name_2(fixture_path, readonly_index):
    symbols = list(
        readonly_index.search('fullname:"CppCamelCaseSymbol(char const*)"')
    )
    symbols2 = list(
        readonly_index.search("fullname:_Z18CppCamelCaseSymbolPKc")
    )

    assert symbols
    assert symbols == symbols2

    assert symbols[0].name == "_Z18CppCamelCaseSymbolPKc"


def test_searching_camel_case(readonly_index):
    symbols = set(readonly_index.search("camel"))
    assert symbols
    by_name = {x.name: x for x in symbols}

    assert "CamelCaseSymbol" in by_name
    ccs = by_name["CamelCaseSymbol"]
    assert ccs in readonly_index.search("case")
    assert ccs in readonly_index.search("cam ca sym")
    assert ccs in readonly_index.search("cam ca")
    assert ccs in readonly_index.search("cas sym")
    assert ccs in readonly_index.search("symbol")
    assert ccs in readonly_index.search("camelc*")
    assert ccs in readonly_index.search("Camel")
    assert ccs in readonly_index.search("CamelC*")
    assert ccs in readonly_index.search("CamelCase")
    assert ccs in readonly_index.search("camelcaseS*")

    assert "_Z18CppCamelCaseSymbolPKc" in by_name
    ccs = by_name["_Z18CppCamelCaseSymbolPKc"]
    assert ccs in readonly_index.search("case")
    assert ccs in readonly_index.search("cam ca sym")
    assert ccs in readonly_index.search("cam ca")
    assert ccs in readonly_index.search("cas sym")
    assert ccs in readonly_index.search("symbol")
    assert ccs in readonly_index.search("cppcamelc*")
    assert ccs in readonly_index.search("Camel")


def test_searching_by_address(readonly_index):
    symbols = readonly_index.search("address:0x10")
    assert symbols.count > 0
    for sym in symbols:
        assert sym.address == 16
    names = [x.name for x in symbols]
    assert "foo__" in names


def test_searching_by_size(readonly_index):
    symbols = readonly_index.search("size:8")
    for sym in symbols:
        assert sym.size == 8
    names = [x.name for x in symbols]
    assert "other_top_level_symbol" in names

    symbols = readonly_index.search("size:32..128")
    for sym in symbols:
        assert 32 <= sym.size <= 128

    names = [x.name for x in symbols]
    assert "top_level_symbol" in names

    symbols = readonly_index.search("size:0x20..0x80")
    for sym in symbols:
        assert 32 <= sym.size <= 128

    names = [x.name for x in symbols]
    assert "top_level_symbol" in names


def test_searching_by_type(readonly_index):
    symbols = readonly_index.search("type:FUNC")
    assert symbols.count > 0
    for sym in symbols:
        assert sym.type == SymbolType.FUNC
    names = [x.name for x in symbols]
    assert "main" in names

    symbols = readonly_index.search("type:OBJECT")
    assert symbols.count > 0
    for sym in symbols:
        assert sym.type == SymbolType.OBJECT
    names = [x.name for x in symbols]
    assert "bar" in names

    symbols = readonly_index.search("type:F*")
    assert symbols.count > 0
    for sym in symbols:
        assert sym.type in [SymbolType.FUNC, SymbolType.FILE]

    with pytest.raises(
        Exception, match="Invalid value for 'type' field.*INVALIDTYPE"
    ):
        readonly_index.search("type:INVALIDTYPE")


def test_searching_by_relative_path(fixture_path, readonly_index, chdir):
    with chdir(fixture_path):
        all_symbols = set(readonly_index.search("*:*"))

        # Ensure the path is normalized
        subdir_symbols = set(readonly_index.search("path:subdir///*"))
        assert subdir_symbols
        for sym in subdir_symbols:
            assert fixture_path / "subdir" in sym.path.parents
        for sym in all_symbols.difference(subdir_symbols):
            assert fixture_path / "subdir" not in sym.path.parents

    with chdir(fixture_path / "subdir"):
        subdir_symbols = set(readonly_index.search("path:./*"))
        assert subdir_symbols
        for sym in subdir_symbols:
            assert fixture_path / "subdir" in sym.path.parents
        for sym in all_symbols.difference(subdir_symbols):
            assert fixture_path / "subdir" not in sym.path.parents


def test_searching_by_absolute_path(fixture_path, readonly_index, chdir):
    with chdir(fixture_path):
        all_symbols = set(readonly_index.search("*:*"))
        # Ensure the path is normalized
        foo_symbols = set(
            readonly_index.search(f"path:///{fixture_path}///subdir//foo.c.o")
        )
        assert foo_symbols
        for sym in foo_symbols:
            assert sym.path == fixture_path / "subdir" / "foo.c.o"
        for sym in all_symbols.difference(foo_symbols):
            assert sym.path != fixture_path / "subdir" / "foo.c.o"


def test_searching_by_basename(fixture_path, readonly_index):
    all_symbols = set(readonly_index.search("*:*"))
    bar_symbols = set(readonly_index.search("path:bar.cpp.o"))
    assert bar_symbols
    for sym in bar_symbols:
        assert sym.path == fixture_path / "subdir" / "bar.cpp.o"
    for sym in all_symbols.difference(bar_symbols):
        assert sym.path != fixture_path / "subdir" / "bar.cpp.o"


def test_searching_long_name(fixture_path, readonly_index):
    name = "name_has_256_chars_" + "0" * 237
    res = readonly_index.search(name)

    assert res.count == 1
    symbol = list(res)[0]
    assert symbol.name == name
    assert symbol.path == fixture_path / "toplev.c.o"

    name = "name_has_256_chars_" + "0" * 236  # 1 char shorter
    res = readonly_index.search(name)
    assert res.count == 0

    name = "name_has_256_chars_" + "0" * 236 + "1"
    res = readonly_index.search(name)
    assert res.count == 0

    with pytest.raises(QueryParser.Error, match="'name'.*too long"):
        readonly_index.search(f"{name}*")

    preflen = len(readonly_index.SCHEMA["name"].prefix)
    res = readonly_index.search(f"name:{name[:MAX_TERM_SIZE-preflen]}*")
    assert res.count == 1

    with pytest.raises(QueryParser.Error, match="'name'.*too long"):
        readonly_index.search(f"name:{name[:MAX_TERM_SIZE-preflen+1]}*")


def test_searching_cxx(readonly_index):
    symbols = readonly_index.search("cxx func")
    by_name = {x.name: x for x in symbols}

    sym = by_name["_Z12cxx_functionSt6vectorIiSaIiEE"]

    assert sym in readonly_index.search("c fu vec")
    assert sym in readonly_index.search("12 c f v")
    assert sym in readonly_index.search("cxx fu")
    assert sym in readonly_index.search("vector")
    assert sym in readonly_index.search("func vec")


def test_tokenize_symbol():
    tokens = SymbolNameField.tokenize_value("foo")
    assert tokens == set(
        [
            "foo",
        ]
    )

    tokens = SymbolNameField.tokenize_value("foo_bar")
    assert tokens == set(
        [
            "bar",
            "foo",
        ]
    )

    tokens = SymbolNameField.tokenize_value("_foo123_bar37_")
    assert tokens == set(
        [
            "foo",
            "foo123",
            "123",
            "bar",
            "37",
            "bar37",
        ]
    )

    tokens = SymbolNameField.tokenize_value("__foo_bar__")
    assert tokens == set(
        [
            "bar",
            "foo",
        ]
    )

    tokens = SymbolNameField.tokenize_value("FooBarCamelCase")
    assert tokens == set(
        [
            "Bar",
            "Camel",
            "Case",
            "Foo",
            "FooBarCamelCase",
            "amel",
            "ar",
            "ase",
            "oo",
        ]
    )

    tokens = SymbolNameField.tokenize_value("LSDigitVALUE")
    assert tokens == set(
        [
            "Digit",
            "LSD",
            "LSDigitVALUE",
            "VALUE",
            "igit",
        ]
    )

    tokens = SymbolNameField.tokenize_value(
        "_Z37cxxFunctionReturningStdVectorOfStringB5cxx11v"
    )
    assert tokens == set(
        [
            "11",
            "37",
            "5",
            "Function",
            "Of",
            "Returning",
            "Std",
            "String",
            "Vector",
            "Z37",
            "cxx",
            "cxx11",
            "cxxFunctionReturningStdVectorOfStringB",
            "cxxFunctionReturningStdVectorOfStringB5",
            "ector",
            "eturning",
            "td",
            "tring",
            "unction",
        ]
    )

    tokens = SymbolNameField.tokenize_value(
        "_Z39cxxFunctionAcceptingBoostVectorOfStringN5boost9container6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEvvEE"
    )
    assert tokens == set(
        [
            "11",
            "1112",
            "39",
            "5",
            "6",
            "7",
            "9",
            "Accepting",
            "Boost",
            "EE",
            "EEE",
            "ES",
            "Evv",
            "Function",
            "INS",
            "Ic",
            "Of",
            "Sa",
            "St",
            "String",
            "Vector",
            "Z39",
            "basic",
            "boost",
            "boost9",
            "ccepting",
            "char",
            "container",
            "container6",
            "cxx",
            "cxx1112",
            "cxxFunctionAcceptingBoostVectorOfStringN",
            "cxxFunctionAcceptingBoostVectorOfStringN5",
            "ector",
            "oost",
            "string",
            "stringIcSt",
            "stringIcSt11",
            "traits",
            "traitsIcESaIcEEEvvEE",
            "tring",
            "unction",
            "vector",
            "vectorINSt",
            "vectorINSt7",
            "vv",
        ]
    )
