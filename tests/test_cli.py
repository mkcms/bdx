import json
import re
import subprocess
from pathlib import Path
from typing import Optional

import pytest
from click.testing import CliRunner, Result

from bdx.cli import cli


@pytest.fixture
def index_path(tmp_path):
    return tmp_path / "index"


def index_directory(
    runner: CliRunner, fixture_path: Path, index_path: Path
) -> Result:
    return runner.invoke(
        cli,
        [
            "index",
            "--index-path",
            str(index_path),
            "-d",
            str(fixture_path),
            "--opt",
            "index_relocations=True",
        ],
    )


def index_directory_compile_commands(
    runner: CliRunner, index_path: Path
) -> Result:
    return runner.invoke(cli, ["index", "--index-path", str(index_path), "-c"])


def search_directory(runner: CliRunner, index_path: Path, *args) -> Result:
    return runner.invoke(
        cli, ["search", "--index-path", str(index_path), *args]
    )


def test_cli_indexing(fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    searchresult = search_directory(
        runner, index_path, "--format", "{basename}: {section}: {name}", "*:*"
    )
    assert searchresult.exit_code == 0

    lines = searchresult.output.splitlines()

    assert "foo.c.o: .text: c_function" in lines
    assert "bar.cpp.o: .bss: bar" in lines


def test_cli_indexing_with_compile_commands(fixture_path, index_path, chdir):
    with chdir(fixture_path):
        if not Path("compile_commands.json").exists():
            pytest.skip(
                reason=(
                    "compile_commands.json not generated, do: "
                    f"`make -C {fixture_path} compile_commands.json`"
                )
            )

        runner = CliRunner()

        result = index_directory_compile_commands(runner, index_path)
        assert result.exit_code == 0

        searchresult = search_directory(
            runner,
            index_path,
            "-f",
            "{basename}: {section}: {name}: {source}",
            "*:*",
        )
        assert searchresult.exit_code == 0

        lines = searchresult.output.splitlines()

        assert (
            f"foo.c.o: .text: c_function: {fixture_path}/subdir/foo.c" in lines
        )
        assert f"bar.cpp.o: .bss: bar: {fixture_path}/subdir/bar.cpp" in lines


def test_cli_search_json_output(fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    searchresult = search_directory(
        runner,
        index_path,
        "-f",
        "json",
        "c",
        "funct",
    )
    assert searchresult.exit_code == 0

    results = [json.loads(l) for l in searchresult.output.splitlines()]
    results_by_name = {}
    for x in results:
        del x["mtime"]
        del x["source"]
        results_by_name[x["name"]] = x

    assert results_by_name["c_function"] == {
        "outdated": {
            "symbol": False,
            "binary": False,
        },
        "index": 1,
        "total": 2,
        "arch": "EM_X86_64",
        "path": str(fixture_path / "subdir" / "foo.c.o"),
        "name": "c_function",
        "demangled": None,
        "section": ".text",
        "address": 13,
        "size": 13,
        "type": "FUNC",
        "relocations": ["foo"],
    }
    assert results_by_name["_Z12cxx_functionSt6vectorIiSaIiEE"] == {
        "outdated": {
            "symbol": False,
            "binary": False,
        },
        "index": 0,
        "total": 2,
        "arch": "EM_X86_64",
        "path": str(fixture_path / "subdir" / "bar.cpp.o"),
        "name": "_Z12cxx_functionSt6vectorIiSaIiEE",
        "demangled": "cxx_function(std::vector<int, std::allocator<int> >)",
        "section": ".text",
        "address": 0,
        "size": 28,
        "type": "FUNC",
        "relocations": ["bar", "foo"],
    }


def test_cli_search_sexp_output(fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    searchresult = search_directory(
        runner, index_path, "-f", "sexp", "c", "funct"
    )
    assert searchresult.exit_code == 0

    results = searchresult.output.splitlines()
    results = [
        re.sub(f':path "{str(fixture_path)}', ':path "XXX', s) for s in results
    ]
    results = [re.sub(f":mtime [0-9]+", ":mtime XXX", s) for s in results]
    results = [re.sub(f":source .*? :", ":source XXX :", s) for s in results]

    assert (
        "(:outdated (:binary nil :symbol nil)"
        " :index 0"
        " :total 2"
        ' :arch "EM_X86_64"'
        ' :path "XXX/subdir/bar.cpp.o"'
        " :source XXX"
        ' :name "_Z12cxx_functionSt6vectorIiSaIiEE"'
        ' :demangled "cxx_function(std::vector<int, std::allocator<int> >)"'
        ' :section ".text"'
        " :address 0"
        " :size 28"
        ' :type "FUNC"'
        ' :relocations ("bar" "foo")'
        " :mtime XXX"
        ")"
    ) in results


def test_cli_disassemble(monkeypatch, fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    check_call_args: Optional[tuple] = None

    def mock_check_call(*args, **kwargs):
        nonlocal check_call_args

        check_call_args = (args, kwargs)

    with monkeypatch.context():
        monkeypatch.setattr(subprocess, "check_call", mock_check_call)

        result = runner.invoke(
            cli, ["disass", "--index-path", str(index_path), "fullname:main"]
        )

    assert result.exit_code == 0
    assert check_call_args is not None

    args, kwargs = check_call_args

    assert args[0].startswith("objdump")
    assert "--section '.text'" in args[0]

    output = subprocess.check_output(*args, **kwargs, text=True)
    assert re.search("push[ ]+%rbp", output)


def test_cli_find_definition(monkeypatch, fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    result = runner.invoke(
        cli,
        ["find-definition", "--index-path", str(index_path), "fullname:main"],
    )

    assert result.exit_code == 0

    assert result.stdout.strip() == f"/src/tests/fixture/toplev.c:7: main"


def test_cli_file_list(fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    filesresult = runner.invoke(cli, ["files", "--index-path", index_path])

    assert filesresult.exit_code == 0

    assert set(filesresult.output.splitlines()) == set(
        [
            str(fixture_path / "subdir" / "bar.cpp.o"),
            str(fixture_path / "subdir" / "foo.c.o"),
            str(fixture_path / "toplev.c.o"),
        ]
    )


def test_cli_complete_query(chdir, fixture_path, index_path):
    runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "path:"]
    )
    assert completionsresult.exit_code == 0
    assert set(
        [
            "path:bar.cpp.o",
            "path:foo.c.o",
            "path:toplev.c.o",
            "path:" + str(fixture_path / "subdir" / "bar.cpp.o"),
            "path:" + str(fixture_path / "subdir" / "foo.c.o"),
            "path:" + str(fixture_path / "toplev.c.o"),
            "path:tests/",
            "path:tests/*",
        ]
    ).issubset(set(completionsresult.output.splitlines()))

    with chdir(fixture_path):
        completionsresult = runner.invoke(
            cli, ["complete-query", "--index-path", index_path, "path:./"]
        )
        assert completionsresult.exit_code == 0
        assert set(completionsresult.output.splitlines()) == set(
            [
                "path:./subdir/",
                "path:./subdir/*",
                "path:./toplev.c",
                "path:./toplev.c.o",
            ]
        )

    with chdir(fixture_path / "subdir"):
        completionsresult = runner.invoke(
            cli, ["complete-query", "--index-path", index_path, "path:./../"]
        )
        assert completionsresult.exit_code == 0
        assert set(completionsresult.output.splitlines()) == set(
            [
                "path:./../subdir/",
                "path:./../subdir/*",
                "path:./../toplev.c",
                "path:./../toplev.c.o",
            ]
        )

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "name:"]
    )
    assert "name:uses_c_function" in completionsresult.output
    assert "name:bar" in completionsresult.output

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "path:/* AN"]
    )
    assert "path:/* AND " in completionsresult.output

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "path:/* "]
    )
    assert "path:/* AND" in completionsresult.output
    assert "path:/* OR" in completionsresult.output
    assert "path:/* demangled:" in completionsresult.output

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "demangl"]
    )
    assert set(completionsresult.output.splitlines()) == set(["demangled:"])

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "demangled: (O"]
    )
    assert set(completionsresult.output.splitlines()) == set(
        ["demangled: (OR "]
    )

    completionsresult = runner.invoke(
        cli,
        ["complete-query", "--index-path", index_path, 'demangled:"CppCam'],
    )
    assert set(completionsresult.output.splitlines()) == set(
        ['demangled:"CppCamelCaseSymbol(char const*)"']
    )

    completionsresult = runner.invoke(
        cli, ["complete-query", "--index-path", index_path, "demangled:CppCam"]
    )
    assert set(completionsresult.output.splitlines()) == set(
        ['demangled:"CppCamelCaseSymbol(char const*)"']
    )


def test_cli_graph(fixture_path, index_path):
    try:
        import bdx.graph
    except ImportError:
        pytest.skip(reason="Graphs not available, package not installed")

    try:
        runner = CliRunner(mix_stderr=False)  # type: ignore
    except:
        runner = CliRunner()
    result = index_directory(runner, fixture_path, index_path)
    assert result.exit_code == 0

    graphresult = runner.invoke(
        cli,
        [
            "graph",
            "--index-path",
            index_path,
            "main",
            "c_function",
            "--json-progress",
        ],
    )

    assert graphresult.exit_code == 0
    stderr = graphresult.stderr.splitlines()

    assert "main -- uses_c_function" in graphresult.output
    assert "uses_c_function -- c_function" in graphresult.output

    assert '{"done": 1, "total": 1}' in stderr
    assert '{"found": 1}' in stderr
    assert '{"visited": 2}' in stderr
