# bdx #

An indexer and graph generator for binary build directories.

This tool can be used to quickly search where an ELF symbol matching some
criteria is defined in a directory and generate graphs for various queries.

Features:

- Parallel, incremental indexing using sharded Xapian database
- Indexes cross-references by analyzing ELF relocations
- Query the database with a simple query language and custom output formats
- Disassemble symbols matching a query
- Generate symbol reference graphs in DOT format

## Installation ##

With pip:

    pip install .

Or, for development:

    pip install -e .[dev]

For optional graph generation (this installs `pygraphviz`):

    pip install .[graphs]

[xapian][xapian] is required to be installed on the system.

To install shell completion for the `bdx` command provided, put into shell init
file:

    eval "$(_BDX_COMPLETE=bash_source bdx)" # or `zsh_source` on zsh

### Getting Xapian ###

You need Xapian Python bindings, you can get them:

1. By installing [**unofficial** Xapian bindings][xapian-bindings] Python
   package with:

        pip install xapian-bindings

2. By running the provided [install_xapian_bindings.sh](./install_xapian_bindings.sh) script
3. By manually downloading and installing them from [Xapian download page][xapian-downloads]

## Usage ##

### Indexing ###

To index a project that contains a `compile_commands.json` file:

    bdx index -c

Or you can specify the directory to index:

    bdx index -d ./build

Alternatively you can specify list of files to index (here with bash process substitution):

    bdx index  -f <(find . -name '*.o')

The indexer will only index files changed since last run.  With `--exclude`
option you can choose directories/glob patterns to ignore.

When indexing a large repository when a lot of files have changed, it's often
better to use `--delete` option, to completely rebuild the index.  Removing
outdated documents from the database is very slow.

The `index` command also accepts `-o`, `--opt` option which can be used to set
some indexing settings, e.g. to enable indexing relocations:

    bdx index -d ./build --opt index_relocations=True

Available options:

- `num_processes` - number of parallel indexing processes (default=same as # of
  CPUs).

- `demangle_names` - if True (the default), then symbol names are demangled and
  saved to the database.

- `index_relocations` - if True, all relocations will be applied and indexed.
  By default this is false.  Setting this to True will slow down indexing.

- `min_symbol_size` - (default 1) only index symbols with size equal to or
  greater than this.

- `use_dwarfdump` - if True (the default), use `dwarfdump` program, if it's
  available, to find the source file for a compiled file, if it can't be found
  in any other way.

- `save_filters` - if True (False by default), then exclusions provided with
  `--exclude` option are saved for future runs.

- `delete_saved_filters` - if True (False by default), then delete all previous
  `--exclude` exclusions saved with `save_filters` option.

### Disassembling ###

After a directory is indexed, you can disassemble symbols matching a search
query.

You can set the command to disassemble with the `-D`, `--disassembler` option,
which can contain `{}` placeholders for replacement.

```
$ bdx disass tree node defp source:./gcc/cp/parser* section:.text

/src/gcc-12/build/gcc/cp/parser.o:     file format elf64-x86-64


Disassembly of section .text:

000000000000a1d0 <defparse_location(tree_node*)>:
    a1d0:	48 8b 47 08          	mov    0x8(%rdi),%rax
    a1d4:	48 8b 10             	mov    (%rax),%rdx
    a1d7:	48 8b 40 08          	mov    0x8(%rax),%rax
    a1db:	8b 7a 04             	mov    0x4(%rdx),%edi
    a1de:	8b 50 04             	mov    0x4(%rax),%edx
    a1e1:	89 fe                	mov    %edi,%esi
    a1e3:	e9 00 00 00 00       	jmp    a1e8 <defparse_location(tree_node*)+0x18>
```

### Searching ###

`bdx search` and other commands accept a query string.  A simple query language
is recognized.

```
$ bdx search -n 5 tree
tree-eh.o: _ZL20outside_finally_tree8treempleP6gimple
hooks.o: _Z14hook_void_treeP9tree_node
tree-eh.o: _ZL22record_in_finally_tree8treempleP4gtry
langhooks.o: _Z20lhd_return_null_treeP9tree_node
langhooks.o: _Z23lhd_tree_dump_dump_treePvP9tree_node
```

The `-n` option sets the maximum number of symbols to search for.

The `-f` option can be used to set output format (`json`, `sexp` or Python string format spec):

```
$ bdx search -n 5 -f json tree
{"path": "/src/gcc-12/build/stage1-gcc/tree-eh.o", "name": "_ZL20outside_finally_tree8treempleP6gimple", "section": ".text", "address": 12255, "size": 104, "type": "FUNC", "relocations": ["", "_ZN10hash_tableI19finally_tree_hasherLb0E11xcallocatorE4findERKP17finally_tree_node"], "mtime": 1652372105820280262, "demangled": "outside_finally_tree(treemple, gimple*)"}
{"path": "/src/gcc-12/build/prev-gcc/hooks.o", "name": "_Z14hook_void_treeP9tree_node", "section": ".text", "address": 560, "size": 1, "type": "FUNC", "relocations": [], "mtime": 1652375092039025278, "demangled": "hook_void_tree(tree_node*)"}
{"path": "/src/gcc-12/build/gcc/tree-eh.o", "name": "_ZL22record_in_finally_tree8treempleP4gtry", "section": ".text", "address": 13440, "size": 415, "type": "FUNC", "relocations": ["", "_Z11fancy_abortPKciS0_", "_ZN10hash_tableI19finally_tree_hasherLb0E11xcallocatorE6expandEv", "prime_tab", "xmalloc"], "mtime": 1652377778150208461, "demangled": "record_in_finally_tree(treemple, gtry*)"}
{"path": "/src/gcc-12/build/stage1-gcc/langhooks.o", "name": "_Z20lhd_return_null_treeP9tree_node", "section": ".text", "address": 278, "size": 15, "type": "FUNC", "relocations": [], "mtime": 1652372076295950259, "demangled": "lhd_return_null_tree(tree_node*)"}
{"path": "/src/gcc-12/build/stage1-gcc/langhooks.o", "name": "_Z23lhd_tree_dump_dump_treePvP9tree_node", "section": ".text", "address": 1692, "size": 19, "type": "FUNC", "relocations": [], "mtime": 1652372076295950259, "demangled": "lhd_tree_dump_dump_tree(void*, tree_node*)"}
$ bdx search -n 5 -f '0x{address:0>10x}|{section:<10}|{type:8}|{demangled}' tree
0x0000002fdf|.text     |FUNC    |outside_finally_tree(treemple, gimple*)
0x0000000230|.text     |FUNC    |hook_void_tree(tree_node*)
0x0000003480|.text     |FUNC    |record_in_finally_tree(treemple, gtry*)
0x0000000116|.text     |FUNC    |lhd_return_null_tree(tree_node*)
0x000000069c|.text     |FUNC    |lhd_tree_dump_dump_tree(void*, tree_node*)
```

### Find definition ###

`bdx find-definition` command accepts a query string and attempts to find
source locations where the symbols matching the query are defined:

```
$ bdx find-definition -n 5 hash table
/src/gcc-12/gcc/hash-table.h:909: _ZN10hash_tableI13saving_hasherLb0E11xcallocatorE14find_with_hashERKPvj
/src/gcc-12/gcc/hash-table.h:676: _ZN10hash_tableI20action_record_hasherLb0E11xcallocatorED2Ev
/src/gcc-12/gcc/hash-table.h:676: _ZN10hash_tableI19external_ref_hasherLb0E11xcallocatorED2Ev
/src/gcc-12/gcc/hash-table.h:676: _ZN10hash_tableI15variable_hasherLb0E11xcallocatorED2Ev
/src/gcc-12/gcc/hash-table.h:676: _ZN10hash_tableI20action_record_hasherLb0E11xcallocatorED1Ev
```

#### Examples ####

1. Search for symbols having `foo` AND `bar` somewhere in their name:

        bdx search foo AND bar

    or:

        bdx search foo bar

2. Search for symbols having either `foo` or `bar` in their name:

        bdx search foo OR bar

3. Search for symbols named _exactly_ `foo`:

        bdx search fullname:foo

4. Search for symbols where [Elf ST_INFO type][elf-manpage] is `STT_FUNC` or `STT_OBJECT`:

        bdx search type:FUNC OR type:OBJECT

5. Search for symbols in binary files with specific architecture:

        bdx search arch:X86_64

6. Search for symbols `foo*` in binary files named `bar.o`:

        bdx search 'name:foo*' path:bar.o

7. Search for symbols in files compiled from source file named `file.c`:

        bdx search source:file.c

8. Search for symbols `foo` or `bar` that are not mangled (`_Z*` prefix):

        bdx search '(foo OR bar)' AND NOT name:_Z*

9. Search for symbols that reference/call `memset`:

        bdx search relocations:memset

10. Search for symbols that call `malloc`, but not `free`:

        bdx search relocations:malloc NOT relocations:free

11. Search for symbols with size in some range, where address is at least 0xfff0:

        bdx search foo size:100..200 address:0xfff0..

12. Search for symbols by relative path of the binary:

        bdx search 'path:./build/module/*'

13. Search for string literals:

        bdx search 'path:"/path/to/File With Spaces.o"'

14. Search for big symbols in some section:

        bdx search section:.rodata AND size:1000..


### Graph generation ###

Generate an SVG image showing at most 20 routes from symbol `main` in
`main.o` to all symbols in section `.text` in files matching wildcard
`Algorithms_*`:

    bdx graph 'main path:main.o' 'section:".text" AND path:Algorithms*' -n 20 | dot -Tsvg > graph.svg

Example graphs: ![ASTAR](./examples/astar.svg) ![BFS](./examples/bfs.svg) ![DFS](./examples/dfs.svg)

By default this generates paths by using the ASTAR algorithm, the `--algorithm
BFS` or `--algorithm DFS` options will use
breadth-first-search/depth-first-search algorithms which can generate different
graphs and can be slower/faster depending on the index and the queries
provided.

## License ##

```
Copyright (C) 2024 Michał Krzywkowski

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
<!-- Local Variables: -->
<!-- coding: utf-8 -->
<!-- fill-column: 79 -->
<!-- indent-tabs-mode: nil -->
<!-- End: -->

[xapian]: https://xapian.org/
[xapian-downloads]: https://xapian.org/download
[xapian-bindings]: https://pypi.org/project/xapian-bindings/
[elf-manpage]: https://manpages.ubuntu.com/manpages/oracular/en/man5/elf.5.html
