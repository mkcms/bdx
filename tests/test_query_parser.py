import json
from enum import Enum
from pathlib import Path

import pytest
import xapian
from pytest import fixture

from bdx.index import (
    MAX_TERM_SIZE,
    DatabaseField,
    EnumField,
    IntegerField,
    PathField,
    Schema,
)
from bdx.query_parser import QueryParser

AND = xapian.Query.OP_AND
OR = xapian.Query.OP_OR
WILDCARD = xapian.Query.OP_WILDCARD
VALUE_RANGE = xapian.Query.OP_VALUE_RANGE
VALUE_GE = xapian.Query.OP_VALUE_GE
VALUE_LE = xapian.Query.OP_VALUE_LE
AND_NOT = xapian.Query.OP_AND_NOT
MATCH_ALL = (xapian.Query.MatchAll.get_type(),)  # pyright: ignore
EMPTY_MATCH = (xapian.Query().get_type(),)
LEAF_TERM = 100


@fixture
def query_parser():
    schema = Schema([DatabaseField("name", "XNAME", key="name")])
    yield QueryParser(schema)


def query_to_tuple(query: xapian.Query):
    type = query.get_type()
    num_subqueries = query.get_num_subqueries()
    subqueries = [query.get_subquery(i) for i in range(num_subqueries)]
    subqueries = [query_to_tuple(subq) for subq in subqueries]

    terms = (
        [x.decode() for x in query]  # pyright: ignore
        if type == LEAF_TERM or type == WILDCARD
        else []
    )

    return (type, *subqueries, *terms)


def query_to_str(query: xapian.Query):
    return str(query)


def test_empty(query_parser):
    assert query_to_tuple(query_parser.parse_query("")) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query("  ")) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query("  \n   ")) == EMPTY_MATCH


def test_matchall(query_parser):
    assert query_to_tuple(query_parser.parse_query("  *:*  ")) == MATCH_ALL


def test_not(query_parser):
    assert query_to_tuple(query_parser.parse_query("NOT foo")) == (
        AND_NOT,
        MATCH_ALL,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
    )
    assert query_to_tuple(query_parser.parse_query("!foo")) == (
        AND_NOT,
        MATCH_ALL,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
    )
    assert query_to_tuple(query_parser.parse_query("NOT foo bar")) == (
        AND,
        (
            AND_NOT,
            MATCH_ALL,
            (
                LEAF_TERM,
                "XNAMEfoo",
            ),
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("NOT")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("!NOT")


def test_single_term(query_parser):
    assert query_to_tuple(query_parser.parse_query("foo")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )
    assert query_to_tuple(query_parser.parse_query("  foo  ")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )


def test_multiple_terms(query_parser):
    assert query_to_tuple(query_parser.parse_query("foo bar")) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )
    assert query_to_tuple(query_parser.parse_query("foo bar baz")) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
        (
            LEAF_TERM,
            "XNAMEbaz",
        ),
    )


def test_string(query_parser):
    assert query_to_tuple(query_parser.parse_query(' "foo baz"')) == (
        LEAF_TERM,
        "XNAMEfoo baz",
    )


def test_unterminated_string(query_parser):
    with pytest.raises(QueryParser.Error, match="[Uu]nterminated"):
        query_parser.parse_query('test "string')


def test_string_escaped(query_parser):
    assert query_to_tuple(query_parser.parse_query(' "foo \\"baz\\""')) == (
        LEAF_TERM,
        'XNAMEfoo "baz"',
    )

    assert query_to_tuple(query_parser.parse_query(json.dumps("test"))) == (
        LEAF_TERM,
        "XNAMEtest",
    )

    assert query_to_tuple(
        query_parser.parse_query(json.dumps(json.dumps("test")))
    ) == (
        LEAF_TERM,
        f'XNAME{json.dumps("test")}',
    )

    assert query_to_tuple(
        query_parser.parse_query(json.dumps(json.dumps(json.dumps("test"))))
    ) == (
        LEAF_TERM,
        f'XNAME{json.dumps(json.dumps("test"))}',
    )


def test_field_with_value(query_parser):
    assert query_to_tuple(query_parser.parse_query("name:bar")) == (
        LEAF_TERM,
        "XNAMEbar",
    )
    assert query_to_tuple(query_parser.parse_query("name: FOO")) == (
        LEAF_TERM,
        "XNAMEFOO",
    )


def test_field_with_string_value(query_parser):
    assert query_to_tuple(query_parser.parse_query('name:"foo bar"')) == (
        LEAF_TERM,
        "XNAMEfoo bar",
    )


def test_wildcard(query_parser):
    assert (
        query_to_str(query_parser.parse_query("fo*"))
        == "Query(WILDCARD SYNONYM XNAMEfo)"
    )
    assert (
        query_to_str(query_parser.parse_query("name:fo*"))
        == "Query(WILDCARD SYNONYM XNAMEfo)"
    )
    assert (
        query_to_str(query_parser.parse_query("name:foo.b*"))
        == "Query(WILDCARD SYNONYM XNAMEfoo.b)"
    )


def test_auto_wildcard(query_parser):
    query_parser.auto_wildcard = True
    assert (
        query_to_str(query_parser.parse_query("fo"))
        == "Query(WILDCARD SYNONYM XNAMEfo)"
    )
    assert (
        query_to_str(query_parser.parse_query("name:fo")) == "Query(XNAMEfo)"
    )


def test_match_all(query_parser):
    assert query_to_tuple(query_parser.parse_query("*:*")) == MATCH_ALL
    assert query_to_tuple(query_parser.parse_query("NOT *:*")) == (
        AND_NOT,
        MATCH_ALL,
        MATCH_ALL,
    )


def test_intrange(query_parser):
    slot = 99928
    query_parser.schema = Schema(
        [
            IntegerField("value", "XV", slot=slot, key="value"),
        ]
    )
    query_parser.default_fields = ["value"]

    assert xapian.sortable_serialise(123) == b"\xbb\xb0"
    assert xapian.sortable_serialise(456) == b"\xc7\x20"
    assert xapian.sortable_serialise(987) == b"\xcb\xb6"
    assert (
        query_to_str(query_parser.parse_query("123..456"))
        == "Query(VALUE_RANGE 99928 \\xbb\\xb0 \\xc7 )"
    )
    assert (
        query_to_str(query_parser.parse_query("..987"))
        == "Query(VALUE_LE 99928 ˶)"
    )
    assert (
        query_to_str(query_parser.parse_query("369.."))
        == "Query(VALUE_GE 99928 \\xc5\\xc4)"
    )
    assert (
        query_to_str(query_parser.parse_query("369"))
        == "Query(VALUE_RANGE 99928 \\xc5\\xc4 \\xc5\\xc4)"
    )

    query_parser.schema = Schema(
        [
            IntegerField("value", "XV1", slot=slot, key="value"),
            IntegerField(
                "other_value", "XV2", slot=slot + 1, key="other_value"
            ),
        ]
    )

    assert (
        query_to_str(query_parser.parse_query("value:..12346"))
        == "Query(VALUE_LE 99928 \\xda\\x07@)"
    )
    assert (
        query_to_str(query_parser.parse_query("value:99182"))
        == "Query(VALUE_RANGE 99928 \\xe0&\\x0d\\xb8 \\xe0&\\x0d\\xb8)"
    )

    assert (
        query_to_str(
            query_parser.parse_query("value:..12346 AND other_value:10..")
        )
        == "Query((VALUE_LE 99928 \\xda\\x07@ AND VALUE_GE 99929 \\xad))"
    )

    with pytest.raises(QueryParser.Error, match="Invalid integer range.*-1"):
        query_parser.parse_query("value:-1")
    with pytest.raises(QueryParser.Error, match="Invalid integer range.*1a"):
        query_parser.parse_query("value:1a")
    with pytest.raises(QueryParser.Error, match="Invalid integer range.*1_2"):
        query_parser.parse_query("value:1_2")
    with pytest.raises(QueryParser.Error, match="Invalid integer range.*[.]"):
        query_parser.parse_query("value:.")


def test_hex_intrange(query_parser):
    slot = 99928
    query_parser.schema = Schema(
        [
            IntegerField("value", "XV", slot=slot, key="value"),
        ]
    )
    query_parser.default_fields = ["value"]

    assert xapian.sortable_serialise(0x80) == b"\xc0"
    assert xapian.sortable_serialise(0x100) == b"\xc4"

    assert (
        query_to_str(query_parser.parse_query("value:0x80"))
        == "Query(VALUE_RANGE 99928 \\xc0 \\xc0)"
    )

    assert (
        query_to_str(query_parser.parse_query("value:0x80..0x100"))
        == "Query(VALUE_RANGE 99928 \\xc0 \\xc4)"
    )
    assert (
        query_to_str(query_parser.parse_query("value:128..0x100"))
        == "Query(VALUE_RANGE 99928 \\xc0 \\xc4)"
    )
    assert (
        query_to_str(query_parser.parse_query("value:0x80..256"))
        == "Query(VALUE_RANGE 99928 \\xc0 \\xc4)"
    )

    assert (
        query_to_str(query_parser.parse_query("value:..0x100"))
        == "Query(VALUE_LE 99928 \\xc4)"
    )


def test_path_field(query_parser):
    query_parser.schema = Schema(
        [
            DatabaseField("name", "XNAME", key="name"),
            PathField("path", "XPATH", key="path"),
        ]
    )

    assert query_to_tuple(query_parser.parse_query('path:"/FOO"')) == (
        LEAF_TERM,
        "XPATH/FOO",
    )

    query_parser.default_fields = ["name", "path"]
    assert query_to_tuple(query_parser.parse_query("FOO")) == (
        OR,
        (LEAF_TERM, "XNAMEFOO"),
        (LEAF_TERM, "XPATHFOO"),
        (LEAF_TERM, f"XPATH{(Path() / 'FOO').absolute().resolve()}"),
    )


def test_enumeration_field(query_parser):
    class Enumeration(Enum):
        FOO = "FOO"
        FOO_2 = "FOO_2"
        BAR = "BAR"

    query_parser.schema = Schema(
        [
            EnumField("value", "XV", key="value", enum=Enumeration),
        ]
    )

    assert query_to_tuple(query_parser.parse_query("value:FOO")) == (
        LEAF_TERM,
        "XVFOO",
    )

    assert query_to_tuple(query_parser.parse_query("value:BAR")) == (
        LEAF_TERM,
        "XVBAR",
    )

    with pytest.raises(
        QueryParser.Error, match="Invalid value for 'value' field.*UNKNOWN"
    ):
        query_parser.parse_query("value:UNKNOWN")

    assert (
        query_to_str(query_parser.parse_query("value:F*"))
        == "Query(WILDCARD SYNONYM XVF)"
    )

    assert (
        query_to_str(query_parser.parse_query("value:B*"))
        == "Query(WILDCARD SYNONYM XVB)"
    )

    with pytest.raises(
        QueryParser.Error, match="Invalid prefix for 'value' field.*ZZZ"
    ):
        query_parser.parse_query("value:ZZZ*")


def test_single_term_no_default_fields(query_parser):
    query_parser.default_fields = []
    assert query_to_tuple(query_parser.parse_query("foo")) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query('"foo bar"')) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query("name:foo")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )


def test_field_with_no_value(query_parser):
    query_parser.ignore_missing_field_values = False
    with pytest.raises(QueryParser.Error, match=r"\bname\b.*at position 5"):
        query_parser.parse_query("name:")

    query_parser.schema = Schema(
        [
            DatabaseField("name", "XNAME", key="name"),
            DatabaseField("path", "XPATH", key="path"),
        ]
    )
    query_parser.ignore_missing_field_values = True
    assert (
        query_to_tuple(query_parser.parse_query("name: path:baz"))
        == EMPTY_MATCH
    )
    assert query_to_tuple(query_parser.parse_query("name: OR path:baz")) == (
        LEAF_TERM,
        "XPATHbaz",
    )


def test_unknown_field(query_parser):
    with pytest.raises(QueryParser.Error, match="Unknown field"):
        query_to_tuple(query_parser.parse_query("unknown:text"))

    with pytest.raises(QueryParser.Error, match="Unknown field"):
        query_to_tuple(
            query_parser.parse_query("name:foo unknown:text name:bar")
        )


def test_multiple_default_fields(query_parser):
    query_parser.schema = Schema(
        [
            DatabaseField("name", "XNAME", key="name"),
            DatabaseField("full_name", "XFULLNAME", key="full_name"),
            DatabaseField("something", "XSOMETHING", key="something"),
        ]
    )
    query_parser.default_fields = ["name", "full_name"]
    assert query_to_tuple(query_parser.parse_query("foo")) == (
        OR,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XFULLNAMEfoo",
        ),
    )
    assert query_to_tuple(query_parser.parse_query('"foo bar"')) == (
        OR,
        (
            LEAF_TERM,
            "XNAMEfoo bar",
        ),
        (
            LEAF_TERM,
            "XFULLNAMEfoo bar",
        ),
    )


def test_weird_tokens(query_parser):
    assert query_to_tuple(query_parser.parse_query("  /~?# foo ?$@#  ")) == (
        AND,
        (
            LEAF_TERM,
            "XNAME/~?#",
        ),
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAME?$@#",
        ),
    )
    assert query_to_tuple(query_parser.parse_query("  !/~?# foo ?$@#  ")) == (
        AND,
        (AND_NOT, MATCH_ALL, (LEAF_TERM, "XNAME/~?#")),
        (LEAF_TERM, "XNAMEfoo"),
        (LEAF_TERM, "XNAME?$@#"),
    )
    assert query_to_tuple(query_parser.parse_query("  #name://foo//  ")) == (
        LEAF_TERM,
        "XNAME#name://foo//",
    )
    assert query_to_tuple(
        query_parser.parse_query("  #name://foo//bar  ")
    ) == (LEAF_TERM, "XNAME#name://foo//bar")


def test_or(query_parser):
    assert query_to_tuple(query_parser.parse_query("foo OR bar")) == (
        OR,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )


def test_and(query_parser):
    assert query_to_tuple(query_parser.parse_query("foo AND bar")) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )


def test_operand_missing(query_parser):
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo OR")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("OR foo")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo OR OR")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo OR AND")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo AND")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("AND foo")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo AND AND")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("foo AND OR")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("NOT")
    with pytest.raises(QueryParser.Error):
        query_parser.parse_query("NOT NOT")


def test_parens(query_parser):
    assert query_to_tuple(query_parser.parse_query("()")) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query("(())")) == EMPTY_MATCH
    assert query_to_tuple(query_parser.parse_query("(foo)")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )
    assert query_to_tuple(query_parser.parse_query("((foo))")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )
    assert query_to_tuple(query_parser.parse_query("((foo) bar)")) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )
    assert query_to_tuple(query_parser.parse_query("foo ()")) == (
        LEAF_TERM,
        "XNAMEfoo",
    )
    assert query_to_tuple(query_parser.parse_query("foo () bar")) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            LEAF_TERM,
            "XNAMEbar",
        ),
    )

    assert query_to_tuple(query_parser.parse_query("foo AND bar OR baz")) == (
        OR,
        (
            AND,
            (
                LEAF_TERM,
                "XNAMEfoo",
            ),
            (
                LEAF_TERM,
                "XNAMEbar",
            ),
        ),
        (
            LEAF_TERM,
            "XNAMEbaz",
        ),
    )

    assert query_to_tuple(
        query_parser.parse_query("foo AND (bar OR baz)")
    ) == (
        AND,
        (
            LEAF_TERM,
            "XNAMEfoo",
        ),
        (
            OR,
            (
                LEAF_TERM,
                "XNAMEbar",
            ),
            (
                LEAF_TERM,
                "XNAMEbaz",
            ),
        ),
    )


def test_missing_closing_paren(query_parser):
    with pytest.raises(
        QueryParser.Error, match=r'closing "[)]".*at position 1.*at position 5'
    ):
        assert query_parser.parse_query(" (foo")


def test_complete_keywords_and_known_fields(empty_index, query_parser):
    assert set(query_parser.complete_query(empty_index, "")) == set(
        [
            "AND",
            "OR",
            "NOT",
            *[field + ":" for field in empty_index.schema],
        ]
    )

    assert set(query_parser.complete_query(empty_index, "A")) == set(
        [
            "AND",
        ]
    )

    assert set(query_parser.complete_query(empty_index, "AN")) == set(
        [
            "AND",
        ]
    )

    assert set(query_parser.complete_query(empty_index, "ANN")) == set([])

    assert set(
        query_parser.complete_query(empty_index, "prefix string")
    ) == set([])

    assert set(
        query_parser.complete_query(empty_index, "prefix string ")
    ) == set(
        [
            "prefix string AND ",
            "prefix string OR ",
            "prefix string NOT ",
            *[f"prefix string {field}:" for field in empty_index.schema],
        ]
    )

    assert set(
        query_parser.complete_query(empty_index, "prefix string A")
    ) == set(["prefix string AND "])

    assert set(
        query_parser.complete_query(empty_index, "prefix string O")
    ) == set(["prefix string OR "])

    assert set(
        query_parser.complete_query(
            empty_index, '"__tsan::InitializeInterceptors()" AN'
        )
    ) == set(['"__tsan::InitializeInterceptors()" AND '])


def test_complete_name(readonly_index, query_parser):
    assert set(query_parser.complete_query(readonly_index, "name:Cam")) == set(
        [
            "name:CamelCaseSymbol",
        ]
    )


def test_complete_all_terms(readonly_index):
    query_parser = readonly_index.make_query_parser()

    completions = set(query_parser.complete_query(readonly_index, "name:"))
    terms = set(readonly_index.iter_prefix("name", ""))
    assert completions == set([f"name:{term}" for term in terms])

    completions = set(
        query_parser.complete_query(readonly_index, 'demangled:"')
    )
    terms = set(readonly_index.iter_prefix("demangled", ""))
    assert completions == set([f'demangled:"{term}"' for term in terms])

    completions = set(query_parser.complete_query(readonly_index, ""))
    terms = set(readonly_index.iter_prefix("name", ""))
    terms.update(set(readonly_index.iter_prefix("fullname", "")))
    assert completions.intersection(terms)


def test_complete_all_quoted_terms(readonly_index):
    query_parser = readonly_index.make_query_parser()
    query_parser.default_fields.append("demangled")

    completions = set(query_parser.complete_query(readonly_index, 'prefix "'))
    terms = set(readonly_index.iter_prefix("name", ""))
    terms.update(set(readonly_index.iter_prefix("demangled", "")))
    terms.update(set(readonly_index.iter_prefix("fullname", "")))

    completions = set(x for x in completions if "name_has_256_chars" not in x)
    terms = set(x for x in terms if "name_has_256_chars" not in x)

    terms_with_prefix = set(f'prefix "{term}"' for term in terms)

    assert completions == terms_with_prefix


def test_complete_all_quoted_terms_with_prefix(readonly_index):
    query_parser = readonly_index.make_query_parser()

    completions = set(query_parser.complete_query(readonly_index, 'prefix "_'))
    terms = set(readonly_index.iter_prefix("name", "_"))
    terms.update(set(readonly_index.iter_prefix("demangled", "_")))
    terms.update(set(readonly_index.iter_prefix("fullname", "_")))
    assert completions == set(f'prefix "{term}"' for term in terms)


def test_complete_demangled_name(readonly_index):
    query_parser = readonly_index.make_query_parser()

    assert set(
        query_parser.complete_query(readonly_index, 'demangled:"Cpp')
    ) == set(
        [
            'demangled:"CppCamelCaseSymbol(char const*)"',
        ]
    )

    assert set(
        query_parser.complete_query(readonly_index, "demangled:Cpp")
    ) == set(
        [
            'demangled:"CppCamelCaseSymbol(char const*)"',
        ]
    )

    assert set(
        query_parser.complete_query(readonly_index, "demangled:global_")
    ) == set(
        [
            "demangled:global_integer",
        ]
    )

    assert set(
        query_parser.complete_query(readonly_index, 'demangled:"global_')
    ) == set(
        [
            'demangled:"global_integer"',
        ]
    )

    assert set(
        query_parser.complete_query(
            readonly_index, 'demangled:"global_integer" AND demangled:"global'
        )
    ) == set(
        [
            'demangled:"global_integer" AND demangled:"global"',
            'demangled:"global_integer" AND demangled:"global_integer"',
        ]
    )


def test_complete_path(chdir, fixture_path, readonly_index):
    query_parser = readonly_index.make_query_parser()

    with chdir(fixture_path):
        assert set(
            query_parser.complete_query(readonly_index, "path:./s")
        ) == set(
            [
                "path:./subdir/",
                "path:./subdir/*",
            ]
        )

        assert set(
            query_parser.complete_query(readonly_index, "path:./..//fixture/")
        ) == set(
            [
                "path:./../fixture/subdir/",
                "path:./../fixture/subdir/*",
                "path:./../fixture/toplev.c",
                "path:./../fixture/toplev.c.o",
            ]
        )

        assert set(
            query_parser.complete_query(readonly_index, "path:su")
        ) == set(
            [
                "path:subdir/",
                "path:subdir/*",
            ]
        )
        assert set(
            query_parser.complete_query(readonly_index, "path:subdir/")
        ) == set(
            [
                "path:subdir/bar.cpp",
                "path:subdir/bar.cpp.o",
                "path:subdir/foo.c",
                "path:subdir/foo.c.o",
            ]
        )


def test_complete_query_as_term(readonly_index):
    query_parser = readonly_index.make_query_parser()

    assert set(
        query_parser.complete_query(
            readonly_index, "cxx_function(std::vector<int, std::"
        )
    ) == set(['"cxx_function(std::vector<int, std::allocator<int> >)"'])
