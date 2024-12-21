from pathlib import Path

import pytest
import xapian
from pytest import fixture

from bdx.index import DatabaseField, IntegerField, PathField, Schema
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
            IntegerField("value", "XV", slot=slot, key="value"),
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
