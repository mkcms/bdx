import re
from enum import Enum
from typing import Optional

import xapian

from bdx import debug
from bdx.index import Schema


class Token(Enum):
    """Enum of all recognized tokens."""

    EOF = "EOF"
    Whitespace = "WHITESPACE"
    Term = "TERM"
    String = "STRING"
    Field = "FIELD"
    Lparen = "("
    Rparen = ")"
    And = "AND"
    Or = "OR"
    Not = "NOT"
    MatchAll = "MatchAll"
    Wildcard = "WILDCARD"

    @staticmethod
    def patterns() -> list[tuple["Token", re.Pattern]]:
        """Return a list of patterns for each token, in proper test order."""
        return [
            (Token.Whitespace, re.compile(r"\s+")),
            (Token.And, re.compile(r"AND\b")),
            (Token.Or, re.compile(r"OR\b")),
            (Token.Not, re.compile(r"NOT\b|!")),
            (Token.Lparen, re.compile(r"[(]")),
            (Token.Rparen, re.compile(r"[)]")),
            (Token.String, re.compile(r'"([^"]+)"')),
            (Token.Field, re.compile(r"([a-zA-Z_]+):")),
            (Token.MatchAll, re.compile(r"[*]:[*]")),
            (Token.Wildcard, re.compile(r"[*]")),
            (Token.Term, re.compile(r"([^\s()*]+)")),
        ]


_MATCH_ALL = xapian.Query.MatchAll  # pyright: ignore


class QueryParser:
    """Custom query parser for the database."""

    ignore_missing_field_values = True

    class Error(RuntimeError):
        """Parsing error."""

    # Grammar:
    #
    # query = boolexpr
    #
    # boolexpr = orexpr
    # orexpr = andexpr ["OR" orexpr]
    # andexpr = expr [["AND"] andexpr]
    #
    # expr =
    #         NOT expr
    #         | matchall
    #         | "(" query ")"
    #         | field value
    #         | field wildcard
    #         | value
    #
    # value = (term | string) [wildcard]
    #
    # NOT = NOT|!
    # matchall = [*]:[*]
    # field = [a-zA-Z_]+ ":"
    # string = '"' [^"]+ '"'
    # wildcard = [*]
    # term = [^\s()*]*

    def __init__(
        self,
        schema: Schema,
        default_fields: Optional[list[str]] = None,
        auto_wildcard: bool = False,
    ):
        """Construct a QueryParser using given schema.

        Args:
            schema: The database schema to use.
            default_fields: List of database field names that will be
                searched for by default when the query contains a term value,
                but does not specify a prefix
                (e.g. "val*" instead of "field:val*").
            auto_wildcard: If true, then each search term is implicitly
                converted into a wildcard.
                E.g. search "term" will become "field:term*".

        """
        self.schema = schema
        self.default_fields = default_fields or list(schema)
        self.auto_wildcard = auto_wildcard
        self._query = ""
        self._token: Optional[Token] = None
        self._value: str = ""
        self._pos: int = 0
        self._parsed = None
        self._empty = xapian.Query()

    def parse_query(self, query: str) -> xapian.Query:
        """Parse the given query."""
        if query.strip() == "*:*":
            return _MATCH_ALL

        self._query = query
        self._token = None
        self._pos = 0
        self._parsed = None
        self._empty = xapian.Query()  # re-set it for tests

        self._next_token()
        try:
            self._parse_query()
        except Exception as e:
            raise QueryParser.Error(str(e)) from e
        self._expect(Token.EOF, "EOF")
        if self._parsed is None:
            return xapian.Query()
        return self._parsed

    def _next_token(self):
        while True:
            pos = self._pos
            query = self._query[pos:]
            if not query:
                self._token = Token.EOF
                return

            for token, pat in Token.patterns():
                match = re.match(pat, query)
                if match:
                    _, idx = match.span()
                    pos += idx
                    self._pos = pos

                    if token == Token.Whitespace:
                        self._next_token()
                        return

                    self._token = token
                    if match.groups():
                        self._value = match.group(1)
                    else:
                        self._value = ""
                    return

            debug(f"Warning: unknown token at {self._pos}")
            self._pos += 1

    def _parse_query(self):
        return self._parse_boolexpr()

    def _parse_boolexpr(self):
        return self._parse_orexpr()

    def _parse_orexpr(self):
        if not self._parse_andexpr():
            return False
        if self._token == Token.Or:
            self._next_token()
            lhs = self._parsed
            if not self._parse_orexpr():
                msg = "Expected RHS operand to OR"
                raise QueryParser.Error(msg)
            rhs = self._parsed
            if lhs != self._empty and rhs != self._empty:
                self._parsed = xapian.Query(xapian.Query.OP_OR, lhs, rhs)
            elif lhs != self._empty:
                self._parsed = lhs
            elif rhs != self._empty:
                self._parsed = rhs

        self._parsed = self._flatten_query(xapian.Query.OP_OR, self._parsed)

        return True

    def _parse_andexpr(self):
        if not self._parse_expr():
            return False

        lhs = self._parsed
        rhs = None

        if self._token == Token.And:
            self._next_token()
            if not self._parse_andexpr():
                msg = "Expected RHS operand to AND"
                raise QueryParser.Error(msg)
            rhs = self._parsed
        elif self._parse_andexpr():
            rhs = self._parsed

        if rhs is not None:
            if lhs is None:
                self._parsed = rhs
            else:
                self._parsed = xapian.Query(xapian.Query.OP_AND, lhs, rhs)
        else:
            self._parsed = lhs

        self._parsed = self._flatten_query(xapian.Query.OP_AND, self._parsed)

        return True

    def _parse_expr(self):
        retval = True

        if self._token == Token.MatchAll:
            self._next_token()
            self._parsed = _MATCH_ALL
        elif self._token == Token.Not:
            self._next_token()
            retval = self._parse_expr()
            if not retval:
                msg = "Expected an expression"
                raise QueryParser.Error(msg)
            self._parsed = xapian.Query(
                xapian.Query.OP_AND_NOT, _MATCH_ALL, self._parsed
            )
        elif self._token == Token.Lparen:
            pos = self._pos
            self._next_token()
            self._parsed = None
            self._parse_query()
            self._expect(
                Token.Rparen, f'closing ")" (opening at position {pos - 1})'
            )
            self._next_token()
        elif self._token == Token.Term:
            retval = self._parse_term()
        elif self._token == Token.String:
            retval = self._parse_string()
        elif self._token == Token.Field:
            field = self._value
            self._parse_field()

            if field not in self.schema:
                known = ", ".join(self.schema.keys())
                msg = f'Unknown field "{field}", must be one of [{known}]'
                raise QueryParser.Error(msg)

            value_present = self._token in [
                Token.Term,
                Token.String,
                Token.Wildcard,
            ]
            ignore_missing_values = self.ignore_missing_field_values

            if not value_present and not ignore_missing_values:
                msg = (
                    f"Missing value for field {field} at position {self._pos}"
                )
                raise QueryParser.Error(msg)
            elif not value_present:
                self._parsed = self._empty
                retval = True
            else:
                retval = self._parse_field_with_value(field)
        else:
            retval = False
        return retval

    def _parse_term(self):
        value, wildcard = self._maybe_consume_wildcard(Token.Term, "term")

        subqueries = []
        for field in self.default_fields:
            subquery = self.schema[field].make_query(
                value, wildcard=wildcard or self.auto_wildcard
            )
            subqueries.append(subquery)

        self._parsed = self._merge_queries(subqueries)
        return True

    def _parse_string(self):
        value, wildcard = self._maybe_consume_wildcard(Token.String, "string")

        subqueries = []
        for field in self.default_fields:
            subquery = self.schema[field].make_query(value, wildcard=wildcard)
            subqueries.append(subquery)

        self._parsed = self._merge_queries(subqueries)
        return True

    def _parse_field(self):
        self._expect(Token.Field, "field name")
        self._next_token()

    def _parse_field_with_value(self, field):
        if self._token == Token.Wildcard:
            # We are looking at "field:*"
            value, wildcard = "", True
            self._next_token()
        else:
            value, wildcard = self._maybe_consume_wildcard(
                [Token.Term, Token.String],
                f'value for field "{field}"',
            )

        schema_field = self.schema[field]

        self._parsed = schema_field.make_query(
            value,
            wildcard=wildcard,
        )

        return True

    def _maybe_consume_wildcard(self, expected_token, msg) -> tuple[str, bool]:
        self._expect(
            expected_token,
            msg,
        )
        value = self._value
        self._next_token()

        if self._token == Token.Wildcard:
            have_it = True
            self._next_token()
        else:
            have_it = False

        return value, have_it

    def _merge_queries(self, subqueries):
        if len(subqueries) == 1:
            return subqueries[0]
        else:
            return xapian.Query(xapian.Query.OP_OR, subqueries)

    def _flatten_query(self, op, query: Optional[xapian.Query]):
        if query is not None and query.get_type() == op:
            subqueries = self._get_all_subqueries_of_type(op, query)
            return xapian.Query(op, subqueries)
        return query

    def _get_all_subqueries_of_type(self, op, query: xapian.Query):
        if query.get_type() == op and query.get_num_subqueries() >= 2:
            subqueries = [
                query.get_subquery(i)
                for i in range(query.get_num_subqueries())
            ]
            ret = []
            for subq in subqueries:
                flattened = self._get_all_subqueries_of_type(op, subq)
                ret.extend(flattened)
            return ret
        return [query]

    def _expect(self, token_or_tokens, what):
        if not isinstance(token_or_tokens, list):
            tokens = [token_or_tokens]
        else:
            tokens = token_or_tokens
        if self._token not in tokens:
            token = self._token
            pos = self._pos
            msg = f"Expected {what} at position {pos}, got {token}"
            raise QueryParser.Error(msg)
