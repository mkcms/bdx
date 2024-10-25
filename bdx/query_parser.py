import re
from enum import Enum
from typing import Optional

import xapian

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
    Wildcard = "WILDCARD"

    @staticmethod
    def patterns() -> list[tuple["Token", re.Pattern]]:
        """Return a list of patterns for each token, in proper test order."""
        return [
            (Token.Whitespace, re.compile(r"\s+")),
            (Token.And, re.compile(r"AND\b")),
            (Token.Or, re.compile(r"OR\b")),
            (Token.Lparen, re.compile(r"[(]")),
            (Token.Rparen, re.compile(r"[)]")),
            (Token.String, re.compile(r'"([^"]+)"')),
            (Token.Field, re.compile(r"([a-zA-Z_]+):")),
            (Token.Wildcard, re.compile(r"([a-zA-Z_][a-zA-Z0-9_.]*)[*]")),
            (Token.Term, re.compile(r"([a-zA-Z_][a-zA-Z0-9_.]*)")),
        ]


class Op(Enum):
    """Enum of all recogznied operators."""

    And = xapian.Query.OP_AND
    Or = xapian.Query.OP_OR
    Wildcard = xapian.Query.OP_WILDCARD


_MATCH_ALL = xapian.Query.MatchAll


class QueryParser:
    """Custom query parser for the database."""

    ignore_unknown_tokens = True
    ignore_missing_field_values = True

    class Error(RuntimeError):
        """Parsing error."""

    class UnknownTokenError(Error):
        """Unknown token error."""

    # Grammar:
    #
    # query = boolexpr
    #
    # boolexpr = orexpr
    # orexpr = andexpr ["OR" orexpr]
    # andexpr = expr [["AND"] andexpr]
    #
    # expr =
    #         "(" query ")"
    #         | [ field ] value
    #
    # value = term | string | wildcard
    #
    # field = [a-zA-Z_]+ ":"
    # term = [a-zA-Z_][a-zA-Z0-9_.]*
    # string = '"' [^"]+ '"'
    # wildcard = [a-zA-Z_][a-zA-Z0-9_.]*[*]

    def __init__(
        self,
        schema: Schema,
        default_fields: Optional[list[str]] = None,
        wildcard_field: Optional[str] = None,
    ):
        """Construct a QueryParser using given schema.

        Args:
            schema: The database schema to use.
            default_fields: List of database field names that will be
                searched for by default when the query contains a term value,
                but does not specify a prefix
                (e.g. "val*" instead of "field:val*").
            wildcard_field: Name of the field that will be used when the user
                enters a wildcard without specifying a field.

        """
        self.schema = schema
        self.default_fields = default_fields or list(schema)
        self.wildcard_field = wildcard_field
        self._query = ""
        self._token: Optional[Token] = None
        self._value: Optional[str] = None
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
        self._parse_query()
        if self._token != Token.EOF:
            raise QueryParser.Error()
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
                        self._value = None
                    return

            if self.ignore_unknown_tokens:
                self._pos += 1
            else:
                break

        raise QueryParser.UnknownTokenError(
            f'Invalid token beginning at pos {pos} ("{query[:6]}...")'
        )

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
                raise QueryParser.Error("Expected RHS operand to OR")
            rhs = self._parsed
            if lhs != self._empty and rhs != self._empty:
                self._parsed = xapian.Query(Op.Or.value, lhs, rhs)
            elif lhs != self._empty:
                self._parsed = lhs
            elif rhs != self._empty:
                self._parsed = rhs

        return True

    def _parse_andexpr(self):
        if not self._parse_expr():
            return False

        lhs = self._parsed
        rhs = None

        if self._token == Token.And:
            self._next_token()
            if not self._parse_andexpr():
                raise QueryParser.Error("Expected RHS operand to AND")
            rhs = self._parsed
        elif self._parse_andexpr():
            rhs = self._parsed

        if rhs is not None:
            if lhs is None:
                self._parsed = rhs
            else:
                self._parsed = xapian.Query(Op.And.value, lhs, rhs)
        else:
            self._parsed = lhs

        return True

    def _parse_expr(self):
        retval = True

        if self._token == Token.Lparen:
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
        elif self._token == Token.Wildcard:
            retval = self._parse_wildcard()
        elif self._token == Token.Field:
            field = self._value
            self._parse_field()

            is_known_field = field in self.schema
            value_present = self._token in [
                Token.Term,
                Token.String,
                Token.Wildcard,
            ]
            ignore_missing_values = self.ignore_missing_field_values

            if (
                not is_known_field
                and not value_present
                and not ignore_missing_values
            ):
                raise QueryParser.Error(
                    f"Missing value for field {field} at position {self._pos}"
                )
            if not is_known_field or (
                not value_present and ignore_missing_values
            ):
                if value_present:
                    self._next_token()
                self._parsed = self._empty
                retval = True
            else:
                retval = self._parse_field_with_value(field)
        else:
            retval = False
        return retval

    def _parse_term(self):
        self._expect(Token.Term, "term")
        if self._value is None:
            # This is more of a programmer error...
            msg = "Missing value for term"
            raise QueryParser.Error(msg)
        value = self._value
        subqueries = []
        for field in self.default_fields:
            schema_field = self.schema[field]
            prefix = schema_field.prefix
            if schema_field.boolean or not schema_field.lowercase:
                term = f"{prefix}{value}"
            else:
                term = f"{prefix}{value.lower()}"
            subquery = xapian.Query(term)
            subqueries.append(subquery)

        self._next_token()
        if len(subqueries) == 1:
            query = subqueries[0]
        else:
            query = xapian.Query(Op.Or.value, subqueries)
        self._parsed = query
        return True

    def _parse_wildcard(self):
        self._expect(Token.Wildcard, "wildcard")
        if not self.wildcard_field:
            self._parsed = self._empty
            self._next_token()
            return True
        if self._value is None:
            # This is more of a programmer error...
            msg = "Missing value for wildcard"
            raise QueryParser.Error(msg)

        value = self._value
        field = self.schema[self.wildcard_field]
        prefix = field.prefix
        if field.boolean or not field.lowercase:
            term = f"{prefix}{value}"
        else:
            term = f"{prefix}{value.lower()}"
        query = xapian.Query(
            Op.Wildcard.value, term, 0, xapian.Query.WILDCARD_LIMIT_FIRST
        )

        self._next_token()
        self._parsed = query
        return True

    def _parse_string(self):
        self._expect(Token.String, "string")
        value = self._value
        subqueries = []
        for field in self.default_fields:
            prefix = self.schema[field].prefix
            term = f"{prefix}{value}"
            subquery = xapian.Query(term)
            subqueries.append(subquery)

        self._next_token()
        if len(subqueries) == 1:
            query = subqueries[0]
        else:
            query = xapian.Query(Op.Or.value, subqueries)
        self._parsed = query
        return True

    def _parse_field(self):
        self._expect(Token.Field, "field name")
        self._next_token()

    def _parse_field_with_value(self, field):
        self._expect(
            [Token.Term, Token.String, Token.Wildcard],
            f'value for field "{field}"',
        )
        if self._value is None:
            # This is more of a programmer error...
            msg = "Missing value for term"
            raise QueryParser.Error(msg)

        schema_field = self.schema[field]
        field_prefix = schema_field.prefix
        if schema_field.boolean or not schema_field.lowercase:
            term = self._value
        else:
            term = self._value.lower()

        term_with_prefix = f"{field_prefix}{term}"

        if self._token == Token.Wildcard:
            self._parsed = xapian.Query(
                Op.Wildcard.value,
                term_with_prefix,
                0,
                xapian.Query.WILDCARD_LIMIT_FIRST,
            )

        else:
            self._parsed = xapian.Query(term_with_prefix)

        self._next_token()
        return True

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