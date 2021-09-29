import pytest

from carvajal import aws
from hypothesis import given, strategies as st

def test__capitalize_returns_empty_string_from_empty_string():
    assert aws._capitalize('') == ''

@given(st.text(min_size=1))
def test__capitalize_capitalizes_first_char(text):
    # We can't always just grab the first character of the result,
    # because some characters like ŉ upcase to two chars.
    initial_capital = text[0].upper()
    length_of_initial_capital = len(initial_capital)
    result = aws._capitalize(text)
    assert result[0:length_of_initial_capital] == text[0].upper()

@given(st.text(min_size=1))
def test__capitalize_does_not_change_tail(text):
    # We can't always just slice from 1 to the end of the result,
    # because some characters like ß upcase to two chars.
    length_of_initial_capital = len(text[0].upper())
    result = aws._capitalize(text)
    tail = result[length_of_initial_capital:]
    assert tail == text[1:]
