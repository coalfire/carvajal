# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

import typing

from hypothesis import given, strategies as st
from carvajal import utils


def test_all_and_not_empty_returns_false_on_empty_list():
    assert utils.all_and_not_empty([]) is False


def test_all_and_not_empty_returns_false_on_empty_set():
    assert utils.all_and_not_empty(set()) is False


@given(st.lists(st.booleans(), min_size=1))
def test_all_and_not_empty_is_same_as_all_for_non_empty_lists(nonempty):
    assert utils.all_and_not_empty(nonempty) is all(nonempty)


@given(st.sets(st.booleans(), min_size=1))
def test_all_and_not_empty_is_same_as_all_for_non_empty_sets(nonempty):
    assert utils.all_and_not_empty(nonempty) is all(nonempty)


@given(iterable=st.from_type(typing.Iterable))
def test_fuzz_all_and_not_empty(iterable):
    utils.all_and_not_empty(iterable=iterable)
