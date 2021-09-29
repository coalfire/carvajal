import pytest

from carvajal import utils
from hypothesis import given, strategies as st

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
