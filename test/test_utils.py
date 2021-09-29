import pytest

from carvajal import utils

def test_all_and_not_empty_returns_false_on_empty_list():
    assert utils.all_and_not_empty([]) is False

def test_all_and_not_empty_returns_false_on_lists_that_are_not_all_true():
    assert utils.all_and_not_empty([True, False]) is False

def test_all_and_not_empty_returns_true_on_non_empty_lists_that_are_all_true():
    assert utils.all_and_not_empty([True, True]) is True
