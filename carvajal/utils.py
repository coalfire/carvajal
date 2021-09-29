"""
Miscellaneous utilities.
"""

from typing import Iterable


def all_and_not_empty(iterable: Iterable) -> bool:
    """
    Return True if iterable is all True and not empty.
    This is much like the standard library all,
    but False for the vacuous case of an empty iterable.

    :param iterable: iterable to check
    :type iterable: iterable
    :return: True or False, iterable is non-empty and all True
    :rtype: bool
    """
    if not iterable:
        return False
    return all(iterable)
