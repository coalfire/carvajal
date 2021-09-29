# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

from hypothesis import given, strategies as st
from carvajal import aws

# pylint: disable=protected-access
def test__capitalize_returns_empty_string_from_empty_string():
    assert aws._capitalize("") == ""


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


# See "Tag naming limits and requirements" in
# https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html
# In summary : letters, numbers, spaces, and a bit of punctuation,

tag_alphabet=st.characters(
    whitelist_categories=('L', 'N', 'Zs'),
    whitelist_characters=('_', '.', ':', '/', '=', '+', '-', '@'),
)

tag_keys = st.text(min_size=1, max_size=128, alphabet=tag_alphabet)
tag_values = st.text(min_size=0, max_size=256, alphabet=tag_alphabet)
tag = st.builds(dict, Key=tag_keys, Value=tag_values)
tags = st.lists(tag)
aws_objects = st.dictionaries(st.just("Tags"), tags, min_size=1)

@given(
    aws_object=aws_objects,
    key=st.text(),
    regex=st.text(),
)
def test_fuzz_tags_key_value_matches_regex(aws_object, key, regex):
    aws.tags_key_value_matches_regex(
        aws_object=aws_object, key=key, regex=regex
    )
