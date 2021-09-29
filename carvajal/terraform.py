"""
Functions for extracting information from terraform.
"""

from functools import lru_cache
import subprocess
import yaml


@lru_cache(maxsize=128)
def console(query):
    """
    Ask terraform console a question.
    It is usually easier to use data or variable instead.
    If the output will be used as a data structure,
    use struct instead.

    :param query: terraform console expression
    :type query: str
    :return: Terraform's output
    :rtype: str
    """
    tf_console = ["terraform", "console"]
    run = subprocess.run(
        tf_console,
        input=query,
        stdout=subprocess.PIPE,
        encoding="utf-8",
        check=True,
    )
    return run.stdout.strip().strip('"')


def output(query):
    """
    Ask terraform output a question.

    :param query: terraform output key
    :type query: str
    :return: Terraform's output
    :rtype: str
    """
    tf_output = ["terraform", "output", query]
    run = subprocess.run(
        tf_output, stdout=subprocess.PIPE, encoding="utf-8", check=True
    )
    return run.stdout.strip().strip('"')


def value(what_type, name):
    """
    Ask terraform console for a data or a variable value.
    it is usually easier to use data or variable instead.

    :param what_type: "data" or "var"
    :type what_type: str
    :param name: Name of data or var to return
    :type name: str
    :return: Terraform's output
    :rtype: str
    """
    if what_type not in ["data", "var"]:
        raise ValueError
    query = f"{what_type}.{name}"
    return console(query)


def data(query):
    """
    Ask terraform console for a data value.

    :param query: terraform data to look up
    :type query: str
    :return: Terraform's output
    :rtype: str
    """
    return value("data", query)


def variable(var):
    """
    Ask terraform console for a variable value.

    :param var: terraform var to look up
    :type var: str
    :return: Terraform's output
    :rtype: str
    """
    return value("var", var)


def struct(query):
    """
    Ask terraform console a question,
    returning the answer as a data structure
    (list or dict, as appropriate)

    :param query: terraform console expression
    :type query: str
    :return: Terraform's output
    :rtype: list or dict
    """
    return yaml.safe_load(console(query))
