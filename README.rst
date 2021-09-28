carvajal
========

Helper functions for describing AWS infrastructure.

``carvajal`` is particularly intended for writing tests,
but can also be used for monitoring and auditing.

``carvajal`` includes terraform helpers to look up 
variables, data sources, and other terraform objects.

``carvajal`` has been in use for a few years now,
but you should not consider it stable (yet).
Pin your version in your ``requirements.txt``,
please, or be prepared to rewrite some of your tests on occasion.
``carvajal`` will always follow semantic versioning.

Complete documentation is at
https://carvajal.readthedocs.io/en/latest/index.html.

Source code is at
https://github.com/coalfire/carvajal.

usage
~~~~~

``pip install carvajal``

Create a ``test`` directory.

Write some tests for all of your instances in ``test/test_all.py``:

.. code-block:: python

    import pytest

    from carvajal import aws

    def test_none_accept_ssh_from_world():
        my_instances = aws.get_instances()
        ssh_ingress_rules = aws.instances_ingress_rules_for_port(my_instances, 22)
        actual = aws.rules_cidrs_and_security_groups(ssh_ingress_rules)
        assert "0.0.0.0/0" not in actual["cidrs"]


Run ``pytest``.


philosophy and alternatives
---------------------------

``carvajal`` has some guiding principals:

* test deployed resources, not the deploy code.
* make broad assertions about the state of your infrastructure - for instance:

   * nothing has 22 open from the world.
   * web instances only allow 443 in.

* test in production.

   * It's not that we are *not* going to test before we go to prod.
   * It is that we are going to *continue* testing once we reach prod.

* use an existing language (in this case Python),
  rather than having new tools specific to Infrastructure-as-Code.

   * At least some users will not have to learn a new language
   * Users can choose from multiple test frameworks (pyunit, pytest, etc)
   * Users can integrate into other tools - for instance, prometheus exporters.

* ``carvajal`` is only one of many tools for testing Infrastructure-as-Code.
* we don't think other Infrastructure-as-Code philosphies are wrong,
  but they do not accomplish what ``carvajal`` is trying to accomplish.


Some other tools you might consider are:

* `Terratest <https://terratest.gruntwork.io/>`_

* `Kitchen-Terraform <https://github.com/newcontext-oss/kitchen-terraform>`_

* `InSpec <https://community.chef.io/tools/chef-inspec>`_

* `Serverspec <https://serverspec.org/>`_

* `ScoutSuite <https://github.com/nccgroup/ScoutSuite>`_

development
------------

.. code-block:: shell

    make help

to do
-----

We need tests.

We need type hints.

Function names could do with a thorough review and setting a standard format.
