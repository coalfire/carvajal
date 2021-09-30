pytest examples
~~~~~~~~~~~~~~~

A simple test
+++++++++++++

.. code-block:: python

    import pytest

    from carvajal import aws

    def test_none_accept_ssh_from_world():
        my_instances = aws.get_instances()
        ssh_ingress_rules = aws.instances_ingress_rules_for_port(my_instances, 22)
        actual = aws.rules_cidrs_and_security_groups(ssh_ingress_rules)
        assert "0.0.0.0/0" not in actual["cidrs"]


Using all_and_not_empty
+++++++++++++++++++++++

Let's test that some instances have API termination disabled.
This is a nice one to have:
sometimes when developing a complex configuration,
we may destroy and rebuild an instance multiple times.
To make that easy, we will enable API termination -
but once our configuration is proven good,
we want to turn it off.
A test will help us remember to do this.

.. code-block:: python

    import pytest

    from carvajal import aws


    def test_has_api_termination_disabled(web):
        my_instances = aws.get_instances()
        web_instances = aws.match_env_type_num_name_scheme(my_instances, r"web")
        disabled = aws.instances_attribute(web, 'disableApiTermination')
        # THIS IS INCORRECT
        assert all(disabled)


There is a problem here.
If there are no web instances
(for instance, I have put in bad credentials,
or the names are actually "PROD-WEB-01")
then this test will pass.
That is not desirable!

Here is a better way:

.. code-block:: python

    import pytest

    from carvajal import aws
    from carvajal import utils

    def test_has_api_termination_disabled(web):
        my_instances = aws.get_instances()
        web_instances = aws.match_env_type_num_name_scheme(my_instances, r"web")
        disabled = aws.instances_attribute(web, 'disableApiTermination')
        assert utils.all_and_not_empty(disabled)


Going a little further
++++++++++++++++++++++

Perhaps we would like to test some things about
our internally reachable web instances:

* That they are only reachable from your offices.
* That they can only be SSH'ed to from your developer offices.
* That they have public IPs
* That their public IPs are elastic IPs
* That they don't accept any traffic other than SSH and HTTPS
* That they cannot send traffic other than HTTPS
* That they are the correct instance type
* That they have termination protection

Assume we have a ``variables.tf`` file like this:

.. code-block:: terraform

    variable "cidr" {
      default = {
        cidr.adelaide      = "10.10.0.0/24"
        cidr.buenos_aires  = "10.10.0.0/24"
        cidr.cairo         = "10.10.0.0/24"
        cidr.djakarta      = "10.10.0.0/24"
        cidr.new_york      = "10.10.0.0/24"
        cidr.paris         = "10.10.0.0/24"

        cidr.mumbai        = "10.10.0.0/24"
        cidr.san_francisco = "10.10.0.0/24"
      }
    }



We would like to use our terraform states as a single point of truth,
rather than hardcoding these CIDR blocks into our test.
We'll use ``carvajal``'s ``terraform`` submodule to pull in these variables.

One thing you might notice in the earlier examples is that
we defined our instances in each test.
This is going to mean a lot of lengthy API calls as our test suite grows.
More importantly, it is going to get boring.
``pytest.fixture`` will let us pull in this information just once.

These two techniques are demonstrated in this ``test/conftest.py``:

.. code-block:: python

    import pytest
    from carvajal import aws
    from carvajal import terraform as tfm

    @pytest.fixture(scope="session")
    def my_instances():
        return aws.get_instances()

    @pytest.fixture(scope="session")
    def my_offices():
        return {
            tfm.variable("cidr.adelaide"),
            tfm.variable("cidr.buenos_aires"),
            tfm.variable("cidr.cairo"),
            tfm.variable("cidr.djakarta"),
            tfm.variable("cidr.new_york"),
            tfm.variable("cidr.paris"),
        }

    @pytest.fixture(scope="session")
    def developers():
        return {
            tfm.variable("cidr.mumbai"),
            tfm.variable("cidr.san_francisco"),
        }


Finally we write tests for our web instances in ``tests/test_web.py``:

.. code-block:: python

    import pytest

    from carvajal import aws


    @pytest.fixture(scope="module", name="web")
    def web_instances(my_instances):
        # for example: prod-web-03 stage-web-01 test-web-01
        return aws.match_env_type_num_name_scheme(my_instances, r"web")

    def test_accepts_web_from_offices_only(web, my_offices):
        actual = aws.instances_port_ingress_sources(web, port=443)
        assert actual["cidrs"] == my_offices
        assert actual["sgids"] == set()

    def test_accepts_ssh_from_devs_only(web, developers):
        actual = aws.instances_port_ingress_sources(web, port=443)
        assert actual["cidrs"] == developers
        assert actual["sgids"] == set()

    def test_has_public_ip(web):
        public_ips = [instance.get('PublicIpAddress') for instance in web]
        assert all_and_not_empty(public_ips)

    def test_has_elastic_ip(web):
        eips = aws.instances_elastic_ips(web)
        assert all_and_not_empty(eips)

    def test_accepts_only_ssh_and_web(web):
        assert aws.instances_ingress_ports(web) == {22, 443}

    def test_sends_only_web(web):
        assert aws.instances_egress_ports(web) == {443}

    def test_is_type_t3_medium(web):
        t3_medium = [instance.get('InstanceType') == "t3.medium" for instance in web]
        assert all_and_not_empty(t3_medium)

    def test_has_api_termination_disabled(web):
        disabled = aws.instances_attribute(web, 'disableApiTermination')
        assert all_and_not_empty(disabled)


pyunit examples
~~~~~~~~~~~~~~~

``pyunit`` (the module itself is called ``unittest``)
does not have test fixtures,
and thus every test will need to make API calls.
Here is an example:

.. code-block:: python

    import unittest

    from carvajal import aws

    class TestVpnInstances(unittest.TestCase):

        def test_has_public_ip(self):
            all_instances = aws.get_instances()
            vpn_instances = aws.match_env_type_num_name_scheme(all_instances, r"vpn")
            public_ips = [
                instance.get('PublicIpAddress')
                for instance in vpn_instances
            ]
            self.assertTrue(public_ips)
            self.assertTrue(all(public_ips))

    if __name__ == '__main__':
        unittest.main()

However, we can run ``pyunit`` tests with the ``pytest`` runner,
and that will let us use fixtures.
This is be nice for those who prefer the ``xunit`` style of tests,
but need the speed boost from fixtures.

.. code-block:: python

    import unittest

    import pytest

    from carvajal import aws

    @pytest.fixture(scope="class")
    def vpn_instances(request):
        all_instances = aws.get_instances()
        request.cls.vpn =  aws.match_env_type_num_name_scheme(all_instances, r"vpn")


    @pytest.mark.usefixtures("vpn_instances")
    class TestVpnInstancesByFixture(unittest.TestCase):

        def test_has_public_ip(self):
            public_ips = [
                instance.get('PublicIpAddress')
                for instance in self.vpn
            ]
            self.assertTrue(public_ips)
            self.assertTrue(all(public_ips))

        def test_has_elastic_ip(self):
            eips = aws.instances_elastic_ips(self.vpn)
            self.assertTrue(eips)
            self.assertTrue(all(eips))



    if __name__ == '__main__':
        unittest.main()
