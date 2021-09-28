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

Going a little further
++++++++++++++++++++++

Perhaps you would like to test some things about 
your internally reachable web instances:

* That they are only reachable from your offices.
* That they can only be SSH'ed to from your developer offices.
* That they have public IPs
* That their public IPs are elastic IPs
* That they don't accept any traffic other than SSH and HTTPS
* That they cannot send traffic other than HTTPS
* That they are the correct instance type
* That they have termination protection

If you have terraform like this:

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


then you can place this is your ``test/conftest.py``:

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


and write tests for your web instances in ``tests/test_web.py``:

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
        assert public_ips
        assert all(public_ips)

    def test_has_elastic_ip(web):
        eips = aws.instances_elastic_ips(web)
        assert eips
        assert all(eips)

    def test_accepts_only_ssh_and_web(web):
        actual = tests.instances_ingress_ports(web)
        assert actual == {22, 443}

    def test_sends_only_web(web):
        actual = tests.instances_egress_ports(web)
        assert actual == {443}

    def test_is_type_t3_medium(web):
        instance_types = [instance.get('InstanceType') for instance in web]
        assert instance_types
        assert all(i_type == "t3.medium" for i_type in instance_types)

    def test_has_api_termination_disabled(web):
        disabled = aws.instances_attribute(web, 'disableApiTermination')
        assert disabled
        assert all(disabled)


Note the use of fixtures here. 
Hitting the AWS API,
or asking terraform questions, 
takes some time.
We can make sure that we don't issue the same expensive requests over and over
by collecting this information once in a fixture.


pyunit examples
~~~~~~~~~~~~~~~

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

There is a potential problem here, though:
Collecting all of your instances (or any other large collection) can take a
long time. 
If you have a lot of tests, you don't want to do it for every test.
If you want to keep ``xunit`` style tests that ``pyunit`` gives you,
but avoid some of this overhead, 
consider running ``pyunit`` tests with ``pytest``.
This lets you make use of fixtures, which will run once per class.

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
