# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import carvajal.aws
from collections import ChainMap
from hypothesis import given, strategies as st
from re import compile

# TODO: replace st.nothing() with appropriate strategies


@given(buckets=st.builds(list))
def test_fuzz_buckets_encrypted(buckets):
    carvajal.aws.buckets_encrypted(buckets=buckets)


@given(filters=st.one_of(st.none(), st.lists(st.builds(dict))))
def test_fuzz_get_addresses(filters):
    carvajal.aws.get_addresses(filters=filters)


@given(filters=st.one_of(st.none(), st.lists(st.builds(dict))))
def test_fuzz_get_instances(filters):
    carvajal.aws.get_instances(filters=filters)


@given(filters=st.one_of(st.none(), st.lists(st.builds(dict))))
def test_fuzz_get_security_groups(filters):
    carvajal.aws.get_security_groups(filters=filters)


@given(instances=st.builds(list), attribute=st.nothing())
def test_fuzz_instances_attribute(instances, attribute):
    carvajal.aws.instances_attribute(instances=instances, attribute=attribute)


@given(instances=st.builds(list))
def test_fuzz_instances_egress_ports(instances):
    carvajal.aws.instances_egress_ports(instances=instances)


@given(instances=st.builds(list))
def test_fuzz_instances_egress_rules(instances):
    carvajal.aws.instances_egress_rules(instances=instances)


@given(instances=st.builds(list), port=st.integers())
def test_fuzz_instances_egress_rules_for_port(instances, port):
    carvajal.aws.instances_egress_rules_for_port(instances=instances, port=port)


@given(instances=st.builds(list))
def test_fuzz_instances_elastic_ips(instances):
    carvajal.aws.instances_elastic_ips(instances=instances)


@given(instances=st.builds(list))
def test_fuzz_instances_ingress_ports(instances):
    carvajal.aws.instances_ingress_ports(instances=instances)


@given(instances=st.builds(list))
def test_fuzz_instances_ingress_rules(instances):
    carvajal.aws.instances_ingress_rules(instances=instances)


@given(instances=st.builds(list), port=st.integers())
def test_fuzz_instances_ingress_rules_for_port(instances, port):
    carvajal.aws.instances_ingress_rules_for_port(instances=instances, port=port)


@given(instances=st.builds(list), port=st.integers())
def test_fuzz_instances_port_ingress_sources(instances, port):
    carvajal.aws.instances_port_ingress_sources(instances=instances, port=port)


@given(instances=st.builds(list))
def test_fuzz_instances_security_groups(instances):
    carvajal.aws.instances_security_groups(instances=instances)


@given(instances=st.builds(list))
def test_fuzz_instances_security_groups_ids(instances):
    carvajal.aws.instances_security_groups_ids(instances=instances)


@given(objects=st.nothing(), infix=st.nothing(), env=st.text(), num=st.text())
def test_fuzz_match_env_type_num_name_scheme(objects, infix, env, num):
    carvajal.aws.match_env_type_num_name_scheme(
        objects=objects, infix=infix, env=env, num=num
    )


@given(
    objects=st.one_of(
        st.lists(st.builds(dict)),
        st.sets(st.builds(dict)),
        st.frozensets(st.builds(dict)),
        st.dictionaries(keys=st.builds(dict), values=st.builds(dict)),
        st.dictionaries(keys=st.builds(dict), values=st.none()).map(dict.keys),
        st.dictionaries(keys=st.integers(), values=st.builds(dict)).map(dict.values),
        st.iterables(st.builds(dict)),
        st.dictionaries(keys=st.builds(dict), values=st.builds(dict)).map(ChainMap),
    ),
    key=st.text(),
    regex=st.builds(compile, st.sampled_from(["", b""])),
)
def test_fuzz_objects_tags_key_values_matches_regex(objects, key, regex):
    carvajal.aws.objects_tags_key_values_matches_regex(
        objects=objects, key=key, regex=regex
    )


@given(port=st.integers(), rule=st.nothing())
def test_fuzz_port_in_rule(port, rule):
    carvajal.aws.port_in_rule(port=port, rule=rule)


@given(rules=st.builds(list))
def test_fuzz_rules_cidrs_and_security_groups(rules):
    carvajal.aws.rules_cidrs_and_security_groups(rules=rules)


@given(rules=st.builds(list))
def test_fuzz_rules_ports(rules):
    carvajal.aws.rules_ports(rules=rules)


@given(group_ids=st.builds(list))
def test_fuzz_security_groups_egress(group_ids):
    carvajal.aws.security_groups_egress(group_ids=group_ids)


@given(group_ids=st.builds(list))
def test_fuzz_security_groups_ingress(group_ids):
    carvajal.aws.security_groups_ingress(group_ids=group_ids)


@given(
    aws_object=st.builds(dict),
    key=st.text(),
    regex=st.builds(compile, st.sampled_from(["", b""])),
)
def test_fuzz_tags_key_value_matches_regex(aws_object, key, regex):
    carvajal.aws.tags_key_value_matches_regex(
        aws_object=aws_object, key=key, regex=regex
    )

