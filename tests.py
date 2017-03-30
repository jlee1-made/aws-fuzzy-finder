import datetime

from aws_fuzzy_finder import aws_utils


ZERO = datetime.timedelta(0)


class TestInstanceView:
    example_reservations = [{
        u'Groups': [],
        u'Instances': [{
            u'PrivateIpAddress': '10.121.111.123',
            u'PublicDnsName': 'spam.example.com',
            u'State': {
                u'Code': 16,
                u'Name': 'running'
            },
            u'Tags': [{
                u'Key': 'Name',
                u'Value': 'test_foobar"'
            }],
            u'VpcId': 'vpc-f2ccsd34f'
        }, {
            u'PrivateIpAddress': '10.121.12.34',
            u'PublicDnsName': 'spam.example.com',
            u'State': {
                u'Code': 16,
                u'Name': 'running'
            },
            u'Tags': [{
                u'Key': 'Name',
                u'Value': 'prod_something'
            }],
            u'VpcId': 'vpc-2342sfd2'
        }, {
            u'PrivateIpAddress': '10.121.12.55',
            u'PublicDnsName': 'spam.example.com',
            u'PublicIpAddress': '52.123.12.32',
            u'State': {
                u'Code': 16,
                u'Name': 'running'
            },
            u'Tags': [{
                u'Key': 'Name',
                u'Value': 'prod_something2'
            }],
            u'VpcId': 'vpc-2342sfd2'
        }]
    }]

    def test_getting_private_ip(self):
        searchable_instances = aws_utils.prepare_searchable_instances(
            reservations=self.example_reservations,
            use_private_ip=True
        )
        assert searchable_instances == [
            'test_foobar @ 10.121.111.123',
            'prod_something @ 10.121.12.34',
            'prod_something2 @ 10.121.12.55',
        ]

    def test_getting_public_ip(self):
        searchable_instances = aws_utils.prepare_searchable_instances(
            reservations=self.example_reservations,
            use_private_ip=False
        )
        assert searchable_instances == [
            'test_foobar @ 10.121.111.123',
            'prod_something @ 10.121.12.34',
            'prod_something2 @ 52.123.12.32',
        ]


class tzutc(datetime.tzinfo):

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


class TestRds:

    # These sample API snippets are cut-down from their full glory (and names /
    # ids etc. changed) to include keys that are used by this test or otherwise
    # seemed interesting

    connections = [
        {'FromPort': 5432,
         'IpProtocol': 'tcp',
         'IpRanges': [],
         'PrefixListIds': [],
         'ToPort': 5432,
         'UserIdGroupPairs': [{'GroupId': 'sg-3e9382da', 'UserId': '038239020394'}]}]

    rds_instance = {
        'DBInstanceIdentifier': 'uat-spam',
        'DBInstanceStatus': 'available',
        'DBName': 'spamdb',
        'DBSecurityGroups': [],
        'Endpoint': {
            'Address': 'uat-spam.ks93ks9gdf93.eu-west-1.rds.amazonaws.com',
            'HostedZoneId': 'Z34ABKDEXXEREJ',
            'Port': 5432},
        'MasterUsername': 'spamuser',
        'VpcSecurityGroups': [{'Status': 'active',
                               'VpcSecurityGroupId': 'sg-324ac932'},
                              {'Status': 'active',
                               'VpcSecurityGroupId': 'sg-4c89232a'}]}

    ec2_reservation = {
        'Groups': [],
        'Instances': [
            {'PrivateIpAddress': '10.74.123.44',
             'PublicDnsName': 'ec2-12-234-32-123.eu-west-1.compute.amazonaws.com',
             'PublicIpAddress': '12.234.32.123',
             'SecurityGroups': [{'GroupId': 'sg-3e9382da',
                                 'GroupName': 'uat-spam-web'}],
             'State': {'Code': 16, 'Name': 'running'},
             'Tags': [{'Key': 'Env', 'Value': 'uat'},
                      {'Key': 'Zone', 'Value': 'B'},
                      {'Key': 'Service',
                       'Value': 'spamservice'},
                      {'Key': 'Name',
                       'Value': 'uat_spam'}]}],
        'ReservationId': 'r-0049353aa35993b8c'}

    def test_get_rds_security_groups(self):
        groups = aws_utils.get_rds_security_groups(self.rds_instance)
        assert groups == ['sg-324ac932', 'sg-4c89232a']

    def test_get_groups_from_connections(self):
        groups = list(aws_utils.get_groups_from_connections(self.connections))
        assert groups == ['sg-3e9382da']

    def test_find_jump_host_ip(self):
        # TODO: add a host, like ec2_reservation, but that does NOT have a
        # matching VPC security group and assert that it is not a candidate
        # jump host
        connections = self.connections
        # null reservation because we want to test that:
        # - we are robust to missing keys
        # - reservations that do not match are not returned
        null_reservation = {}
        reservations = [null_reservation, self.ec2_reservation]
        reservations = list(
            aws_utils.find_jump_host(connections, reservations))
        [reservation] = reservations
        [instance] = reservation['Instances']
        assert instance['PublicIpAddress'] == '12.234.32.123'
