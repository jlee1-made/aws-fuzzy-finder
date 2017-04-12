import boto3
from botocore.exceptions import (
    NoRegionError,
    PartialCredentialsError,
    NoCredentialsError,
    ClientError
)

from .settings import (
    SEPARATOR,
    NO_REGION_ERROR,
    NO_CREDENTIALS_ERROR,
    WRONG_CREDENTIALS_ERROR
)


def get_aws_account_name_from_boto3_config():
    client = boto3.client("sts")
    return client.get_caller_identity()["Account"]


def get_aws_region_from_boto3_config():
    my_session = boto3.session.Session()
    return my_session.region_name


def list_rds_tags(db_instance_identifier):
    account_id = get_aws_account_name_from_boto3_config()
    region = get_aws_region_from_boto3_config()
    arn = "arn:aws:rds:%s:%s:db:%s" % (
        region, account_id, db_instance_identifier
    )
    rds = boto3.client('rds')
    response = rds.list_tags_for_resource(ResourceName=arn)
    return dict((d['Key'], d['Value']) for d in response['TagList'])


def gather_instance_data(reservations):
    instances = []

    for reservation in reservations:
        for instance in reservation['Instances']:
            if instance['State']['Name'] != 'running':
                continue

            # skipping not named instances
            if 'Tags' not in instance:
                continue

            instance_data = {
                'public_ip': instance.get('PublicIpAddress', ''),
                'private_ip': instance['PrivateIpAddress'],
                'public_dns': instance['PublicDnsName'],
                'tags': instance['Tags']
            }
            instances.append(instance_data)
    return instances


def get_tag_value(tag_name, tags):
    for tag in tags:
        if tag['Key'] == tag_name:
            return tag['Value'].replace('"', '')


def get_aws_instances():
    try:
        return boto3.client('ec2').describe_instances()
    except NoRegionError:
        print(NO_REGION_ERROR)
        exit(1)
    except (PartialCredentialsError, NoCredentialsError):
        print(NO_CREDENTIALS_ERROR)
        exit(1)
    except ClientError:
        print(WRONG_CREDENTIALS_ERROR)
        exit(1)


def prepare_searchable_instances(reservations, use_private_ip, use_public_dns_over_ip=False):
    instance_data = gather_instance_data(reservations)
    searchable_instances = []
    for instance in instance_data:
        name = get_tag_value('Name', instance['tags'])
        if use_public_dns_over_ip:
            ip = instance['public_dns']
        elif use_private_ip:
            ip = instance['private_ip']
        else:
            ip = instance['public_ip'] or instance['private_ip']
        searchable_instances.append("{}{}{}".format(
            name,
            SEPARATOR,
            ip
        ))
    return searchable_instances


def get_rds_security_groups(rds_instance):
    groups = rds_instance.get('VpcSecurityGroups', [])
    return list(
        filter(lambda id_: id_ is not None,
               (group.get('VpcSecurityGroupId', None) for group in groups)))


def fetch_connections(security_groups):
    # Note these are VPC security groups, not DB ones
    connections = []
    ec2 = boto3.resource('ec2')
    for group in security_groups:
        sg = ec2.SecurityGroup(group)
        connections.extend(sg.ip_permissions)
    return connections


def get_groups_from_connections(connections):
    for connection in connections:
        for pair in connection.get('UserIdGroupPairs', []):
            yield pair.get('GroupId')


def find_jump_host(connections, reservations):
    groups = frozenset(get_groups_from_connections(connections))
    for reservation in reservations:
        for instance in reservation.get('Instances', []):
            for group in instance.get('SecurityGroups', []):
                if group.get('GroupId') in groups:
                    yield reservation


def fetch_rds_instances():
    rds = boto3.client('rds')
    return rds.describe_db_instances()['DBInstances']


def prepare_rds_searchable_instances(rds_instances):
    searchable_instances = []
    for instance in rds_instances:
        name = instance.get('DBInstanceIdentifier')
        host = instance.get('Endpoint', {}).get('Address')
        if not name or not host:
            continue

        searchable_instances.append("{}{}{}".format(
            name,
            SEPARATOR,
            host
        ))
    return searchable_instances


def find_rds_instance(rds_instances, name):
    for instance in rds_instances:
        if instance.get('DBInstanceIdentifier') == name:
            return instance
    assert False, (rds_instances, name)
