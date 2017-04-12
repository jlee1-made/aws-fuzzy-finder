import logging
import os
import socket
import subprocess
import click
import shelve
import sys
import time

from . import aws_utils
from .aws_utils import (
    get_aws_instances,
    list_rds_tags,
    prepare_searchable_instances
)
from .settings import (
    ENV_USE_PRIVATE_IP,
    ENV_USE_PUBLIC_DNS_OVER_IP,
    ENV_KEY_PATH,
    ENV_SSH_COMMAND_TEMPLATE,
    ENV_SSH_USER,
    ENV_TUNNEL_SSH_USER,
    ENV_TUNNEL_KEY_PATH,
    SEPARATOR,
    LIBRARY_PATH,
    CACHE_PATH,
    CACHE_EXPIRY_TIME,
    CACHE_ENABLED
)


logger = logging.getLogger()


def configure_dev_logging():
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    root.addHandler(handler)


def find_free_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    addr = s.getsockname()
    s.close()
    port = addr[1]
    return port


def psql_entrypoint(use_private_ip, key_path, user, ip_only, no_cache, tunnel, tunnel_key_path, tunnel_user, psql):
    # This just ignores most arguments because I haven't bothered to find out
    # what they are
    rds_instances = aws_utils.fetch_rds_instances()
    searchable_instances = aws_utils.prepare_rds_searchable_instances(
        rds_instances)

    fuzzysearch_bash_command = 'echo -e "{}" | {}'.format(
        "\n".join(searchable_instances),
        LIBRARY_PATH
    )
    name, host = choice_ex(fuzzysearch_bash_command)
    host = host.rstrip()
    rds_instance = aws_utils.find_rds_instance(rds_instances, name)
    username = rds_instance['MasterUsername']

    db_name = rds_instance.get('DBName')
    if db_name is None:
        rds_identifier = rds_instance.get('DBInstanceIdentifier')
        tags = list_rds_tags(rds_identifier)
        # RDS tag name DefaultDBNameHint is only standard in that this script
        # uses it :-)  Sadly it's not possible to set the DBName metadata, so
        # this method is provided as an alternative means of providing a hint
        # as to the database name to connect to.
        db_name = tags.get('DefaultDBNameHint', 'template1')

    db_port = rds_instance['Endpoint'].get('Port', 5432)

    vpc_groups = aws_utils.get_rds_security_groups(rds_instance)
    connections = aws_utils.fetch_connections(security_groups=vpc_groups)
    boto_instance_data = get_boto_instance_data(no_cache)
    candidate_reservations = boto_instance_data['Reservations']
    # just pick first EC2 host we find
    reservation = next(
        aws_utils.find_jump_host(connections, candidate_reservations))
    searchable_instances = prepare_searchable_instances(
        [reservation],
        use_private_ip or ENV_USE_PRIVATE_IP,
        ENV_USE_PUBLIC_DNS_OVER_IP
    )
    [instance] = searchable_instances
    instance_name, instance_host = instance.split(SEPARATOR)
    instance_host = instance_host.rstrip()

    local_port = find_free_local_port()
    remote_host = host
    remote_port = db_port
    jump_host = instance_host
    command = ['aws-fuzzy-finder-forward-and-run', str(local_port), remote_host, str(remote_port), jump_host, 'psql', '-h', 'localhost', '-p', str(local_port), '-W', '-U', username, db_name]
    os.execvp(command[0], command)


def get_boto_instance_data(no_cache):
    try:
        with shelve.open(CACHE_PATH) as cache:
            data = cache.get('fuzzy_finder_data')
            if CACHE_ENABLED and data and data.get('expiry') >= time.time() and not no_cache:
                logger.info('EC2 instance data: Cache HIT')
                boto_instance_data = data['aws_instances']
            else:
                logger.info('EC2 instance data: Cache MISS')
                boto_instance_data = get_aws_instances()
                if CACHE_ENABLED:
                    cache['fuzzy_finder_data'] = {
                        'aws_instances': boto_instance_data,
                        'expiry': time.time() + CACHE_EXPIRY_TIME
                    }
    except:
        logger.info('EC2 instance data: Cache MISS')
        boto_instance_data = get_aws_instances()
    return boto_instance_data


@click.command()
@click.option('--private', 'use_private_ip', flag_value=True, help="Use private IP's")
@click.option('--key-path', default='~/.ssh/id_rsa', help="Path to your private key, default: ~/.ssh/id_rsa")
@click.option('--user', default='ec2-user', help="User to SSH with, default: ec2-user")
@click.option('--ip-only', 'ip_only', flag_value=True, help="Print chosen IP to STDOUT and exit")
@click.option('--no-cache', flag_value=True, help="Ignore and invalidate cache")
@click.option('--tunnel/--no-tunnel', help="Tunnel to another machine")
@click.option('--tunnel-key-path', default='~/.ssh/id_rsa', help="Path to your private key, default: ~/.ssh/id_rsa")
@click.option('--tunnel-user', default='ec2-user', help="User to SSH with, default: ec2-user")
@click.option('--psql', flag_value=True, help="psql to host")
@click.option('--log', flag_value=True, help="Enable logging output to stdout")
def entrypoint(use_private_ip, key_path, user, ip_only, no_cache, tunnel, tunnel_key_path, tunnel_user, psql, log):
    if log:
        configure_dev_logging()

    if psql:
        return psql_entrypoint(use_private_ip, key_path, user, ip_only, no_cache, tunnel, tunnel_key_path, tunnel_user, psql)

    boto_instance_data = get_boto_instance_data(no_cache)

    searchable_instances = prepare_searchable_instances(
        boto_instance_data['Reservations'],
        use_private_ip or ENV_USE_PRIVATE_IP,
        ENV_USE_PUBLIC_DNS_OVER_IP
    )
    searchable_instances.sort(reverse=True)

    fuzzysearch_bash_command = 'echo -e "{}" | {}'.format(
        "\n".join(searchable_instances),
        LIBRARY_PATH
    )

    ssh_command = ENV_SSH_COMMAND_TEMPLATE.format(
        user=ENV_SSH_USER or user,
        key=ENV_KEY_PATH or key_path,
        host=choice(fuzzysearch_bash_command),
    )

    if tunnel:
        ssh_command += " -t " + ENV_SSH_COMMAND_TEMPLATE.format(
            user=ENV_TUNNEL_SSH_USER or tunnel_user,
            key=ENV_TUNNEL_KEY_PATH or tunnel_key_path,
            host=choice(fuzzysearch_bash_command),
        )

    print(ssh_command)
    subprocess.call(ssh_command, shell=True, executable='/bin/bash')


def choice_ex(fuzzysearch_bash_command):
    try:
        choice = subprocess.check_output(
            fuzzysearch_bash_command,
            shell=True,
            executable='/bin/bash'
        ).decode(encoding='UTF-8')
    except subprocess.CalledProcessError:
        exit(1)

    return choice.split(SEPARATOR)


def choice(fuzzysearch_bash_command):
    choice = choice_ex(fuzzysearch_bash_command)
    return choice[1].rstrip()


if __name__ == '__main__':
    entrypoint()
