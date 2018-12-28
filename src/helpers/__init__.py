import sys, logging, boto3, socket, configparser
from os import path, getcwd, environ
from yaml import load, dump
from jinja2 import Environment, FileSystemLoader


log = logging.getLogger('s4tool')
session = None
config = None

def make_arn(service, resource, partition='aws', use_account_id=True, account_id=None, region=None):
  if use_account_id and not account_id:
    account_id = get_aws_account_id()

  return 'arn:{partition}:{service}:{region}:{account_id}:{resource}'.format(
    partition=partition,
    service=service,
    region=region or '',
    account_id=account_id or '',
    resource=resource
  )


def start_boto_session(credentials_file=None, temp_profile=None, access_key_id=None, secret_access_key=None, profile=None, region=None):
  global session
  if (access_key_id and not secret_access_key) or \
     (secret_access_key and not access_key_id):
    log.critical('Set both secret_access_key and access_key_id together')
    sys.exit(1)

  if not session:
    session = boto3.Session(profile_name=profile, region_name=region,
                            aws_access_key_id=access_key_id,
                            aws_secret_access_key=secret_access_key)
    if not profile:
      if not credentials_file or not temp_profile:
        log.critical('when not using a profile ensure credentials_file and temp_profile are defined')
        sys.exit(1)
      update_config(credentials_file,
                    profile=temp_profile,
                    region=region,
                    access_key_id=access_key_id,
                    secret_access_key=secret_access_key)


def get_aws_account_id(return_identity=False):
  global session
  sts_client = session.client('sts')

  identity = sts_client.get_caller_identity()
  if return_identity:
    return identity['Account'], identity
  
  return identity['Account']


def assume_role(role, temp_profile, credentials_file, region=None, profile=None):
  global session
  assume_session = boto3.Session(profile_name=profile, region_name=region)
  sts_client = assume_session.client('sts')

  if role.startswith('arn:iam'):
    role_session_name = role.split('/')[:-1]
    role_arn = role
  else:
    role_session_name = role
    role_arn = make_arn('iam', path.join('role', role))

  assumedRoleObject = sts_client.assume_role(
    RoleArn=role_arn,
    RoleSessionName=role_session_name
  )
  credentials = assumedRoleObject['Credentials']
  
  log.info('Assuming role %s' % role_arn)
  session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'],
                       region_name=region)
  update_config(credentials_file,
                profile=temp_profile,
                region=region,
                role_arn=role_arn,
                access_key_id=credentials['AccessKeyId'],
                secret_access_key=credentials['SecretAccessKey'],
                session_token=credentials['SessionToken'],
                expiration=credentials['Expiration'])


def update_config(credentials_file, profile, access_key_id=None, secret_access_key=None, session_token=None, role_arn=None, region=None, expiration=None):
  log.info('Updating aws credentials file with profile [%s]' % profile)
  config = configparser.RawConfigParser()
  with open(credentials_file, 'r') as f:
    config.readfp(f)
    config.remove_section(profile)

  with open(credentials_file, 'w') as f:
    config.add_section(profile)
    config.set(profile, 'output', 'json')
    config.set(profile, 'aws_access_key_id', access_key_id)
    config.set(profile, 'aws_secret_access_key', secret_access_key)
    if session_token:
      config.set(profile, 'aws_session_token', session_token)
    if expiration:
      config.set(profile, 'expiration', expiration)
    if role_arn:
      config.set(profile, 'aws_role_arn', role_arn)
    if region:
      config.set(profile, 'region', region)
    config.write(f)


def get_config(config_file=None):
  global config
  if not config_file:
    config_file = 'config.yaml'
  config_path = path.realpath(getcwd())
  if not config:
    env = Environment(loader = FileSystemLoader(config_path), trim_blocks=True, lstrip_blocks=True)
    log.info('Reading configuration file at %s' % path.join(config_path, config_file))
    template = env.get_template(config_file)
    log.debug('Jinja2 parsing %s' % config_file)
    config = load(template.render({
      'USER': environ.get('USER'),
      'HOME': environ.get('HOME'),
      'HOSTNAME': socket.gethostname(),
      'PWD': path.realpath(getcwd())
    }))

  return config

def get_session(temp_profile, credentials_file):
  global session
  
  config = get_config()

  aws_region = config['aws'].get('region')
  aws_profile = config['aws'].get('profile')
  access_key_id = config['aws'].get('access_key_id')
  secret_access_key = config['aws'].get('secret_access_key')

  start_boto_session(temp_profile=temp_profile, credentials_file=credentials_file, profile=aws_profile, access_key_id=access_key_id, secret_access_key=secret_access_key, region=aws_region)
  if 'assume_role' in config['aws']:
    assume_role(config['aws']['assume_role'], temp_profile=temp_profile, credentials_file=credentials_file, region=aws_region, profile=aws_profile)

  return session
