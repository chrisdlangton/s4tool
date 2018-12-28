import os, logging, colorlog, boto3, socket, logging
from os import path, getcwd, environ
from yaml import load, dump
from jinja2 import Environment, FileSystemLoader


log = logging.getLogger('s4tool')
log.setLevel(logging.INFO)
format_str = '%(asctime)s - %(levelname)-8s - %(message)s'
date_format = '%Y-%m-%d %H:%M:%S'
if os.isatty(2):
  cformat = '%(log_color)s' + format_str
  colors = {'DEBUG': 'reset',
            'INFO': 'bold_blue',
            'WARNING': 'bold_orange',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red'}
  formatter = colorlog.ColoredFormatter(cformat, date_format, log_colors=colors)
else:
  formatter = logging.Formatter(format_str, date_format)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)

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


def start_boto_session(profile=None, region=None):
  global session
  if not session:
    session = boto3.Session(profile_name=profile, region_name=region)


def get_aws_account_id(return_identity=False):
  global session
  sts_client = session.client('sts')

  identity = sts_client.get_caller_identity()
  if return_identity:
    return identity["Account"], identity
  
  return identity["Account"]


def assume_role(role, region=None, profile=None):
  global session
  assume_session = boto3.Session(profile_name=profile, region_name=region)
  sts_client = assume_session.client('sts')

  if role.startswith('arn:iam'):
    role_session_name = role.split('/')[:-1]
    role_arn = role
  else:
    role_session_name = role
    role_arn = make_arn('iam', 'role/%s' % role)

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

def get_config():
  global config
  config_file = 'config.yaml'
  config_path = path.realpath(getcwd())
  if not config:
    env = Environment(loader = FileSystemLoader(config_path), trim_blocks=True, lstrip_blocks=True)
    log.info('Reading configuration file at %s' % path.join(config_path, config_file))
    template = env.get_template(config_file)
    log.info('Jinja2 parsing %s' % config_file)
    config = load(template.render({
      'USER': environ.get('USER'),
      'HOME': environ.get('HOME'),
      'HOSTNAME': socket.gethostname(),
      'PWD': path.realpath(getcwd())
    }))

  return config

def get_session():
  global session
  
  config = get_config()

  aws_region = config['aws'].get('region')
  aws_profile = config['aws'].get('profile')

  start_boto_session(profile=aws_profile, region=aws_region)
  if 'assume_role' in config['aws']:
    assume_role(config['aws']['assume_role'], region=aws_region, profile=aws_profile)

  return session
