import os, colorlog, logging, argparse
from helpers import make_arn, get_session, get_config, start_boto_session
from os import path
from subprocess import check_output
from os.path import expanduser


def main(credentials_file, temp_profile, log_level=0, config_file=None):
  log = logging.getLogger()

  config = get_config(config_file)
  aws_region = config['aws'].get('region')
  session = get_session(temp_profile, credentials_file)
  profile = config['aws'].get('profile')
  if not profile or config['aws'].get('assume_role'):
    profile = temp_profile

  # print check_output(['aws', '--profile', profile, 's3', 'ls'])
  kms = session.client('kms')
  alias = config['kms']['alias']
  if alias.startswith('arn:aws'):
    alias_arn = alias
  else:
    alias_arn = make_arn('kms', path.join('alias', alias), region=aws_region)
  log.debug(alias_arn)
  log.info('gathering a list of KMS aliases')
  for k in kms.list_aliases()['Aliases']:
    log.info('comparing %s' % k['AliasArn'])
    if alias_arn == k['AliasArn']:
      log.info('found %s' % alias_arn)

  s3 = session.client('s3')
  log.info('gathering a list of S3 buckets')
  for b in s3.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      log.warn('bucket [%s] exists' % b['Name'])


def setup_logging():
  log = logging.getLogger()
  format_str = '%(asctime)s - %(levelname)-8s - %(message)s'
  date_format = '%Y-%m-%d %H:%M:%S'
  if os.isatty(2):
    cformat = '%(log_color)s' + format_str
    colors = {'DEBUG': 'reset',
              'INFO': 'bold_blue',
              'WARNING': 'bold_yellow',
              'ERROR': 'bold_red',
              'CRITICAL': 'bold_red'}
    formatter = colorlog.ColoredFormatter(cformat, date_format, log_colors=colors)
  else:
    formatter = logging.Formatter(format_str, date_format)

  if log_level > 0:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)
  if log_level == 1:
    log.setLevel(logging.CRITICAL)
  if log_level == 2:
    log.setLevel(logging.ERROR)
  if log_level == 3:
    log.setLevel(logging.WARN)
  if log_level == 4:
    log.setLevel(logging.INFO)
  if log_level >= 5:
    log.setLevel(logging.DEBUG)


if __name__ == '__main__':
  CREDS_FILE='%s/.aws/credentials' % expanduser("~")
  parser = argparse.ArgumentParser(description='s4tool')
  parser.add_argument('-f', '--credentials_file', default=CREDS_FILE, help='absolute path to aws credentials file (default: %s)' % CREDS_FILE)
  parser.add_argument('-c', '--config_file', default=None, help='absolute path to s4tool config file')
  parser.add_argument('-p', '--temp_profile', type=str, default='s4tool', help='s4tool will save credentials to leverage the awscli')
  parser.add_argument('-v', action='store_true')
  parser.add_argument('-vv', action='store_true')
  parser.add_argument('-vvv', action='store_true')
  parser.add_argument('-vvvv', action='store_true')
  parser.add_argument('-vvvvv', action='store_true')
  args = parser.parse_args()
  log_level = 0
  if args.v:
    log_level = 1
  elif args.vv:
    log_level = 2
  elif args.vvv:
    log_level = 3
  elif args.vvvv:
    log_level = 4
  elif args.vvvvv:
    log_level = 5
  params = {
    'credentials_file': args.credentials_file,
    'config_file': args.config_file,
    'temp_profile': args.temp_profile,
    'log_level': log_level
  }

  main(**params)
