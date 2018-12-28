import logging, argparse
from helpers import make_arn, get_session, get_config, start_boto_session
from os import path
from subprocess import check_output
from os.path import expanduser


def main(credentials_file, temp_profile, log_level, config_file=None):
  log = logging.getLogger('s4tool')
  log_levels = {'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARNING': logging.WARNING,
                'WARN': logging.WARN,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL}

  log.setLevel(log_levels[log_level])

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
  log.info(alias_arn)
  log.info('gathering a list of KMS aliases')
  for k in kms.list_aliases()['Aliases']:
    log.info('comparing %s' % k['AliasArn'])
    if alias_arn == k['AliasArn']:
      log.info('found %s' % alias_arn)

  s3 = session.client('s3')
  log.info('gathering a list of S3 buckets')
  for b in s3.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      log.info('bucket [%s] exists' % b['Name'])

if __name__ == '__main__':
  CREDS_FILE='%s/.aws/credentials' % expanduser("~")
  parser = argparse.ArgumentParser(description='s4tool')
  parser.add_argument('-f', '--credentials_file', default=CREDS_FILE, help='absolute path to aws credentials file (default: %s)' % CREDS_FILE)
  parser.add_argument('-c', '--config_file', default=None, help='absolute path to s4tool config file')
  parser.add_argument('-p', '--temp_profile', type=str, default='s4tool', help='s4tool will save credentials to leverage the awscli')
  parser.add_argument('-l', '--log_level', type=str, default='INFO')
  args = parser.parse_args()

  main(**args.__dict__)
