import logging
from helpers import get_session, get_config

def main():
  log = logging.getLogger('s4tool')
  log.info('do argparse')


def setup():
  log = logging.getLogger('s4tool')
  session = get_session()
  config = get_config()
  s3_client = session.client('s3')
  log.info('gathering a list of S3 buckets')
  for b in s3_client.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      log.info('bucket [%s] exists' % b['Name'])


def sync():
  log = logging.getLogger('s4tool')
  session = get_session()
  config = get_config()
  s3_client = session.client('s3')
  log.info('gathering a list of S3 buckets')
  for b in s3_client.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      log.info('found bucket [%s]' % b['Name'])


if __name__ == '__main__':
  main()
  setup()
  sync()