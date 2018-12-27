from helpers import get_session, get_config
from jinja2 import Environment, FileSystemLoader

def main():
  session = get_session()
  config = get_config()
  s3_client = session.client('s3')
  for b in s3_client.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      print 'bucket [%s] exists' % b['Name']


if __name__ == '__main__':
  main()