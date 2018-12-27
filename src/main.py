from helpers import get_session, start_boto_session, assume_role

def main():
  session = get_session()
  s3_client = session.client('s3')
  print s3_client.list_buckets()


if __name__ == '__main__':
  main()  