import sys, os, colorlog, logging, argparse, json, rsa
from helpers import make_arn, get_session, get_config, start_boto_session, get_aws_account_id, setup_logging
from os import path, getcwd
from subprocess import check_output
from os.path import expanduser


def main(credentials_file, temp_profile, log_level=2, config_file=None):
  setup_logging(log_level)
  log = logging.getLogger()
  pwd = path.realpath(getcwd())

  config = get_config(config_file)
  aws_region = config['aws'].get('region')
  safe_mode = config.get('safe_mode', False)
  log.info('safe_mode %s' % safe_mode)
  session = get_session(temp_profile, credentials_file)
  profile = config['aws'].get('profile')
  if not profile or config['aws'].get('assume_role'):
    profile = temp_profile

  log.debug('test awscli %s', check_output(['aws', '--profile', profile, 's3', 'ls']) )
  kms = session.client('kms')
  kms_key_arn = None
  kms_key_id = config['s3'].get('kms_key_id')
  if kms_key_id:
    if kms_key_id.startswith('arn:aws'):
      kms_key_arn = kms_key_id
    else:
      kms_key_arn = make_arn('kms', kms_key_id, region=aws_region)
    log.debug('kms_key_arn [%s]' % kms_key_arn)
    log.info('gathering a list of KMS aliases')

    found_key = False
    found_alias = False
    if 'key/' in kms_key_arn:
      for k in kms.list_keys()['Keys']:
        log.debug('comparing %s' % k['KeyArn'])
        if kms_key_arn == k['KeyArn']:
          found_key = True
          log.info('found %s' % kms_key_arn)
    elif 'alias/' in kms_key_arn:
      for k in kms.list_aliases()['Aliases']:
        log.debug('comparing %s' % k['AliasArn'])
        if kms_key_arn == k['AliasArn']:
          found_alias = True
          log.info('found %s' % kms_key_arn)
    else:
      log.critical('kms_key_id should be either an alias or key arn')
      sys.exit(1)

    if not found_alias and not found_key:
      if safe_mode:
        log.critical('kms_key_id [%s] could not be found, perhaps try using the full arn in the config' % kms_key_arn)
        sys.exit(1)
      else:
        log.warn('kms_key_id [%s] could not be found, creating resources' % kms_key_arn)
        if 'setup' in config:
          key_origin = config['setup'].get('key_origin')
          key_store_id = config['setup'].get('key_store_id')
          if key_origin == 'AWS_CLOUDHSM' and not key_store_id:
            log.critical('key_store_id is requried when using AWS_CLOUDHSM origin')
            sys.exit(1)
          if config['setup'].get('key_policy'):
            params = {
              'Policy': json.dumps(config['setup']['key_policy']),
              'Origin': key_origin,
              'Description': "s4tool",
              'KeyUsage': 'ENCRYPT_DECRYPT'
            }
            if key_store_id:
              params['CustomKeyStoreId'] = key_store_id
            key = kms.create_key(**params)
        else:
          key = kms.create_key(
            BypassPolicyLockoutSafetyCheck=True,
            Origin=key_origin,
            Description="s4tool",
            KeyUsage='ENCRYPT_DECRYPT')
        key_id = key['KeyMetadata']['KeyId']
        kms_key_arn = key['KeyMetadata']['Arn']
        log.info('Created key with id [%s]' % key_id)
        if key_origin == 'EXTERNAL':
          key_material = config['setup'].get('key_material')
          if not key_material:
            log.critical('key_material is requried when using EXTERNAL origin')
            sys.exit(1)
          log.info('Retrieving ImportToken and PublicKey')
          parameters_for_import = kms.get_parameters_for_import(
              KeyId=key_id,
              WrappingAlgorithm='RSAES_OAEP_SHA_1',
              WrappingKeySpec='RSA_2048',
          )
          with open(path.join(pwd, 'PublicKey.b64'), 'w') as f:
            f.write(parameters_for_import['PublicKey'])
          check_output(['openssl',
                        'enc', '-d', '-base64', '-A',
                        '-in', path.join(pwd, 'PublicKey.b64'),
                        '-out', path.join(pwd, 'PublicKey.bin')])
          with open(path.join(pwd, 'ImportToken.b64'), 'w') as f:
            f.write(parameters_for_import['ImportToken'])
          check_output(['openssl',
                        'enc', '-d', '-base64', '-A',
                        '-in', path.join(pwd, 'ImportToken.b64'),
                        '-out', path.join(pwd, 'ImportToken.bin')])

          log.info('Retrieve key material [%s]' % key_material)
          with open(key_material) as f:
            log.info('Creating crypto envelope')
            check_output(['openssl',
                          'rsautl', '-encrypt', '-oaep', '-pubin', '-keyform', 'DER',
                          '-in', path.join(pwd, key_material),
                          '-inkey', path.join(pwd, 'PublicKey.bin'),
                          '-out', path.join(pwd, 'EncryptedKeyMaterial.bin')])
          log.info('Importing key material envelope to KMS')
          with open('ImportToken.bin', 'rb') as t:
            with open('EncryptedKeyMaterial.bin', 'rb') as f:
              kms.import_key_material(
                KeyId=key_id,
                ImportToken=t.read(),
                EncryptedKeyMaterial=f.read(),
                ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE'
              )

        if 'alias/' in config['s3']['kms_key_id']:
          alias = ''.join(config['s3']['kms_key_id'].split('/')[-1:])
          log.info('Creating alias/%s' % alias)
          kms.create_alias(AliasName='alias/%s' % alias, TargetKeyId=key_id)
        if 'setup' in config and config['setup'].get('enable_key_rotation'):
          log.info('Enabling key rotation')
          kms.enable_key_rotation(KeyId=key_id)

  s3 = session.client('s3')
  log.info('gathering a list of S3 buckets')
  found_bucket = False
  for b in s3.list_buckets()['Buckets']:
    if b['Name'] == config['s3']['bucket']:
      found_bucket = True
      log.info('bucket [%s] exists' % config['s3']['bucket'])
  if safe_mode and not found_bucket:
    log.critical('bucket [%s] could not be found' % config['s3']['bucket'])
    sys.exit(1)
  if not safe_mode and not found_bucket:
    log.warn('bucket [%s] could not be found, creating resources' % config['s3']['bucket'])
    s3.create_bucket(
      Bucket=config['s3']['bucket'],
      CreateBucketConfiguration={
        'LocationConstraint': aws_region
      }
    )
    sse = config['s3'].get('sse')
    if sse == 'aws:kms':
      log.info('Enabling bucket SSE with KMS CMK')
      s3.put_bucket_encryption(Bucket=config['s3']['bucket'],
          ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms','KMSMasterKeyID': kms_key_arn}}]})
    elif sse == 'AES256':
      log.info('Enabling bucket default S3SSE with AES256')
      s3.put_bucket_encryption(Bucket=config['s3']['bucket'],
          ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})

    if 'setup' in config and config['setup'].get('bucket_policy'):
      log.info('Applying bucket policy')
      s3.put_bucket_policy(Bucket=config['s3']['bucket'], Policy=json.dumps(config['setup']['bucket_policy']))


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
