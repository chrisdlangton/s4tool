# s4tool
AWS S3 Syncronisation (S4) Tool

# Contents

1. [Install](#install)

2. [Usage](#usage)
    - [Debug](#debug)
    - [Options](#options)

3. [Third Example](#third-example)

## Install

1. `git clone git@github.com:chrisdlangton/s4tool.git; cd s4tool`

2. `cp bin/s4tool /usr/local/bin/`

3. create a config in `~/.s4tool` with the following basic values;

```yaml
aws:
  access_key_id: ABCDEF123ABCDEF123
  secret_access_key: abcdefabcdefabcdefabcdefabcdefabcdef

s3:
  bucket: bucketname

files:
  - '{{ HOME }}/Documents'
  - '{{ HOME }}/Pictures'
```

or copy the sample one `cp sample.yaml ~/.s4tool` and change the key, secret, bucket, and files values

NOTE: when running in EC2 use an instance role, do not define key and secret here.

## Usage

Simply type in the terminal `s4tool`

### Debug

Standard python logging is used, to get more levels of verbosity just use `s4tool -v` or `s4tool -vv`, keep adding v's up[ to 5 times.]

### Options

Type `s4tool -h` to see the available cli arguments;

- use `-f` or `--credentials_file` CREDENTIALS_FILE
  absolute path to aws credentials file (default: /home/kde/.aws/credentials)
- use `-c` or `--config_file` CONFIG_FILE
  absolute path to s4tool config file
- use `-p` or `--temp_profile` TEMP_PROFILE
  s4tool will save credentials to leverage the awscli

## Additional cli options for sync

Use a dict instead of string for `files` values;

```yaml
files:
  - '{{ HOME }}/Documents'
  - path: '{{ HOME }}/Pictures'
    extra_options: '--no-progress'
```

you can also use a list for `extra_options`

```yaml
files:
  - '{{ HOME }}/Documents'
  - path: '{{ HOME }}/Pictures'
    extra_options:
      - '--no-progress'
      - '--acl'
      - 'bucket-owner-full-control'
```

See: https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html

## Configuration

Changing yaml values in `~/.s4tool` (or a file when passing the `--config_file` argument) provides several features;

### Encryption

For AES256 S3 server-side encryption (S3SSE) where the AWS managed key is used you can add the following;

```yaml
s3:
  sse: AES256
```

Or for KMS CMK (Customer manage key) SSE add the following;

```yaml
s3:
  sse: 'aws:kms'
  kms_key_id: 'your key arn or name or alias'
```

The `kms_key_id` is only needed when using `sse: 'aws:kms'` and can be the ARN of the KMS key, or an Alias. also if the key is in the same account as you are currently authorised with (access key or assumed role) then you can just use the kms key or alias name by itself, s4tool will build the ARN for you.

### Set the aws profile

To use a local profile for Auth instead of key and secret

Add the yaml value

```yaml
aws:
  profile: chris
```

### Assume Role

Assume a role instead of using key and secret

Add the yaml value

```yaml
aws:
  assume_role: full-admin
  assume_role_duration: 43200
```

Notice the optional duration, this is a max value of 43200 or what is set in the IAM role, which ever is less.

### Set the default region

Add the yaml value

```yaml
aws:
  region: ap-southeast-2
```

## safe mode

By default this is `safe_mode: False`. You can let s4tool create AWS Resources for you if you have set `safe_mode: True`.

For the basic bucket and/or KMS key creation just use the above configuration values.

## Creating a bucket with a bucket policy

The following is an example bucket policy configuration

```yaml
setup:
  bucket_policy:
    Version: '2012-10-17'
    Id: PutObjPolicy
    Statement:
      - Sid: DenyUnEncryptedObjectUploads
        Effect: Deny
        Principal: "*"
        Action: s3:PutObject
        Resource: arn:aws:s3:::backup-name/*
        Condition:
          StringNotEquals:
            s3:x-amz-server-side-encryption: aws:kms
      - Sid: DenyPlaintextRequests
        Effect: Deny
        Principal:
          AWS: "*"
        Action: s3:*
        Resource: arn:aws:s3:::backup-name/*
        Condition:
          Bool:
            aws:SecureTransport: 'false'
```

## Creating a KMS key with rotation

You can enable the AWS managed KMS key rotation when the KMS key material origin is AWS_KMS (default)

```yaml
setup:
  enable_key_rotation: True
```

## Creating a KMS CMK

You can create a CMK with the following

```yaml
setup:
  key_origin: EXTERNAL
  key_material: awscmk.key
```

Assuming you have a key material with that name. You can test this using `dd if=/dev/urandom bs=32 count=1 of=awscmk.key` on Linux to create a key material.

NOTE: In production it is recommended you use a CA or HSM to generate the key material for KMS CMK.

## Creating a KMS key with a policy

The following is an example key policy configuration

```yaml
setup:
  key_policy:
    Version: '2012-10-17'
    Id: s4tool-keypolicy
    Statement:
      - Sid: Enable IAM User Permissions
        Effect: Allow
        Principal:
          AWS: arn:aws:iam::123456789100:root
        Action: kms:*
        Resource: "*"
      - Sid: Allow access for Key Administrators
        Effect: Allow
        Principal:
          AWS:
            - arn:aws:iam::123456789100:user/chris
            - arn:aws:iam::123456789100:role/full-admin
        Action:
          - kms:Create*
          - kms:Describe*
          - kms:Enable*
          - kms:List*
          - kms:Put*
          - kms:Update*
          - kms:Revoke*
          - kms:Disable*
          - kms:Get*
          - kms:Delete*
          - kms:TagResource
          - kms:UntagResource
          - kms:ScheduleKeyDeletion
          - kms:CancelKeyDeletion
        Resource: "*"
      - Sid: Allow use of the key
        Effect: Allow
        Principal:
          AWS:
            - arn:aws:iam::123456789100:user/chris
            - arn:aws:iam::123456789100:role/full-admin
            - arn:aws:iam::123456789100:root
        Action:
          - kms:Encrypt
          - kms:Decrypt
          - kms:ReEncrypt*
          - kms:GenerateDataKey*
          - kms:DescribeKey
        Resource: "*"
      - Sid: Allow attachment of persistent resources
        Effect: Allow
        Principal:
          AWS:
            - arn:aws:iam::123456789100:user/chris
            - arn:aws:iam::123456789100:role/full-admin
            - arn:aws:iam::123456789100:root
        Action:
          - kms:CreateGrant
          - kms:ListGrants
          - kms:RevokeGrant
        Resource: "*"
        Condition:
          Bool:
            kms:GrantIsForAWSResource: 'true'
```