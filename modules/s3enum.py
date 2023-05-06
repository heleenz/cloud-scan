import boto3
from botocore.exceptions import ClientError

# replace with your bucket name
bucket_name = '1908rbucket1'

s3 = boto3.client('s3')

response = s3.get_bucket_acl(Bucket=bucket_name)
print(f"Bucket ACL for {bucket_name}: {response['Grants']}")

# Scan bucket CORS configuration
try:
    response = s3.get_bucket_cors(Bucket=bucket_name)
    print(f"Bucket CORS configuration for {bucket_name}: {response['CORSRules']}")
except ClientError:
    print(f"Bucket {bucket_name} does not have a CORS configuration")

# check bucket versioning
try:
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    if 'Status' in response and response['Status'] == 'Enabled':
        print('Bucket versioning is enabled')
    else:
        print('Bucket versioning is not enabled')
except ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchBucket':
        print(f'Bucket {bucket_name} does not exist')
    else:
        print(f'Error checking bucket versioning: {e}')

# check bucket encryption
response = s3.get_bucket_encryption(Bucket=bucket_name)
if 'ServerSideEncryptionConfiguration' in response:
    rules = response['ServerSideEncryptionConfiguration']['Rules']
    print(f"Bucket encryption rules for {bucket_name}: {rules}")
else:
    print(f"Bucket {bucket_name} does not have server-side encryption enabled")

# check bucket lifecycle configuration
try:
    response = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    if 'Rules' in response and len(response['Rules']) > 0:
        print('Bucket lifecycle configuration exists')
    else:
        print('Bucket lifecycle configuration does not exist')
except ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
        print('Bucket lifecycle configuration does not exist')
    elif e.response['Error']['Code'] == 'NoSuchBucket':
        print(f'Bucket {bucket_name} does not exist')
    else:
        print(f'Error checking bucket lifecycle configuration: {e}')

# check bucket policy
try:
    response = s3.get_bucket_policy(Bucket=bucket_name)
    print(f"Bucket policy for {bucket_name}: {response['Policy']}")
except ClientError:
    print(f"Bucket {bucket_name} does not have a policy")