import boto3

# Initialize the boto3 client for IAM
iam = boto3.client('iam', aws_access_key_id="AKIAVN2VQDPCI5SDRBVL", aws_secret_access_key="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")

# Check if root account has access keys
access_key_metadata = iam.list_access_keys(UserName='root')['AccessKeyMetadata']
if len(access_key_metadata) > 0:
    print('Root account has access keys. Consider removing them.')

# Check if root account access keys are rotated
access_key_last_rotated = sorted(access_key_metadata, key=lambda x: x['CreateDate'], reverse=True)[0]['CreateDate']
if (datetime.datetime.now(access_key_last_rotated.tzinfo) - access_key_last_rotated).days > 90:
    print('Root account access keys are not rotated. Consider rotating them.')

# Check if root account has a certificate
certs = iam.list_signing_certificates(UserName='root')['Certificates']
if len(certs) > 0:
    print('Root account has a certificate. Consider removing it.')

# Check if root account certificate is rotated
cert_last_rotated = sorted(certs, key=lambda x: x['UploadDate'], reverse=True)[0]['UploadDate']
if (datetime.datetime.now(cert_last_rotated.tzinfo) - cert_last_rotated).days > 90:
    print('Root account certificate is not rotated. Consider rotating it.')

# Check if root account has MFA enabled
mfa_devices = iam.list_mfa_devices(UserName='root')['MFADevices']
if len(mfa_devices) == 0:
    print('Root account does not have MFA enabled. Consider enabling it.')
