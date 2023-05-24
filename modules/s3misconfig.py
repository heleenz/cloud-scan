import boto3
from botocore.exceptions import ClientError


# Replace with your AWS access key ID and secret access key

def s3_misconfiguration(key_id, secret_key):
    output_list = []
    check = {}
    result_tuple = ()

    # Initialize a boto3 S3 client using the access key ID and secret access key
    s3 = boto3.client('s3', aws_access_key_id=key_id, aws_secret_access_key=secret_key)
    # Get list of all buckets
    response = s3.list_buckets()

    # Check each bucket
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']

        check['checklist_id'] = 14
        # 1. Access Logging Enabled
        response = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' not in response:
            output = 'S3 bucket access logging is not enabled'
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

        check['checklist_id'] = 15
        # 2. S3 Buckets Public Access Block
        try:
            response = s3.get_bucket_acl(Bucket=bucket_name)
            grants = response['Grants']

            for grant in grants:
                grantee = grant['Grantee']
                if 'URI' in grantee and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    output = "Public access is found in bucket ACL"
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
        except:
            pass

        check['checklist_id'] = 16
        # 3. S3 Bucket Default Encryption
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        if 'ServerSideEncryptionConfiguration' not in response:
            output = 'S3 bucket default encryption is not enabled'
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

        check['checklist_id'] = 17
        # 4. S3 HTTPS Only
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            bucket_policy = response['Policy']

            # Check each statement for the NotSecureTransport condition
            for statement in bucket_policy['Statement']:
                if 'Condition' in statement:
                    condition = statement['Condition']
                    if 'NotSecureTransport' in condition:
                        print(f"The S3 bucket '{bucket_name}' has an HTTPS-only policy.")
                    else:
                        output = f"The S3 bucket '{bucket_name}' does not have an HTTPS-only policy."
                        print(output)
                        check['output'] = output
                        result_tuple = (check["checklist_id"], check['output'])
                        output_list.append(result_tuple)
        except:
            output = f"The S3 bucket '{bucket_name}' does not have an HTTPS-only policy."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

        check['checklist_id'] = 18
        # 5. S3 Does Not Allow Public Writes
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            statements = policy['Policy']['Statement']
            for statement in statements:
                if statement['Effect'] == 'Allow' and 's3:PutObject' in statement['Action']:
                    if 'Condition' in statement:
                        conditions = statement['Condition']
                        if 'StringEquals' in conditions:
                            if 's3:x-amz-acl' in conditions['StringEquals'] and conditions['StringEquals'][
                                's3:x-amz-acl'] == 'public-read-write':
                                output = f"Bucket {bucket_name} allows public write access."
                    elif 's3:x-amz-acl' in statement['Principal']:
                        if statement['Principal']['s3:x-amz-acl'] == 'public-read-write':
                            output = f"Bucket {bucket_name} allows public write access."
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
        except:
            pass

        check['checklist_id'] = 19
        # 6. S3 Bucket Authenticated Users WRITE Access
        response = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in response['Grants']:
            if 'URI' in grant['Grantee'] and grant['Grantee'][
                'URI'] == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                if 'WRITE' in grant['Permission']:
                    output = "Warning: S3 Bucket allows WRITE access to AWS authenticated users."
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)

        check['checklist_id'] = 20
        # 7. S3 Bucket MFA Delete Enabled
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        if 'MFADelete' not in response or response['MFADelete'] != 'Enabled':
            output = "Warning: S3 Bucket MFA Delete is not enabled."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

        check['checklist_id'] = 21
        # 8. S3 Bucket Public Access Via Policy
        try:
            response = s3.get_bucket_policy_status(Bucket=bucket_name)
            if response['PolicyStatus']['IsPublic']:
                output = f"S3 Bucket {bucket_name} has public access via bucket policy"
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)
        except:
            pass

        check['checklist_id'] = 22
        # 9. S3 Buckets Encrypted with Customer-Provided CMKs
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        if 'ServerSideEncryptionConfiguration' in response:
            for rule in response['ServerSideEncryptionConfiguration']['Rules']:
                if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms':
                    print("Info: S3 Bucket is encrypted with AWS KMS CMK.")
                else:
                    output = "Warning: S3 Bucket is not encrypted with a customer-provided AWS KMS CMK."
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
        else:
            output = "Warning: S3 Bucket is not encrypted with a customer-provided AWS KMS CMK."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

        check['checklist_id'] = 23
        # 10. S3 Buckets Lifecycle Configuration
        try:
            response = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if 'Rules' not in response:
                output = "Lifecycle Configuration is not configured."
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                output = "Lifecycle Configuration does not exist."
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 24
        # 11. S3 Buckets with Website Configuration Enabled
        try:
            response = s3.get_bucket_website(Bucket=bucket_name)
            output = f"INFORMATIONAL: Bucket {bucket_name} has website configuration enabled."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        except:
            pass

        check['checklist_id'] = 25
        # 12. S3 Object Lock Enabled
        try:
            s3.get_object_lock_configuration(Bucket=bucket_name)
            print(f"S3 bucket {bucket_name} has Object Lock enabled.")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
                output = f"S3 bucket {bucket_name} does not have Object Lock enabled."
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 26
        # 13. S3 Bucket Public FULL_CONTROL Access
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'URI' in grant['Grantee'] and grant['Permission'] == 'FULL_CONTROL':
                    output = "Bucket {} has public FULL_CONTROL access".format(bucket_name)
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
        except:
            pass

        check['checklist_id'] = 27
        # 14. S3 Bucket Authenticated Users FULL_CONTROL Access
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'Type' in grant['Grantee'] and grant['Grantee']['Type'] == 'Group' and \
                        'AuthenticatedUsers' in grant['Grantee']['URI'] and \
                        grant['Permission'] == 'FULL_CONTROL':
                    output = "Bucket {} allows AWS authenticated users FULL_CONTROL access".format(bucket_name)
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
        except:
            pass

            check['checklist_id'] = 28
            # 15. S3 Bucket Public READ Access
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    if 'URI' in grant['Grantee'] and grant['Permission'] == 'READ':
                        output = "Bucket {} has public READ access".format(bucket_name)
                        print(output)
                        check['output'] = output
                        result_tuple = (check["checklist_id"], check['output'])
                        output_list.append(result_tuple)
            except:
                pass

        check['checklist_id'] = 29
        # 16. S3 Bucket Authenticated Users READ Access
        response = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in response['Grants']:
            grantee = grant['Grantee']
            if (grantee['Type'] == 'AmazonCustomerByEmail' or grantee['Type'] == 'CanonicalUser') and grant[
                'Permission'] == 'READ':
                output = 'Bucket has READ access to AWS authenticated users through ACL'
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 30
        # 17. S3 Bucket Public READ_ACP Access
        response = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in response['Grants']:
            grantee = grant['Grantee']
            if (grantee['Type'] == 'Group' and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers' and
                    grant['Permission'] == 'READ_ACP'):
                output = 'Bucket allows public READ_ACP access'
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 31
        # 18. S3 Bucket Authenticated Users READ_ACP Access
        response = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in response['Grants']:
            grantee = grant['Grantee']
            if (grantee['Type'] == 'AmazonCustomerByEmail' or grantee['Type'] == 'CanonicalUser') and grant[
                'Permission'] == 'READ_ACP':
                output = 'Bucket has READ_ACP access to AWS authenticated users through ACL'
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 32
        # 19. S3 Bucket Public WRITE_ACP Access
        response = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in response['Grants']:
            grantee = grant['Grantee']
            if (grantee['Type'] == 'Group' and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers' and
                    grant['Permission'] == 'WRITE_ACP'):
                output = 'Bucket allows public WRITE_ACP access'
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 33
        # 20. S3 Bucket Authenticated Users WRITE_ACP Access
        response = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in response['Grants']:
            grantee = grant['Grantee']
            if (grantee['Type'] == 'AmazonCustomerByEmail' or grantee['Type'] == 'CanonicalUser') and grant[
                'Permission'] == 'WRITE_ACP':
                output = 'Bucket has WRITE_ACP access to AWS authenticated users through ACL'
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

        check['checklist_id'] = 34
        # 21. Server Side Encryption
        # Get the bucket encryption status
        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        # Check if the bucket has Server-Side Encryption enabled
        if 'ServerSideEncryptionConfiguration' not in encryption:
            output = f"S3 Bucket {bucket_name} does not have Server-Side Encryption enabled."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    return output_list

