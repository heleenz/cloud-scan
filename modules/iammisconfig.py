import datetime
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError


def iam_misconfiguration(key_id, secret_key):
    output_list = []
    check = {}
    result_tuple = ()
# Initialize the boto3 client for IAM
    iam = boto3.client('iam', aws_access_key_id=key_id,
                       aws_secret_access_key=secret_key)

    # Root account MFA
    check["checklist_id"] = 78
    try:
        response = iam.get_account_summary()
        mfa_enabled = response['SummaryMap']['AccountMFAEnabled']

        if mfa_enabled:
            pass
        else:
            output = "Root Account MFA is not enabled. Enable MFA for the root account for enhanced security."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
    except ClientError as e:
         print("Unable to retrieve MFA status for the root account. Error: {}".format(e))

    # Root account password rotation
    check["checklist_id"] = 79
    try:
        response = iam.get_account_password_policy()
        max_password_age = response['PasswordPolicy']['MaxPasswordAge']

        if max_password_age <= 90:
            pass
        else:
            output = "Root Account password rotation policy does not meet the recommended maximum age of 90 days. Update the password rotation policy for enhanced security."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
    except ClientError as e:
        print("Unable to retrieve password policy for the root account. Error: {}".format(e))

    # Minimum admins
    check["checklist_id"] = 80
    admins = iam.list_users(PathPrefix='/admin/')['Users']

    if len(admins) <= 1:
        pass
    else:
        output = "Minimum Admins: Your AWS account should have a minimum number of admins."
        check['output'] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)

    # Too many admins
    check["checklist_id"] = 81
    admins = iam.list_users(PathPrefix='/admin/')['Users']

    if len(admins) > 1:
        output = "Too Many Admins: Your AWS account has too many admins."
        check['output'] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)


    # MFA on user accounts
    check["checklist_id"] = 82
    users = iam.list_users()['Users']

    if users:
        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            print(mfa_devices)
            if len(mfa_devices) == 0:
                output = f"MFA on User Account: MFA is not enabled for user {user['UserName']}."
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    # Access key rotation
    check["checklist_id"] = 83
    access_keys = iam.list_access_keys()['AccessKeyMetadata']

    for access_key in access_keys:
        access_key_id = access_key['AccessKeyId']
        access_key_status = access_key['Status']

        if access_key_status == 'Active':
            output = f"Access Key Rotation: Access key {access_key_id} should be rotated periodically."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)


    # Certificate rotation
    check["checklist_id"] = 84
    certificates = iam.list_server_certificates()['ServerCertificateMetadataList']

    if certificates:
        for certificate in certificates:
            certificate_name = certificate['ServerCertificateName']
            certificate_expiration = certificate['Expiration']

            # Calculate the remaining days until expiration
            remaining_days = (certificate_expiration - datetime.datetime.now()).days

            if remaining_days <= 30:
                output = f"Certificate Rotation: Certificate {certificate_name} should be rotated periodically."
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    # Access keys inactivity
    check["checklist_id"] = 85
    response = iam.list_users()
    users = response['Users']

    # Iterate over each user and check for inactive access keys
    for user in users:
        username = user['UserName']

        # Get all access keys for the user
        response = iam.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']

        # Iterate over each access key and check for inactivity
        for access_key in access_keys:
            access_key_id = access_key['AccessKeyId']
            status = access_key['Status']

            # Check if the access key is inactive
            if status == 'Inactive':
                output = f"Inactive access key found: {access_key_id} for user: {username}"
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    # User console access inactive
    check["checklist_id"] = 86
    response = iam.list_users()
    users = response['Users']

    # Iterate over each user and check for console access activity
    for user in users:
        username = user['UserName']

        # Check if the user has not used the console in the last 90 days
        response = iam.get_user(UserName=username)
        last_used = response['User'].get('PasswordLastUsed')

        if last_used is None:
            output = f"No console access activity found for user: {username}"
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        else:
            # Check if the user has not used the console in the last 90 days
            inactivity_days = (datetime.now() - last_used.replace(tzinfo=None)).days
            if inactivity_days > 90:
                output = f"Inactive console access found for user: {username}"
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)


    # User account service inactivity
    check["checklist_id"] = 87
    response = iam.list_users()
    users = response['Users']

    # Iterate over each user and check for inactivity on services
    for user in users:
        username = user['UserName']

        # Check if the user has any privileges
        response = iam.list_user_policies(UserName=username)
        policies = response['PolicyNames']

        # Flag to track service inactivity
        service_inactive = True

        # Iterate over each policy and check for inactivity on services
        for policy_name in policies:
            response = iam.list_policy_versions(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
            versions = response['Versions']

            # Check if any policy version grants privileges to services
            for version in versions:
                document = iam.get_policy_version(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}",
                                                        VersionId=version['VersionId'])['PolicyVersion']['Document']
                statements = document['Statement']

                # Iterate over each statement and check for service privileges
                for statement in statements:
                    if statement['Effect'] == 'Allow':
                        resources = statement.get('Resource', [])
                        if isinstance(resources, str):
                            resources = [resources]
                        if any(resource.startswith('arn:aws:') for resource in resources):
                            # Service privileges found, set the flag to False
                            service_inactive = False
                            break

                if not service_inactive:
                    break

        # Check if the user has any inactive service privileges
        if service_inactive:
            output = f"Inactive service privileges found for user: {username}"
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)


    # User Inline Policies
    check["checklist_id"] = 88
    response = iam.list_users()
    users = response['Users']

    # Iterate over each user and check for inline policies
    for user in users:
        user_name = user['UserName']

        # Check if the user has inline policies
        response = iam.list_user_policies(UserName=user_name)
        policies = response['PolicyNames']

        if len(policies) > 0:
            output = f"User '{user_name}' has inline policies."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    # User account with multiple access keys
    check["checklist_id"] = 89
    response = iam.list_users()
    users = response['Users']

    # Iterate over each user and check for multiple access keys
    for user in users:
        user_name = user['UserName']

        # Get all access keys for the user
        response = iam.list_access_keys(UserName=user_name)
        access_keys = response['AccessKeyMetadata']

        # Check if the user has multiple access keys
        if len(access_keys) > 1:
            output = f"User '{user_name}' has multiple access keys."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)


    # Inactive Role
    check["checklist_id"] = 90
    response = iam.list_roles()
    roles = response['Roles']

    # Iterate over each role and check for inactivity
    for role in roles:
        role_name = role['RoleName']

        # Check if the role has been used in the last 30 days
        response = iam.get_role(RoleName=role_name)
        last_used = response['Role'].get('RoleLastUsed')

        if last_used is None:
            print(f"Inactive role found: {role_name}")
            # Perform the cleanup operation for the inactive role
            # Uncomment the following line to delete the inactive role
            # iam.delete_role(RoleName=role_name)
        else:
            last_used_date = last_used.get('LastUsedDate')
            if last_used_date is not None:
                last_used_datetime = datetime.strptime(str(last_used_date), "%Y-%m-%d %H:%M:%S+00:00")
                days_since_last_used = (datetime.now() - last_used_datetime).days
                if days_since_last_used > 30:
                    output = f"Inactive role found: {role_name}"
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)
                    # Perform the cleanup operation for the inactive role
                    # Uncomment the following line to delete the inactive role
                    # iam.delete_role(RoleName=role_name)


    # Role Service Inactivity
    check["checklist_id"] = 91
    response = iam.list_roles()
    roles = response['Roles']

    # Iterate over each role and check for service inactivity
    for role in roles:
        role_name = role['RoleName']

        # Check if the role has access to any services
        response = iam.list_role_policies(RoleName=role_name)
        policies = response['PolicyNames']

        # Flag to track service inactivity
        service_inactive = True

        # Iterate over each policy and check for service inactivity
        for policy_name in policies:
            response = iam.get_policy(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
            policy_document = response['Policy']['DefaultVersionId']

            # Get the policy version
            response = iam.get_policy_version(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}",
                                              VersionId=policy_document)
            document = response['PolicyVersion']['Document']
            statements = document['Statement']

            # Iterate over each statement and check for service privileges
            for statement in statements:
                if statement['Effect'] == 'Allow':
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    if any(resource.startswith('arn:aws:') for resource in resources):
                        # Service access found, set the flag to False
                        service_inactive = False
                        break

            if not service_inactive:
                break

        # Check if the role has inactive service access
        if service_inactive:
            output = f"Role '{role_name}' has inactive service access"
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    # Role Inline policies
    check["checklist_id"] = 92
    response = iam.list_roles()
    roles = response['Roles']

    # Iterate over each role and check for inline policies
    for role in roles:
        role_name = role['RoleName']

        # Get inline policies attached to the role
        response = iam.list_role_policies(RoleName=role_name)
        policies = response['PolicyNames']

        # Check if any inline policies are attached to the role
        if policies:
            output = f"Role '{role_name}' has inline policies attached"
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    # ELB Certificate Rotation
    check["checklist_id"] = 93
    elbv2_client = boto3.client('elbv2', region_name='us-east-1', aws_access_key_id=key_id,
                   aws_secret_access_key=secret_key)

    # Get all load balancers
    response = elbv2_client.describe_load_balancers()
    load_balancers = response['LoadBalancers']

    # Iterate over each load balancer and check for certificate rotation
    for lb in load_balancers:
        load_balancer_arn = lb['LoadBalancerArn']

        # Get the SSL/TLS certificate information
        response = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
        listeners = response['Listeners']

        for listener in listeners:
            # Check if the listener uses SSL/TLS
            if listener['Protocol'] == 'HTTPS' or listener['Protocol'] == 'TLS':
                certificate_arn = listener['Certificates'][0]['CertificateArn']

                # Get the certificate details
                response = elbv2_client.describe_certificates(CertificateArns=[certificate_arn])
                certificates = response['Certificates']

                for certificate in certificates:
                    expiration_date = certificate['NotAfter']
                    days_remaining = (expiration_date - datetime.now()).days

                    # Define the threshold for certificate rotation
                    rotation_threshold = 30

                    if days_remaining <= rotation_threshold:
                        output = f"Load balancer '{load_balancer_arn}' requires certificate rotation"
                        check['output'] = output
                        result_tuple = (check["checklist_id"], check['output'])
                        output_list.append(result_tuple)

    # Complex Password Policy
    check["checklist_id"] = 94
    # Get the account's password policy
    try:
        response = iam.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        # Check the various settings of the password policy
        minimum_length = password_policy['MinimumPasswordLength']
        require_uppercase = password_policy['RequireUppercaseCharacters']
        require_lowercase = password_policy['RequireLowercaseCharacters']
        require_numbers = password_policy['RequireNumbers']
        require_symbols = password_policy['RequireSymbols']

        # Define the complexity requirements
        minimum_length_requirement = 8
        require_uppercase_requirement = True
        require_lowercase_requirement = True
        require_numbers_requirement = True
        require_symbols_requirement = True

        # Check if the password policy meets the complexity requirements
        if minimum_length < minimum_length_requirement:
            output = "Password policy does not meet the minimum length requirement."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        if require_uppercase != require_uppercase_requirement:
            output = "Password policy does not require uppercase characters."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        if require_lowercase != require_lowercase_requirement:
            output = "Password policy does not require lowercase characters."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        if require_numbers != require_numbers_requirement:
            output = "Password policy does not require numbers."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        if require_symbols != require_symbols_requirement:
            output = "Password policy does not require symbols."
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
    except:
        pass

    return output_list
