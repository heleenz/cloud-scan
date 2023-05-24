
from datetime import datetime, timedelta

import boto3
key_id, secret_key = ('AKIAVN2VQDPCI5SDRBVL', 'pf5s0GBh46eEJyw15k924iztV6WoMH2AqBe/yCOZ')
iam = boto3.client('iam', aws_access_key_id=key_id,
                   aws_secret_access_key=secret_key)
#
#
# def create_password_policy():
#
#     # Define the password policy parameters
#     password_policy = {
#         'MinimumPasswordLength': 8,
#         'RequireUppercaseCharacters': True,
#         'RequireLowercaseCharacters': True,
#         'RequireNumbers': True,
#         'RequireSymbols': False,
#         'PasswordReusePrevention': 5,
#         'MaxPasswordAge': 90
#     }
#
#     # Create the password policy
#     iam.update_account_password_policy(**password_policy)
#
# # Example usage
# create_password_policy()




def cleanup_inactive_roles():

    # Get all IAM roles
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
                    print(f"Inactive role found: {role_name}")
                    # Perform the cleanup operation for the inactive role
                    # Uncomment the following line to delete the inactive role
                    # iam.delete_role(RoleName=role_name)

# Example usage
cleanup_inactive_roles()


# ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

#
# def get_aws_account_id():
#     sts_client = boto3.client('sts', aws_access_key_id=key_id, aws_secret_access_key=secret_key)
#     response = sts_client.get_caller_identity()
#     aws_account_id = response['Account']
#
#     return aws_account_id
#
#
# # Example usage
# account_id = get_aws_account_id()
# print("AWS Account ID:", account_id)
#
#
# iam_client = boto3.client('iam', aws_access_key_id=key_id, aws_secret_access_key=secret_key)
#
#
# def is_root_user():
#     current_user = iam_client.get_user()
#     current_user_arn = current_user['User']['Arn']
#     root_user_arn = f'arn:aws:iam::{account_id}:root'  # Replace AWS_ACCOUNT_ID with your actual account ID
#
#     return current_user_arn == root_user_arn
#
#
# # Example usage
# if is_root_user():
#     print("Current user is the account root user.")
# else:
#     print("Current user is not the account root user.")
