import boto3

# Create a Boto3 IAM client
iam = boto3.client('iam')

# Get all IAM users
response = iam.list_users()
users = response['Users']

# Check for users with policies that allow full access
for user in users:
    response = iam.list_attached_user_policies(
        UserName=user['UserName']
    )
    for policy in response['AttachedPolicies']:
        policy_name = policy['PolicyName']
        response = iam.get_policy_version(
            PolicyArn=policy['PolicyArn'],
            VersionId=policy['DefaultVersionId']
        )
        policy_version = response['PolicyVersion']
        if policy_version['IsDefaultVersion'] and policy_version['Document'].get('Statement'):
            for statement in policy_version['Document']['Statement']:
                if statement.get('Effect') == 'Allow' and statement.get('Action') == '*' and statement.get(
                        'Resource') == '*':
                    print(
                        f"User {user['UserName']} has an attached policy '{policy_name}' that allows full access!")

# Check for users with admin privileges
response = iam.list_users()
for user in response['Users']:
    response = iam.list_attached_user_policies(
        UserName=user['UserName']
    )
    for policy in response['AttachedPolicies']:
        policy_name = policy['PolicyName']
        response = iam.get_policy_version(
            PolicyArn=policy['PolicyArn'],
            VersionId=policy['DefaultVersionId']
        )
        policy_version = response['PolicyVersion']
        if policy_version['IsDefaultVersion'] and policy_version['Document'].get('Statement'):
            for statement in policy_version['Document']['Statement']:
                if statement.get('Effect') == 'Allow' and 'admin' in statement.get('Action', '') and statement.get(
                        'Resource') == '*':
                    print(f"User {user['UserName']} has an attached policy '{policy_name}' with admin privileges!")

# Check for roles with admin privileges
response = iam.list_roles()
for role in response['Roles']:
    response = iam.list_attached_role_policies(
        RoleName=role['RoleName']
    )
    for policy in response['AttachedPolicies']:
        policy_name = policy['PolicyName']
        response = iam.get_policy_version(
            PolicyArn=policy['PolicyArn'],
            VersionId=policy['DefaultVersionId']
        )
        policy_version = response['PolicyVersion']
        if policy_version['IsDefaultVersion'] and policy_version['Document'].get('Statement'):
            for statement in policy_version['Document']['Statement']:
                if statement.get('Effect') == 'Allow' and 'admin' in statement.get('Action', '') and statement.get(
                        'Resource') == '*':
                    print(f"Role {role['RoleName']} has an attached policy '{policy_name}' with admin privileges!")

# Check for policies that allow all actions on all resources
response = iam.list_policies(Scope='All')
for policy in response['Policies']:
    response = iam.get_policy_version(
        PolicyArn=policy['Arn'],
        VersionId=policy['DefaultVersionId']
    )
    policy_version = response['PolicyVersion']
    if policy_version['IsDefaultVersion'] and policy_version['Document'].get('Statement'):
        for statement in policy_version['Document']['Statement']:
            if statement.get('Effect') == 'Allow' and statement.get('Action') == '*' and statement.get(
                    'Resource') == '*':
                print(f"Policy '{policy['PolicyName']}' allows all actions on all")
