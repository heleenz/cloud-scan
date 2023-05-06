import boto3

# create an EC2 client
ec2 = boto3.client('ec2', region_name='us-east-1')

# specify the instance ID to scan
instance_id = 'i-0aa0b2f909e636a3b'

# Get instance details
response = ec2.describe_instances(InstanceIds=[instance_id])
instance = response['Reservations'][0]['Instances'][0]
print("Instance details:")
print("  ID:", instance['InstanceId'])
print("  Type:", instance['InstanceType'])
print("  Launch Time:", instance['LaunchTime'])
print("  Region:", instance['Placement']['AvailabilityZone'])

# Get security group details
security_groups = instance['SecurityGroups']
for group in security_groups:
    group_id = group['GroupId']
    response = ec2.describe_security_groups(GroupIds=[group_id])
    security_group = response['SecurityGroups'][0]
    print("Security Group details for", group_id)
    print("  Group Name:", security_group['GroupName'])
    print("  Description:", security_group['Description'])
    print("  Inbound Rules:")
    if 'IpPermissions' not in security_group:
        print("    No rules")
    else:
        for rule in security_group['IpPermissions']:
            print("    Protocol:", rule['IpProtocol'])
            print("    From Port:", rule.get('FromPort', 'N/A'))
            print("    To Port:", rule.get('ToPort', 'N/A'))
            print("    CIDR Blocks:", rule.get('IpRanges', 'N/A'))
    print("  Outbound Rules:")
    if 'IpPermissionsEgress' not in security_group:
        print("    No rules")
    else:
        for rule in security_group['IpPermissionsEgress']:
            print("    Protocol:", rule['IpProtocol'])
            print("    From Port:", rule.get('FromPort', 'N/A'))
            print("    To Port:", rule.get('ToPort', 'N/A'))
            print("    CIDR Blocks:", rule.get('IpRanges', 'N/A'))