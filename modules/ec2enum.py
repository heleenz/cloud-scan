import boto3
import os


def ec2_enumeration(instance_id, key_id, secret_key):
    scan_output = ""

    # create an EC2 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    os.environ['AWS_ACCESS_KEY_ID'] = key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

    print("ID: ", os.environ['AWS_ACCESS_KEY_ID'])
    print("KEY: ", os.environ['AWS_SECRET_ACCESS_KEY'])

    # Get instance details
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    print("Instance details:")
    print("  ID:", instance['InstanceId'])
    print("  Type:", instance['InstanceType'])
    print("  Launch Time:", instance['LaunchTime'])
    print("  Region:", instance['Placement']['AvailabilityZone'])

    scan_output += "Instance details:\n"
    scan_output += f"  ID: {instance['InstanceId']}\n"
    scan_output += f"  Type: {instance['InstanceType']}\n"
    scan_output += f"  Launch Time: {instance['LaunchTime']}\n"
    scan_output += f"  Region: {instance['Placement']['AvailabilityZone']}\n"

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

        scan_output += f"Security Group details for {group_id}\n"
        scan_output += f"  Group Name: {security_group['GroupName']}\n"
        scan_output += f"  Description: {security_group['Description']}\n"
        scan_output += "  Inbound Rules:\n"

        if 'IpPermissions' not in security_group:
            print("    No rules")
            scan_output += "    No rules"
        else:
            for rule in security_group['IpPermissions']:
                print("    Protocol:", rule['IpProtocol'])
                print("    From Port:", rule.get('FromPort', 'N/A'))
                print("    To Port:", rule.get('ToPort', 'N/A'))
                print("    CIDR Blocks:", rule.get('IpRanges', 'N/A'))

                scan_output += f"    Protocol: {rule['IpProtocol']}\n"
                scan_output += f"    From Port: {rule.get('FromPort', 'N/A')}\n"
                scan_output += f"    To Port: {rule.get('ToPort', 'N/A')}\n"
                scan_output += f"    CIDR Blocks: {rule.get('IpRanges', 'N/A')}\n"

        print("  Outbound Rules:")
        scan_output += "  Outbound Rules:"

        if 'IpPermissionsEgress' not in security_group:
            print("    No rules")
            scan_output += "    No rules"
        else:
            for rule in security_group['IpPermissionsEgress']:
                print("    Protocol:", rule['IpProtocol'])
                print("    From Port:", rule.get('FromPort', 'N/A'))
                print("    To Port:", rule.get('ToPort', 'N/A'))
                print("    CIDR Blocks:", rule.get('IpRanges', 'N/A'))

                scan_output += f"    Protocol: {rule['IpProtocol']}\n"
                scan_output += f"    From Port: {rule.get('FromPort', 'N/A')}\n"
                scan_output += f"    To Port: {rule.get('ToPort', 'N/A')}\n"
                scan_output += f"    CIDR Blocks: {rule.get('IpRanges', 'N/A')}\n"

    return scan_output
