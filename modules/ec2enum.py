import boto3
import os


def ec2_enumeration(instance_id, key_id, secret_key):
    instance_details = {}
    security_group_details = {}
    output_list = []

    # create an EC2 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    # Get instance details
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    instance_details["ID"] = instance['InstanceId']
    instance_details["Type"] = instance['InstanceType']
    instance_details["Launch Time"] = str(instance['LaunchTime'])
    instance_details["Region"] = instance['Placement']['AvailabilityZone']

    # Get security group details
    security_groups = instance['SecurityGroups']
    for group in security_groups:
        group_id = group['GroupId']
        response = ec2.describe_security_groups(GroupIds=[group_id])
        security_group = response['SecurityGroups'][0]

        security_group_details["Group ID"] = group_id
        security_group_details["Group Name"] = security_group['GroupName']
        security_group_details["Description"] = security_group['Description']

        if 'IpPermissions' not in security_group:
            print("    No rules")
        else:
            inbound_list = []
            for rule in security_group['IpPermissions']:
                inbound_list.append({"Protocol": rule['IpProtocol'], "From Port": rule.get('FromPort', 'N/A'), "To Port": rule.get('ToPort', 'N/A'), "CIDR Blocks": rule.get('IpRanges', 'N/A')})

            security_group_details["Inbound Rules"] = inbound_list

        if 'IpPermissionsEgress' not in security_group:
            print("    No rules")
        else:
            outbound_list = []
            for rule in security_group['IpPermissionsEgress']:
                outbound_list.append({"Protocol": rule['IpProtocol'], "From Port": rule.get('FromPort', 'N/A'), "To Port": rule.get('ToPort', 'N/A'), "CIDR Blocks": rule.get('IpRanges', 'N/A')})

            security_group_details["Outbound Rules"] = outbound_list

        output_list.append(instance_details)
        output_list.append(security_group_details)

    return output_list
