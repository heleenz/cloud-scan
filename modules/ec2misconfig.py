import boto3


def ec2_misconfiguration(key_id, secret_key):
    scan_output = ""

    # Initialize Boto3 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    # Enable Flow Logs on VPC
    response = ec2.describe_flow_logs()
    if len(response['FlowLogs']) == 0:
        print("Flow Logs are not enabled on VPC.")
        scan_output += "Flow Logs are not enabled on VPC.\n"
    else:
        print("Flow Logs are enabled on VPC.")
        scan_output += "Flow Logs are enabled on VPC.\n"

    # Flow Logs Enabled on Subnet
    response = ec2.describe_flow_logs()
    if len(response['FlowLogs']) == 0:
        print("Flow Logs are not enabled on Subnet.")
        scan_output += "Flow Logs are not enabled on Subnet.\n"
    else:
        print("Flow Logs are enabled on Subnet.")
        scan_output += "Flow Logs are enabled on Subnet.\n"

    # Unused network ACLs
    response = ec2.describe_network_acls()
    if len(response['NetworkAcls']) == 0:
        print("No Network ACLs found.")
        scan_output += "Flow Logs are enabled on Subnet.\n"
    else:
        unused_acls = []
        for acl in response['NetworkAcls']:
            if len(acl['Associations']) == 0:
                unused_acls.append(acl['NetworkAclId'])
        if len(unused_acls) == 0:
            print("All Network ACLs are in use.")
            scan_output += "All Network ACLs are in use.\n"
        else:
            print("Unused Network ACLs found: {}".format(unused_acls))
            scan_output += "Unused Network ACLs found: {}\n".format(unused_acls)

    # Unused Security Groups
    response = ec2.describe_security_groups()
    if len(response['SecurityGroups']) == 0:
        print("No Security Groups found.")
        scan_output += "No Security Groups found.\n"
    else:
        unused_security_groups = []
        for sg in response['SecurityGroups']:
            response = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
            if len(response['Reservations']) == 0:
                unused_security_groups.append(sg['GroupId'])
        if len(unused_security_groups) == 0:
            print("All Security Groups are in use.")
            scan_output += "All Security Groups are in use.\n"
        else:
            print("Unused Security Groups found: {}".format(unused_security_groups))
            scan_output += "Unused Security Groups found: {}\n".format(unused_security_groups)

    # Default Security Group
    response = ec2.describe_security_groups(GroupNames=['default'])
    default_security_group = response['SecurityGroups'][0]
    if len(default_security_group['IpPermissions']) == 0 and len(default_security_group['IpPermissionsEgress']) == 0:
        print("Default Security Group is properly configured.")
        scan_output += "Default Security Group is properly configured.\n"
    else:
        print("Default Security Group is not properly configured.")
        scan_output += "Default Security Group is not properly configured.\n"

    # Default Security Group in use and it allows public access
    response = ec2.describe_security_groups(GroupNames=['default'])
    default_security_group = response['SecurityGroups'][0]
    for rule in default_security_group['IpPermissions']:
        if rule['IpRanges'] == [{'CidrIp': '0.0.0.0/0'}] or rule['IpRanges'] == [{'CidrIp': '::/0'}]:
            print("Default Security Group allows public access.")
            scan_output += "Default Security Group allows public access.\n"
            break
    else:
        print("Default Security Group is properly configured.")
        scan_output += "Default Security Group is properly configured.\n"

    # EC2 with Multiple Security Groups
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    for instance in ec2_instances:
        if len(instance['Instances'][0]['SecurityGroups']) > 5:
            print("EC2 instance {} has more than 5 Security Groups assigned to it.".format(instance['Instances'][0]['InstanceId']))
            scan_output += "EC2 instance {} has more than 5 Security Groups assigned to it.\n".format(instance['Instances'][0]['InstanceId'])

    # Publicly accessible EC2 instances
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    for instance in ec2_instances:
        if 'PublicIpAddress' in instance['Instances'][0]:
            print("EC2 instance {} is publicly accessible.".format(instance['Instances'][0]['InstanceId']))
            scan_output += "EC2 instance {} is publicly accessible.\n".format(instance['Instances'][0]['InstanceId'])

    # All EC2 instance ports open for external traffic
    # get all security groups
    sg_response = ec2.describe_security_groups()
    # loop through each security group
    for sg in sg_response['SecurityGroups']:
        # get all inbound rules
        ingress_rules = sg['IpPermissions']
        # check if all ports are open for internal traffic
        for ingress_rule in ingress_rules:
            if ingress_rule.get('IpProtocol') == '-1' and ingress_rule.get('UserIdGroupPairs') == [] and ingress_rule.get(
                    'IpRanges') == [{'CidrIp': '10.0.0.0/8'}]:
                print(f"All ports are open for internal traffic in security group {sg['GroupName']} ({sg['GroupId']})")
                scan_output += f"All ports are open for internal traffic in security group {sg['GroupName']} ({sg['GroupId']})\n"

    # EC2 instance with open ICMP ports:
    # get all security groups
    sg_response = ec2.describe_security_groups()
    # loop through each security group
    for sg in sg_response['SecurityGroups']:
        # get all inbound rules
        ingress_rules = sg['IpPermissions']
        # check if ICMP is open
        for ingress_rule in ingress_rules:
            if ingress_rule.get('IpProtocol') == 'icmp':
                print(f"ICMP is open in security group {sg['GroupName']} ({sg['GroupId']})")
                scan_output += f"ICMP is open in security group {sg['GroupName']} ({sg['GroupId']})\n"

    return scan_output
