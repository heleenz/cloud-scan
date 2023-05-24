import boto3

def sg_misconfiguration(key_id, secret_key):
    output_list = []
    check_result = {}
    result_tuple = ()

    # Initialize Boto3 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    # Enable Flow Logs on VPC
    check_result["checklist_id"] = 1
    response = ec2.describe_flow_logs()
    if len(response['FlowLogs']) == 0:
        # Retrieve VPC ID
        vpc_id = ec2.describe_vpcs()['Vpcs'][0]['VpcId']
        output = f"Flow logs are not enabled on VPC {vpc_id}."
        check_result["output"] = output
        result_tuple = (check_result["checklist_id"], check_result["output"])
        output_list.append(result_tuple)

    # Flow Logs Enabled on Subnet
    check_result["checklist_id"] = 2
    # Describe subnets
    try:
        response = ec2.describe_subnets()
        subnets = response['Subnets']
    except Exception as e:
        print(f"An error occurred while retrieving subnets: {e}")
        subnets = []

    # Check flow logs on subnets
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        flow_logs = subnet.get('FlowLogs', [])
        if len(flow_logs) == 0:
            output = f"Flow logs are not enabled on subnet {subnet_id}."
            check_result["output"] = output
            result_tuple = (check_result["checklist_id"], check_result["output"])
            output_list.append(result_tuple)

    # Unused network ACLs
    check_result["checklist_id"] = 3
    # Describe network ACLs
    try:
        response = ec2.describe_network_acls()
        network_acls = response['NetworkAcls']
    except Exception as e:
        print(f"An error occurred while retrieving network ACLs: {e}")
        network_acls = []

    # Check for unused network ACLs
    unused_acls = []
    for acl in network_acls:
        acl_id = acl['NetworkAclId']
        associations = acl.get('Associations', [])
        if not associations:
            unused_acls.append(acl_id)

    if unused_acls:
        output = f"Unused network ACLs found: {', '.join(unused_acls)}"
        check_result["output"] = output
        result_tuple = (check_result["checklist_id"], check_result["output"])
        output_list.append(result_tuple)

    # Unused Security Groups
    check_result["checklist_id"] = 4
    response = ec2.describe_security_groups()
    if response['SecurityGroups']:
        unused_security_groups = []
        for sg in response['SecurityGroups']:
            response = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
            if len(response['Reservations']) == 0:
                unused_security_groups.append(sg['GroupId'])
        if unused_security_groups:
            output = "Unused Security Groups found: {}".format(unused_security_groups)
            check_result["output"] = output
            result_tuple = (check_result["checklist_id"], check_result["output"])
            output_list.append(result_tuple)

    # Default Security Group
    check_result["checklist_id"] = 5
    # Describe instances
    try:
        response = ec2.describe_instances()
        instances = response['Reservations']
    except Exception as e:
        print(f"An error occurred while retrieving instances: {e}")
        instances = []

    # Check for instances associated with the default security group
    default_group_instances = []
    for instance in instances:
        for group in instance['Instances'][0]['SecurityGroups']:
            if group['GroupName'] == 'default':
                default_group_instances.append(instance['Instances'][0]['InstanceId'])

    if default_group_instances:
        output = "Misconfiguration: EC2 instances are associated with the default security group."
        check_result["output"] = output
        result_tuple = (check_result["checklist_id"], check_result["output"])
        output_list.append(result_tuple)

    # Default Security Group in use and it allows public access
    check_result["checklist_id"] = 6
    response = ec2.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': ['default']
            }
        ]
    )
    if response['SecurityGroups']:
        default_group = response['SecurityGroups'][0]
        group_id = default_group['GroupId']
        ip_permissions = default_group['IpPermissions']
        for permission in ip_permissions:
            if permission.get('IpRanges') and permission['IpRanges'][0]['CidrIp'] == '0.0.0.0/0':
                output = f"Default Security Group (ID: {group_id}) allows public access."
                check_result["output"] = output
                result_tuple = (check_result["checklist_id"], check_result["output"])
                output_list.append(result_tuple)

    # EC2 with Multiple Security Groups
    check_result["checklist_id"] = 7
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    for instance in ec2_instances:
        if len(instance['Instances'][0]['SecurityGroups']) > 5:
            output = "EC2 instance {} has more than 5 Security Groups assigned to it.".format(instance['Instances'][0]['InstanceId'])
            check_result["output"] = output
            result_tuple = (check_result["checklist_id"], check_result["output"])
            output_list.append(result_tuple)

    # Publicly accessible EC2 instances
    check_result["checklist_id"] = 8
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    publicly_accessible_instances = []
    for instance in ec2_instances:
        if 'PublicIpAddress' in instance['Instances'][0]:
            publicly_accessible_instances.append(instance['Instances'][0]['InstanceId'])
    if publicly_accessible_instances:
        output = "EC2 instance {} is publicly accessible.".format(publicly_accessible_instances)
        check_result["output"] = output
        result_tuple = (check_result["checklist_id"], check_result["output"])
        output_list.append(result_tuple)

    # All EC2 instance ports open for external traffic
    check_result["checklist_id"] = 9
    # Get a list of all security groups
    security_groups = ec2.describe_security_groups()
    open_ports_sg = []
    # Iterate through all security groups
    for sg in security_groups['SecurityGroups']:
        # Check if the security group allows all ports
        if sg['IpPermissions'] == [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]:
            open_ports_sg.append(sg['GroupId'])
    if open_ports_sg:
        output = f"Security Group {open_ports_sg} allows all ports to the public!"
        check_result["output"] = output
        result_tuple = (check_result["checklist_id"], check_result["output"])
        output_list.append(result_tuple)

    # All EC2 instance ports open for internal traffic
    check_result["checklist_id"] = 10
    # get all security groups
    sg_response = ec2.describe_security_groups()
    open_ports_sg = []
    # loop through each security group
    for sg in sg_response['SecurityGroups']:
        # get all inbound rules
        ingress_rules = sg['IpPermissions']
        # check if all ports are open for internal traffic
        for ingress_rule in ingress_rules:
            if ingress_rule.get('IpProtocol') == '-1' and ingress_rule.get('UserIdGroupPairs') == [] and ingress_rule.get(
                    'IpRanges') == [{'CidrIp': '10.0.0.0/8'}]:
                open_ports_sg.append(sg['GroupId'])
        if open_ports_sg:
            output = f"All ports are open for internal traffic in security group {open_ports_sg})"
            check_result["output"] = output
            result_tuple = (check_result["checklist_id"], check_result["output"])
            output_list.append(result_tuple)

    # EC2 instance with open ICMP ports:
    check_result["checklist_id"] = 11
    # get all security groups
    sg_response = ec2.describe_security_groups()
    # loop through each security group
    for sg in sg_response['SecurityGroups']:
        # get all inbound rules
        ingress_rules = sg['IpPermissions']
        # check if ICMP is open
        for ingress_rule in ingress_rules:
            if ingress_rule.get('IpProtocol') == 'icmp':
                output = f"ICMP is open in security group {sg['GroupName']} ({sg['GroupId']})"
                check_result["output"] = output
                result_tuple = (check_result["checklist_id"], check_result["output"])
                output_list.append(result_tuple)

    return output_list

# print(ec2_misconfiguration('AKIAVN2VQDPCI5SDRBVL', 'pf5s0GBh46eEJyw15k924iztV6WoMH2AqBe/yCOZ'))