import boto3


def ec2_misconfiguration(key_id, secret_key):
    output_list = []
    check_result = {}
    result_tuple = ()

    # Initialize Boto3 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    # Enable Flow Logs on VPC
    check_result["checklist_id"] = 1
    response = ec2.describe_flow_logs()
    if len(response['FlowLogs']) == 0:
        print("Flow Logs are not enabled on VPC.")
        check_result["misconfigured"] = 1
        check_result["output"] = "Flow Logs are not enabled on VPC."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    else:
        print("Flow Logs are enabled on VPC.")
        check_result["misconfigured"] = 0
        check_result["output"] = "Flow Logs are enabled on VPC."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # Flow Logs Enabled on Subnet
    check_result["checklist_id"] = 2
    response = ec2.describe_flow_logs()
    if len(response['FlowLogs']) == 0:
        print("Flow Logs are not enabled on Subnet.")
        check_result["misconfigured"] = 1
        check_result["output"] = "Flow Logs are not enabled on Subnet."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    else:
        print("Flow Logs are enabled on Subnet.")
        check_result["misconfigured"] = 0
        check_result["output"] = "Flow Logs are enabled on Subnet."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # Unused network ACLs
    check_result["checklist_id"] = 3
    response = ec2.describe_network_acls()
    if len(response['NetworkAcls']) == 0:
        print("No Network ACLs found.")
        check_result["misconfigured"] = 0
        check_result["output"] = "No Network ACLs found."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    else:
        unused_acls = []
        for acl in response['NetworkAcls']:
            if len(acl['Associations']) == 0:
                unused_acls.append(acl['NetworkAclId'])
        if len(unused_acls) == 0:
            print("All Network ACLs are in use.")
            check_result["misconfigured"] = 0
            check_result["output"] = "All Network ACLs are in use."
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
        else:
            print("Unused Network ACLs found: {}".format(unused_acls))
            check_result["misconfigured"] = 1
            check_result["output"] = "Unused Network ACLs found: {}".format(unused_acls)
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # Unused Security Groups
    check_result["checklist_id"] = 4
    response = ec2.describe_security_groups()
    if len(response['SecurityGroups']) == 0:
        print("No Security Groups found.")
        check_result["misconfigured"] = 0
        check_result["output"] = "No Security Groups found."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    else:
        unused_security_groups = []
        for sg in response['SecurityGroups']:
            response = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg['GroupId']]}])
            if len(response['Reservations']) == 0:
                unused_security_groups.append(sg['GroupId'])
        if len(unused_security_groups) == 0:
            print("All Security Groups are in use.")
            check_result["misconfigured"] = 0
            check_result["output"] = "All Security Groups are in use."
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
        else:
            print("Unused Security Groups found: {}".format(unused_security_groups))
            check_result["misconfigured"] = 1
            check_result["output"] = "Unused Security Groups found: {}".format(unused_security_groups)
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # Default Security Group
    check_result["checklist_id"] = 5
    response = ec2.describe_security_groups(GroupNames=['default'])
    default_security_group = response['SecurityGroups'][0]
    if len(default_security_group['IpPermissions']) == 0 and len(default_security_group['IpPermissionsEgress']) == 0:
        print("Default Security Group is properly configured.")
        check_result["misconfigured"] = 0
        check_result["output"] = "Default Security Group is properly configured."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    else:
        print("Default Security Group is not properly configured.")
        check_result["misconfigured"] = 1
        check_result["output"] = "Default Security Group is not properly configured."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # Default Security Group in use and it allows public access
    check_result["checklist_id"] = 6
    response = ec2.describe_security_groups(GroupNames=['default'])
    default_security_group = response['SecurityGroups'][0]
    for rule in default_security_group['IpPermissions']:
        if rule['IpRanges'] == [{'CidrIp': '0.0.0.0/0'}] or rule['IpRanges'] == [{'CidrIp': '::/0'}]:
            print("Default Security Group allows public access.")
            check_result["misconfigured"] = 1
            check_result["output"] = "Default Security Group allows public access."
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
            break
    else:
        print("Default Security Group is properly configured.")
        check_result["misconfigured"] = 0
        check_result["output"] = "Default Security Group is properly configured."
        result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
    output_list.append(result_tuple)

    # EC2 with Multiple Security Groups
    check_result["checklist_id"] = 7
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    for instance in ec2_instances:
        if len(instance['Instances'][0]['SecurityGroups']) > 5:
            print("EC2 instance {} has more than 5 Security Groups assigned to it.".format(instance['Instances'][0]['InstanceId']))
            check_result["misconfigured"] = 1
            check_result["output"] = "EC2 instance {} has more than 5 Security Groups assigned to it.".format(instance['Instances'][0]['InstanceId'])
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
            output_list.append(result_tuple)

    # Publicly accessible EC2 instances
    check_result["checklist_id"] = 8
    response = ec2.describe_instances()
    ec2_instances = response['Reservations']
    for instance in ec2_instances:
        if 'PublicIpAddress' in instance['Instances'][0]:
            print("EC2 instance {} is publicly accessible.".format(instance['Instances'][0]['InstanceId']))
            check_result["misconfigured"] = 1
            check_result["output"] = "EC2 instance {} is publicly accessible.".format(instance['Instances'][0]['InstanceId'])
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
            output_list.append(result_tuple)

    # All EC2 instance ports open for external traffic
    check_result["checklist_id"] = 9
    # Get a list of all security groups
    security_groups = ec2.describe_security_groups()
    # Iterate through all security groups
    for sg in security_groups['SecurityGroups']:
        # Check if the security group allows all ports
        if sg['IpPermissions'] == [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]:
            print(f"Security Group {sg['GroupId']} allows all ports to the public!")
            check_result["misconfigured"] = 1
            check_result["output"] = f"Security Group {sg['GroupId']} allows all ports to the public!"
            result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
            output_list.append(result_tuple)

    # All EC2 instance ports open for internal traffic
    check_result["checklist_id"] = 10
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
                check_result["misconfigured"] = 1
                check_result["output"] = f"All ports are open for internal traffic in security group {sg['GroupName']} ({sg['GroupId']})"
                result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
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
                print(f"ICMP is open in security group {sg['GroupName']} ({sg['GroupId']})")
                check_result["misconfigured"] = 1
                check_result["output"] = f"ICMP is open in security group {sg['GroupName']} ({sg['GroupId']})"
                result_tuple = (check_result["checklist_id"], check_result["misconfigured"], check_result["output"])
                output_list.append(result_tuple)

    return output_list
