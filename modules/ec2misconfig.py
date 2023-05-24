import boto3


def ec2_misconfiguration(key_id, secret_key):
    output_list = []
    check = {}
    result_tuple = ()

    # Create EC2 client
    ec2 = boto3.client('ec2', region_name='us-east-1', aws_access_key_id=key_id, aws_secret_access_key=secret_key)

    check["checklist_id"] = 35
    # Check public snapshots
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    for snapshot in snapshots['Snapshots']:
        if snapshot['Public']:
            output = f"Public snapshot found: {snapshot['SnapshotId']}"
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    check["checklist_id"] = 36
    # Check non-public AMIs
    amis = ec2.describe_images(Owners=['self'])
    for ami in amis['Images']:
        if ami['Public']:
            output = f"Public AMI found: {ami['ImageId']}"
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    check["checklist_id"] = 37
    # Check encrypted AMIs
    for ami in amis['Images']:
        block_device_mappings = ami.get('BlockDeviceMappings', [])
        for block_device in block_device_mappings:
            ebs = block_device.get('Ebs', {})
            if not ebs.get('Encrypted'):
                output = f"Unencrypted AMI found: {ami['ImageId']}"
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    check["checklist_id"] = 38
    # Check blacklisted AMIs
    blacklist = ['ami-0123456789abcdef0', 'ami-abcdef0123456789']
    for ami in amis['Images']:
        if ami['ImageId'] in blacklist:
            output = f"Blacklisted AMI found: {ami['ImageId']}"
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    check["checklist_id"] = 39
    # Check if default VPC is in use
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        if vpc['IsDefault']:
            output = "Default VPC in use."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    check["checklist_id"] = 40
    # Scheduled Event
    response = ec2.describe_instance_status(
        Filters=[
            {
                'Name': 'event.code',
                'Values': ['instance-retirement', 'instance-stop']
            },
            {
                'Name': 'instance-state-name',
                'Values': ['running']
            }
        ]
    )

    if len(response['InstanceStatuses']) > 0:
        for instance in response['InstanceStatuses']:
            output = f"Instance {instance['InstanceId']} is scheduled for {instance['Events'][0]['Description']}."
            print(output)
            check['output'] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
    else:
        print("No EC2 instances scheduled for retirement or maintenance.")

    check["checklist_id"] = 41
    # Multiple Security Groups
    response = ec2.describe_instances()

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if len(instance['SecurityGroups']) > 1:
                output = f"Instance {instance['InstanceId']} has multiple security groups attached."
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    check["checklist_id"] = 42
    # EC2 IAM Roles
    response = ec2.describe_instances()

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'IamInstanceProfile' not in instance:
                output = f"IAM access keys are being used by EC2 instance {instance['InstanceId']} instead of IAM roles/instance profiles."
                print(output)
                check['output'] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    check["checklist_id"] = 43
    # Restrict data-tier subnet connectivity to VPC NAT Gateway
    response = ec2.describe_route_tables()
    for table in response['RouteTables']:
        for association in table['Associations']:
            if 'SubnetId' in association:
                subnet_id = association['SubnetId']
                for route in table['Routes']:
                    if 'NatGatewayId' in route:
                        output = f"Data-tier subnet {subnet_id} has unrestricted access to NAT gateway {route['NatGatewayId']}."
                        print(output)
                        check['output'] = output
                        result_tuple = (check["checklist_id"], check['output'])
                        output_list.append(result_tuple)

    check["checklist_id"] = 44
    # Unrestricted ICMP Access
    response = ec2.describe_security_groups()
    for group in response['SecurityGroups']:
        for permission in group['IpPermissions']:
            if permission['IpProtocol'] == 'icmp':
                for ip_range in permission['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        output = f"Security group '{group['GroupName']}' allows unrestricted ICMP access."
                        print(output)
                        check['output'] = output
                        result_tuple = (check["checklist_id"], check['output'])
                        output_list.append(result_tuple)

    check["checklist_id"] = 45
    # Unrestricted Inbound Access on All Uncommon Ports
    response = ec2.describe_security_groups()
    for group in response['SecurityGroups']:
        for permission in group['IpPermissions']:
            if permission['IpProtocol'] == 'tcp':
                for port in range(permission['FromPort'], permission['ToPort'] + 1):
                    if port not in [22, 23, 25, 53, 80, 123, 137, 138, 139, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 9200, 27017, 443, 445]:  # List of common ports
                        for ip_range in permission['IpRanges']:
                            if ip_range['CidrIp'] == '0.0.0.0/0':
                                output = f"Security group {group['GroupName']} allows unrestricted inbound access on port {port}."
                                print(output)
                                check['output'] = output
                                result_tuple = (check["checklist_id"], check['output'])
                                output_list.append(result_tuple)

    # Unrestricted Access to services
    # List of port numbers to check
    ports = [20, 21, 22, 23, 25, 53, 80, 123, 135, 137, 138, 139, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 9200, 27017, 443, 445]

    # List of services corresponding to each port number
    services = ['FTP', 'FTP', 'SSH', 'Telnet', 'SMTP', 'DNS', 'HTTP', 'NTP', 'RPC', 'NetBIOS', 'NetBIOS', 'NetBIOS', 'MsSQL', 'Oracle', 'MySQL', 'RDP', 'PostgreSQL', 'VNC', 'VNC', 'Elasticsearch', 'MongoDB', 'HTTPS', 'CIFS']

    # Get all security groups
    security_groups = ec2.describe_security_groups()['SecurityGroups']

    # Loop through each security group
    for group in security_groups:
        # Loop through each inbound rule in the security group
        for rule in group['IpPermissions']:
            # Check if the rule allows unrestricted access to any of the ports
            if ('FromPort' in rule and 'ToPort' in rule and rule['FromPort'] == rule['ToPort'] and rule['FromPort'] in ports and len(rule['IpRanges']) == 1 and rule['IpRanges'][0]['CidrIp'] == '0.0.0.0/0'):
                # Get the index of the port in the list of ports
                index = ports.index(rule['FromPort'])
                # Print the security group and the corresponding service for the unrestricted port
                output = f"Security Group '{group['GroupName']}' allows unrestricted inbound access to {services[index]} port {ports[index]}"
                print(output)
                check["checklist_id"] = 0
                check["port_service"] = services[index]
                check['output'] = output
                result_tuple = (check["checklist_id"], check["port_service"], check['output'])
                output_list.append(result_tuple)


        # # Loop through each outbound rule in the security group
        # for rule in group['IpPermissionsEgress']:
        #     # Check if the rule allows unrestricted outbound access
        #     if ('IpRanges' in rule and len(rule['IpRanges']) == 1 and rule['IpRanges'][0]['CidrIp'] == '0.0.0.0/0' and rule['IpProtocol'] == '-1'):
        #         # Print the security group for the unrestricted outbound access
        #         print(f"Security Group '{group['GroupName']}' allows unrestricted outbound access")

    check["checklist_id"] = 63
    # Security Group Port Range
    security_groups = ec2.describe_security_groups()

    # Check if there is any security group with a range of ports opened for inbound traffic
    for sg in security_groups['SecurityGroups']:
        for ip_permission in sg['IpPermissions']:
            if 'FromPort' in ip_permission and 'ToPort' in ip_permission:
                from_port = ip_permission['FromPort']
                to_port = ip_permission['ToPort']
                if from_port < to_port:
                    output = f"Security group {sg['GroupName']} ({sg['GroupId']}) has a port range ({from_port}-{to_port}) opened for inbound traffic."
                    print(output)
                    check['output'] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)

    check["checklist_id"] = 64
    # Check if default security group allows public traffic
    default_sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']

    for default_sg in default_sgs:
        if not default_sg['IpPermissions']:
            output = f"Default security group {default_sg['GroupId']} has no inbound rules defined."
            print(output)
        elif any(rule['IpProtocol'] == '-1' and 'CidrIp' in rule and rule['CidrIp'] == '0.0.0.0/0' for rule in default_sg['IpPermissions']):
            output = f"Default security group {default_sg['GroupId']} allows unrestricted inbound access."
            print(output)
            check["output"] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)
        else:
            output = f"Default security group {default_sg['GroupId']} follows AWS security best practices for inbound traffic."
            print(output)

    check["checklist_id"] = 65
    # Check for excessive number of security groups per region
    security_groups = ec2.describe_security_groups()
    security_group_count = len(security_groups['SecurityGroups'])
    if security_group_count > 60:
        output = f"WARNING: Excessive number of security groups({security_group_count}) per region."
        print(output)
        check["output"] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)

    check["checklist_id"] = 66
    # Check for security groups with name prefixed with launch-wizard
    security_groups = ec2.describe_security_groups()['SecurityGroups']
    launch_wizard_sg = [sg for sg in security_groups if sg['GroupName'].startswith('launch-wizard')]
    if launch_wizard_sg:
        output = "WARNING: EC2 security groups prefixed with launch-wizard should not be in use."
        print(output)
        check["output"] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)

    check["checklist_id"] = 67
    # Check for EC2 instance counts
    instance_limit = ec2.describe_account_attributes(AttributeNames=['max-instances'])['AccountAttributes'][0]['AttributeValues'][0]['AttributeValue']
    instance_count = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running']}])['Reservations']
    if len(instance_count) >= int(instance_limit):
        output = f"WARNING: The limit set for the number of EC2 instances({instance_limit}) has been reached."
        print(output)
        check["output"] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)

    check["checklist_id"] = 68
    # Check for security group rules counts
    max_sg_rules = 50
    for sg in security_groups:
        if len(sg['IpPermissions']) + len(sg['IpPermissionsEgress']) > max_sg_rules:
            output = f"WARNING: EC2 security group({sg['GroupName']}) has an excessive number of rules({len(sg['IpPermissions']) + len(sg['IpPermissionsEgress'])})."
            print(output)
            check["output"] = output
            result_tuple = (check["checklist_id"], check['output'])
            output_list.append(result_tuple)

    check["checklist_id"] = 69
    # Check for security groups allowing inbound traffic from RFC-1918 CIDRs
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        for ip in sg['IpPermissions']:
            for cidr in ip.get('IpRanges', []):
                cidr_ip = cidr['CidrIp']
                if any(cidr_ip.startswith(prefix) for prefix in ('10.', '172.16.', '192.168.')):
                    output = f"Security Group {sg['GroupName']} ({sg['GroupId']}) allows inbound traffic from RFC-1918 CIDR {cidr_ip}"
                    print(output)
                    check["output"] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)

    check["checklist_id"] = 70
    # Check for EC2 instances running in public subnets
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            for interface in instance['NetworkInterfaces']:
                subnet_id = interface['SubnetId']
                response = ec2.describe_subnets(SubnetIds=[subnet_id])
                subnet = response['Subnets'][0]
                if subnet['MapPublicIpOnLaunch']:
                    output = f"Instance {instance['InstanceId']} is in a public subnet {subnet_id}"
                    print(output)
                    check["output"] = output
                    result_tuple = (check["checklist_id"], check['output'])
                    output_list.append(result_tuple)

    check["checklist_id"] = 71
    # Check for EC2 instances with blacklisted instance types
    blacklisted_instance_types = ['t1.micro', 'm1.small', 'm1.medium']
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if instance['InstanceType'] in blacklisted_instance_types:
                output = f"Instance {instance['InstanceId']} has a blacklisted instance type {instance['InstanceType']}"
                print(output)
                check["output"] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    check["checklist_id"] = 72
    # Check for unused EC2 key pairs
    response = ec2.describe_key_pairs()
    # Check for unused key pairs
    unused_key_pairs = []
    for key_pair in response['KeyPairs']:
        key_pair_name = key_pair['KeyName']
        response = ec2.describe_instances(Filters=[{'Name': 'key-name', 'Values': [key_pair_name]}])
        if len(response['Reservations']) == 0:
            unused_key_pairs.append(key_pair_name)
    # Print unused key pairs
    if len(unused_key_pairs) != 0:
        output = f"Unused key pairs: {unused_key_pairs}"
        print(output)
        check["output"] = output
        result_tuple = (check["checklist_id"], check['output'])
        output_list.append(result_tuple)

    check["checklist_id"] = 73
    # Check EC2 instance tenancy
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if instance['Placement']['Tenancy'] != 'default':
                output = f"Instance {instance['InstanceId']} has a non-default tenancy {instance['Placement']['Tenancy']}"
                print(output)
                check["output"] = output
                result_tuple = (check["checklist_id"], check['output'])
                output_list.append(result_tuple)

    return output_list
