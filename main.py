import socket


def connect(operation, data):
    try:
        client = socket.socket()
        client.connect(("127.0.0.1", 51708))

        if operation == "get_list_of_services":
            client.send(data.encode())
            services = client.recv(1024).decode()
            return services

        if operation == "get_service_checklist":
            client.send(data.encode())
            checklist = ""
            while True:
                package = client.recv(1024).decode()
                checklist += package
                if not package:
                    break
            return checklist

        if operation == "ec2_enumeration":
            client.send(data.encode())
            scan_info = ""
            while True:
                package = client.recv(1024).decode()
                scan_info += package
                if not package:
                    break
            return scan_info

        if operation == "ec2_misconfiguration":
            client.send(data.encode())
            scan_info = ""
            while True:
                package = client.recv(1024).decode()
                scan_info += package
                if not package:
                    break
            return scan_info

        if operation == "s3_misconfiguration":
            client.send(data.encode())
            scan_info = ""
            while True:
                package = client.recv(1024).decode()
                scan_info += package
                if not package:
                    break
            return scan_info

        if operation == "sg_misconfiguration":
            client.send(data.encode())
            scan_info = ""
            while True:
                package = client.recv(1024).decode()
                scan_info += package
                if not package:
                    break
            return scan_info

        if operation == "iam_misconfiguration":
            client.send(data.encode())
            scan_info = ""
            while True:
                package = client.recv(1024).decode()
                scan_info += package
                if not package:
                    break
            return scan_info

        client.close()

    except Exception as e:
        print("Client Connection Error: ", e)




