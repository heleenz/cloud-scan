import socket


def connect(operation, data):
    try:
        client = socket.socket()
        client.connect(("127.0.0.1", 51708))

        if operation == "submit_credentials":
            client.send(data.encode())

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

        client.close()

    except Exception as e:
        print("Client Connection Error: ", e)




