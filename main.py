import socket


# message = input("Input a text: ")
# client.send(message.encode())
# data = client.recv(1024)
# print("Server sent: ", data.decode())


def connect(operation, data):
    try:
        client = socket.socket()
        client.connect(("127.0.0.1", 51708))

        if operation == "submit_credentials":
            client.send(data.encode())

        client.close()
    except Exception as e:
        print("Client Connection Error: ", e)




