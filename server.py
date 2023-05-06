import socket
from _thread import *
import serverthread

server = socket.socket()
server.bind(("127.0.0.1", 51708))
server.listen(5)

print("Server running")

while True:
    client, _ = server.accept()
    print("Client connected: ", client)
    start_new_thread(serverthread.client_thread, (client, ))
