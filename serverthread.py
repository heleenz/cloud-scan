import json
import os


def client_thread(con):
    data = con.recv(1024)
    pd = data.decode()
    pd = json.loads(pd)

    if pd["operation"] == "submit_credentials":
        os.environ['AWS_ACCESS_KEY_ID'] = pd["access_key"]
        os.environ['AWS_SECRET_ACCESS_KEY'] = pd["secret_key"]
        print(os.environ['AWS_SECRET_ACCESS_KEY'])

    con.close()


