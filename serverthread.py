import json
import os
from dbmanager import DBManager


def client_thread(con):
    # Receive data from client
    data = con.recv(1024)
    pd = data.decode()
    pd = json.loads(pd)

    db = DBManager()

    if pd["operation"] == "submit_credentials":
        os.environ['AWS_ACCESS_KEY_ID'] = pd["access_key"]
        os.environ['AWS_SECRET_ACCESS_KEY'] = pd["secret_key"]

    elif pd["operation"] == "get_list_of_services":
        services = db.get_list_of_services()
        pd = json.dumps(services)
        con.send(pd.encode())

    elif pd["operation"] == "get_service_checklist":
        checklist = db.get_service_checklist(pd["service"])
        pd = json.dumps(checklist)
        con.send(pd.encode())

    con.close()


