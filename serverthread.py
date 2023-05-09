import json
import os
from dbmanager import DBManager
from modules.ec2enum import start_ec2_scan

key_id = ""
secret_key = ""


def client_thread(con):
    global key_id
    global secret_key
    # Receive data from client
    data = con.recv(1024)
    pd = data.decode()
    pd = json.loads(pd)

    db = DBManager()

    if pd["operation"] == "submit_credentials":
        key_id = pd["access_key"]
        secret_key = pd["secret_key"]
        print("ID: ", key_id)
        print("KEY: ", secret_key)

    elif pd["operation"] == "get_list_of_services":
        services = db.get_list_of_services()
        pd = json.dumps(services)
        con.send(pd.encode())

    elif pd["operation"] == "get_service_checklist":
        checklist = db.get_service_checklist(pd["service"])
        pd = json.dumps(checklist)
        con.send(pd.encode())

    elif pd["operation"] == "start_ec2_scan":
        instance_id = pd["instance_id"]
        pd = start_ec2_scan(instance_id, key_id, secret_key)
        con.send(pd.encode())

    con.close()


