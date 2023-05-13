import json
from dbmanager import DBManager
from modules.ec2enum import ec2_enumeration
from modules.ec2misconfig import ec2_misconfiguration


def client_thread(con):
    data = con.recv(1024)
    pd = data.decode()
    pd = json.loads(pd)

    db = DBManager()

    if pd["operation"] == "get_list_of_services":
        services = db.get_list_of_services()
        pd = json.dumps(services)
        con.send(pd.encode())

    elif pd["operation"] == "get_service_checklist":
        checklist = db.get_service_checklist(pd["service"])
        pd = json.dumps(checklist)
        con.send(pd.encode())

    elif pd["operation"] == "ec2_enumeration":
        instance_id = pd["instance_id"]
        key_id = pd["access_key"]
        secret_key = pd["secret_key"]
        print(f"id: {key_id}\nkey: {secret_key}")
        pd = ec2_enumeration(instance_id, key_id, secret_key)

        con.send(pd.encode())

    elif pd["operation"] == "ec2_misconfiguration":
        key_id = pd["access_key"]
        secret_key = pd["secret_key"]
        scan_output = ec2_misconfiguration(key_id, secret_key)
        pd = []
        for i in range(len(scan_output)):
            if scan_output[i][-2] == 1:
                result = db.get_full_scan_output(scan_output[i][0])
                pd.append([scan_output[i][-1], result[0][0], result[0][1], result[0][2]])
        pd = json.dumps(pd)
        con.send(pd.encode())

    con.close()


