import sqlite3


class DBManager:
    def __init__(self):
        self.con = sqlite3.connect("project.db")
        self.cursor = self.con.cursor()

    # Get list of services
    def get_list_of_services(self):
        self.cursor.execute("SELECT service_name FROM aws_services")
        services = []
        for obj in self.cursor.fetchall():
            services.append(obj[0])
        return services

    def get_service_checklist(self, service):
        checklist = []
        statement = "SELECT checklist.title, checklist.description " \
                    "FROM checklist, aws_services " \
                    "WHERE aws_services.service_name = '" + service + "' AND checklist.service_id = aws_services.id"
        print(statement)
        try:
            self.cursor.execute(statement)
            for obj in self.cursor.fetchall():
                checklist.append(obj)
        except Exception as e:
            print(e)
        return checklist

    def get_full_scan_output(self, arg):
        if type(arg) == str:
            statement = "SELECT checklist.title, checklist.description, severity_level.level " \
                        "FROM checklist, severity_level " \
                        "WHERE checklist.title = 'Unrestricted " + str(arg) + " Access' AND checklist.severity_id = severity_level.id"
            print(statement)
            self.cursor.execute(statement)
        else:
            statement = "SELECT checklist.title, checklist.description, severity_level.level " \
                        "FROM checklist, severity_level " \
                        "WHERE checklist.id = " + str(arg) + " AND checklist.severity_id = severity_level.id"
            self.cursor.execute(statement)
        result = self.cursor.fetchall()
        return result
