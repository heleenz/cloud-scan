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
        self.cursor.execute("SELECT checklist.title, checklist.description "
                            "FROM checklist, aws_services "
                            "WHERE checklist.service_id = aws_services.id")
        checklist = []
        for obj in self.cursor.fetchall():
            checklist.append(obj)
        return checklist

    def get_full_scan_output(self, checklist_id):
        statement = "SELECT checklist.title, checklist.description, severity_level.level " \
                    "FROM checklist, severity_level " \
                    "WHERE checklist.id = " + str(checklist_id) + " AND checklist.severity_id = severity_level.id"
        self.cursor.execute(statement)
        result = self.cursor.fetchall()
        return result
