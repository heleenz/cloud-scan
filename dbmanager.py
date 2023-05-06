import sqlite3

con = sqlite3.connect("project.db")
cursor = con.cursor()


cursor.execute("SELECT * FROM checklist")

