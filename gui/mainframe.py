from tkinter import *
from tkinter import ttk
from main import connect
import json
import os
from awsconnect import AWSCredentialsWindow
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# DASHBOARD data
dashboard_table_count = 0
severity_data = {}
severity_data['High'] = 0
severity_data['Medium'] = 0
severity_data['Low'] = 0
ec2_severities = {'High': 0, 'Medium': 0, 'Low': 0}
s3_severities = {'High': 0, 'Medium': 0, 'Low': 0}
sg_severities = {'High': 0, 'Medium': 0, 'Low': 0}
iam_severities = {'High': 0, 'Medium': 0, 'Low': 0}
services_data = {}
services_data['EC2'] = 0
services_data['S3'] = 0
services_data['Security Groups'] = 0
services_data['IAM'] = 0

# CHECKLIST PROCESSING
# Load list of services for Checklist combobox
operation = "get_list_of_services"
data = {"operation": "get_list_of_services"}
tmp = connect(operation, json.dumps(data))
services_list = json.loads(tmp)
service_checklist = []


def draw_dashboard_canvas(chart, chart_data):
    if chart == "severity":
        colors = ["#f4516c", "#ffb822", "#34bfa3"]

        severity_data['High'] += chart_data['High']
        severity_data['Medium'] += chart_data['Medium']
        severity_data['Low'] += chart_data['Low']

        severity_ax.clear()
        severity_ax.bar(list(severity_data.keys()), list(severity_data.values()), color=colors)
        severity_canvas.draw()
    if chart == "services":
        services_ax.clear()
        services_ax.pie(list(chart_data.values()), labels=list(chart_data.keys()), autopct='%1.1f%%')
        services_canvas.draw()


def update_dashboard_summary():
    total_misconf = 0
    for k, v in services_data.items():
        total_misconf += v
    misconfig_count_label.configure(text=total_misconf)


# Load checklist for selected service
def show_selected(event):
    global operation
    global data
    global tmp
    global service_checklist
    selected_service = check_list_combobox.get()
    operation = "get_service_checklist"
    data = {"operation": "get_service_checklist", "service": selected_service}
    tmp = connect(operation, json.dumps(data))
    service_checklist = json.loads(tmp)

    list_of_lists = []

    for obj in service_checklist:
        obj_text = "\t" + obj[0] + "\n" + obj[1]
        list_of_lists.append(obj_text)

    print(list_of_lists)

    # Remove existing widgets
    try:
        print(info_frame.winfo_children())
        if len(info_frame.winfo_children()) >= 2:
            for widget in info_frame.winfo_children():
                widget.destroy()
        print(info_frame.winfo_children())
    except Exception as e:
        print("Couldn't destroy widgets: ", e)

    # Scrollbar for checklist
    # 1)Create a canvas
    canvas = Canvas(info_frame)
    canvas.pack(side="left", fill="both", expand=1)
    # 2)Add a scrollbar to the canvas
    scroll = ttk.Scrollbar(info_frame, orient="vertical", command=canvas.yview)
    scroll.pack(side="right", fill="y")
    # 3)Configure the canvas
    canvas.configure(yscrollcommand=scroll.set)
    canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    # 4)Create another frame inside the canvas
    inner_frame = ttk.Frame(canvas)
    # 5)Add that new frame to a window in the canvas
    canvas.create_window((0, 0), window=inner_frame, anchor="nw")

    for thing in service_checklist:
        index = service_checklist.index(thing)
        Label(inner_frame, text=list_of_lists[index], wraplength=800, background="#FFFFFF").grid(row=index, sticky="ew",
                                                                                                 column=0, pady=10,
                                                                                                 ipadx=5, ipady=5)


def ec2_enumeration():
    # importing aws credentials
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']

    print(f"SCAN WINDOW\n id: {access_key}\nkey: {secret_key}")

    ec2_instance_id = ec2_entry.get()
    operation = "ec2_enumeration"
    data = {"operation": "ec2_enumeration", "instance_id": ec2_instance_id, "access_key": access_key,
            "secret_key": secret_key}
    tmp = connect(operation, json.dumps(data))
    ec2_enum_lbl["text"] = tmp
    print("Scanning EC2. Please Wait...")


def ec2_misconfiguration():
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    operation = "ec2_misconfiguration"
    data = {"operation": "ec2_misconfiguration", "access_key": access_key, "secret_key": secret_key}
    tmp = connect(operation, json.dumps(data))
    count = 0
    global dashboard_table_count
    global ec2_severities

    # Delete old records from scan tab
    for record in ec2_misconfig_table.get_children():
        ec2_misconfig_table.delete(record)

    for record in dashboard_misconfig_table.get_children():
        service = str(dashboard_misconfig_table.item(record, "values")[0])
        if service == "EC2":
            dashboard_misconfig_table.delete(record)

    # Renew severities count
    severity_data['High'] -= ec2_severities['High']
    severity_data['Medium'] -= ec2_severities['Medium']
    severity_data['Low'] -= ec2_severities['Low']
    ec2_severities['High'] = 0
    ec2_severities['Medium'] = 0
    ec2_severities['Low'] = 0

    # Add records to table in scan and dashboard
    for record in json.loads(tmp):
        ec2_misconfig_table.insert(parent='', index='end', iid=count, text="", values=(record[0], record[-1]))
        count += 1
        dashboard_misconfig_table.insert(parent='', index='end', iid=dashboard_table_count, text="", values=("EC2", record[0], record[-1]))
        dashboard_table_count += 1
        if record[-1] == "High":
            ec2_severities['High'] += 1
        elif record[-1] == "Medium":
            ec2_severities['Medium'] += 1
        else:
            ec2_severities['Low'] += 1
    draw_dashboard_canvas("severity", ec2_severities)
    services_data['EC2'] = len(json.loads(tmp))
    draw_dashboard_canvas("services", services_data)
    update_dashboard_summary()


def s3_misconfiguration():
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    operation = "s3_misconfiguration"
    data = {"operation": "s3_misconfiguration", "access_key": access_key, "secret_key": secret_key}
    tmp = connect(operation, json.dumps(data))
    count = 0
    global dashboard_table_count
    global s3_severities

    # Delete old records
    for record in s3_misconfig_table.get_children():
        s3_misconfig_table.delete(record)

    for record in dashboard_misconfig_table.get_children():
        service = str(dashboard_misconfig_table.item(record, "values")[0])
        if service == "S3":
            dashboard_misconfig_table.delete(record)

    # Renew severities count
    severity_data['High'] -= s3_severities['High']
    severity_data['Medium'] -= s3_severities['Medium']
    severity_data['Low'] -= s3_severities['Low']
    s3_severities['High'] = 0
    s3_severities['Medium'] = 0
    s3_severities['Low'] = 0

    # Add records to table
    for record in json.loads(tmp):
        s3_misconfig_table.insert(parent='', index='end', iid=count, text="", values=(record[0], record[-1]))
        count += 1
        dashboard_misconfig_table.insert(parent='', index='end', iid=dashboard_table_count, text="",
                                         values=("S3", record[0], record[-1]))
        dashboard_table_count += 1

        if record[-1] == "High":
            s3_severities['High'] += 1
        elif record[-1] == "Medium":
            s3_severities['Medium'] += 1
        else:
            s3_severities['Low'] += 1
    draw_dashboard_canvas("severity", s3_severities)
    services_data['S3'] = len(json.loads(tmp))
    draw_dashboard_canvas("services", services_data)
    update_dashboard_summary()

def sg_misconfiguration():
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    operation = "sg_misconfiguration"
    data = {"operation": "sg_misconfiguration", "access_key": access_key, "secret_key": secret_key}
    tmp = connect(operation, json.dumps(data))
    count = 0
    global dashboard_table_count
    global sg_severities

    # Delete old records
    for record in sg_misconfig_table.get_children():
        sg_misconfig_table.delete(record)

    for record in dashboard_misconfig_table.get_children():
        service = str(dashboard_misconfig_table.item(record, "values")[0])
        if service == "Security Groups":
            dashboard_misconfig_table.delete(record)

    # Renew severities count
    severity_data['High'] -= sg_severities['High']
    severity_data['Medium'] -= sg_severities['Medium']
    severity_data['Low'] -= sg_severities['Low']
    sg_severities['High'] = 0
    sg_severities['Medium'] = 0
    sg_severities['Low'] = 0

    # Add records to table
    for record in json.loads(tmp):
        sg_misconfig_table.insert(parent='', index='end', iid=count, text="", values=(record[0], record[-1]))
        count += 1
        dashboard_misconfig_table.insert(parent='', index='end', iid=dashboard_table_count, text="",
                                         values=("Security Groups", record[0], record[-1]))
        dashboard_table_count += 1

        if record[-1] == "High":
            sg_severities['High'] += 1
        elif record[-1] == "Medium":
            sg_severities['Medium'] += 1
        else:
            sg_severities['Low'] += 1
    draw_dashboard_canvas("severity", sg_severities)
    services_data['Security Groups'] = len(json.loads(tmp))
    draw_dashboard_canvas("services", services_data)
    update_dashboard_summary()


def iam_misconfiguration():
    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    operation = "iam_misconfiguration"
    data = {"operation": "iam_misconfiguration", "access_key": access_key, "secret_key": secret_key}
    tmp = connect(operation, json.dumps(data))
    count = 0
    global dashboard_table_count
    global iam_severities

    # Delete old records
    for record in iam_misconfig_table.get_children():
        iam_misconfig_table.delete(record)

    for record in dashboard_misconfig_table.get_children():
        service = str(dashboard_misconfig_table.item(record, "values")[0])
        if service == "IAM":
            dashboard_misconfig_table.delete(record)

    # Renew severities count
    severity_data['High'] -= iam_severities['High']
    severity_data['Medium'] -= iam_severities['Medium']
    severity_data['Low'] -= iam_severities['Low']
    iam_severities['High'] = 0
    iam_severities['Medium'] = 0
    iam_severities['Low'] = 0

    # Add records to table
    for record in json.loads(tmp):
        iam_misconfig_table.insert(parent='', index='end', iid=count, text="", values=(record[0], record[-1]))
        count += 1
        dashboard_misconfig_table.insert(parent='', index='end', iid=dashboard_table_count, text="",
                                         values=("IAM", record[0], record[-1]))
        dashboard_table_count += 1

        if record[-1] == "High":
            iam_severities['High'] += 1
        elif record[-1] == "Medium":
            iam_severities['Medium'] += 1
        else:
            iam_severities['Low'] += 1
    draw_dashboard_canvas("severity", iam_severities)
    services_data['IAM'] = len(json.loads(tmp))
    draw_dashboard_canvas("services", services_data)
    update_dashboard_summary()


def select_scan():
    print(choice.get())
    if choice.get() == "Misconfiguration Check":
        ec2_enum_frame.pack_forget()
        ec2_misconfig_frame.pack(expand=1, fill="both")
    else:
        ec2_enum_frame.pack(expand=1, fill="both")
        ec2_misconfig_frame.pack_forget()


def set_credentials():
    credentials_window.__init__()


def apply_settings():
    credentials_key_lbl['text'] = f"Access Key Id: {os.environ['AWS_ACCESS_KEY_ID']}"

# Create the credentials window and show it
credentials_window = AWSCredentialsWindow()
credentials_window.show()

# Create main window
root = Tk()
root.title("Cloud Scanner")
root.geometry("1000x750")


# Create tab bar
notebook = ttk.Notebook()
notebook.pack(expand=1, fill="both", anchor="center")


# Dashboard tab
dashboard = ttk.Frame(notebook, padding=10)
lbl0 = ttk.Label(dashboard)
lbl0.pack()
dashboard.pack(expand=1, fill="both", padx=5, pady=5)

# Header
header_label = ttk.Label(dashboard, text="Security Scanner", font=("Arial", 16, "bold"))
header_label.pack(pady=10)

# Summary
summary_frame = Frame(dashboard)
summary_frame.pack(side=TOP, fill=X)

resources_label = Label(summary_frame, text="Total Scanned Resources:")
resources_label.pack(side=LEFT)

resources_count_label = Label(summary_frame, text="0")  # Replace with actual count
resources_count_label.pack(side=LEFT, padx=5)

misconfig_label = Label(summary_frame, text="Total Misconfigurations:")
misconfig_label.pack(side=LEFT)

misconfig_count_label = Label(summary_frame, text="0")  # Replace with actual count
misconfig_count_label.pack(side=LEFT, padx=5)

misconfig_frame = Frame(dashboard, width=600)
misconfig_frame.pack(side=LEFT, fill=BOTH, expand=1, padx=10, pady=10)
# Misconfigurations Table
dashboard_misconfig_table = ttk.Treeview(misconfig_frame)
# Define columns
dashboard_misconfig_table['columns'] = ("Service", "Misconfiguration", "Severity level")
# Formate columns
dashboard_misconfig_table.column("#0", width=0, stretch=NO)
dashboard_misconfig_table.column("Service", anchor="w", width=50, minwidth=40)
dashboard_misconfig_table.column("Misconfiguration", anchor="w", width=520, minwidth=80)
dashboard_misconfig_table.column("Severity level", anchor="e", width=60, minwidth=50)
# Create headings
dashboard_misconfig_table.heading("#0", text="", anchor="w")
dashboard_misconfig_table.heading("Service", text="Service", anchor="w")
dashboard_misconfig_table.heading("Misconfiguration", text="Misconfiguration", anchor="w")
dashboard_misconfig_table.heading("Severity level", text="Severity level", anchor="w")

dashboard_misconfig_table.pack(side=LEFT, fill="both", expand=1)


# Charts Frame
charts_frame = Frame(dashboard, width=300)
charts_frame.pack(side=LEFT, fill=BOTH, padx=10, pady=10)

# Bar Chart - Misconfigurations by Severity
severity_frame = Frame(charts_frame)
severity_frame.pack()

severity_label = Label(severity_frame, text="Misconfigurations by Severity:")
severity_label.pack()

# Create a horizontal bar chart using Matplotlib
severity_fig = plt.Figure(figsize=(6, 4), dpi=100)
severity_ax = severity_fig.add_subplot(111)
severity_ax.set_xlabel("Severity")
severity_ax.set_ylabel("Count")
severity_ax.bar(list(severity_data.keys()), list(severity_data.values()))
severity_canvas = FigureCanvasTkAgg(severity_fig, master=severity_frame)
severity_canvas.draw()
severity_canvas.get_tk_widget().pack(fill=X, padx=5)


# Pie Chart - Misconfigurations by Services
services_frame = Frame(charts_frame)
services_frame.pack()

services_label = Label(services_frame, text="Misconfigurations by Services:")
services_label.pack()

# Create a pie chart using Matplotlib
services_fig = plt.Figure(figsize=(6, 4), dpi=100)
services_ax = services_fig.add_subplot(111)
# services_ax.pie(list(services_data.values()), labels=list(services_data.keys()), autopct='%1.1f%%')
services_canvas = FigureCanvasTkAgg(services_fig, master=services_frame)
# services_canvas.draw()
services_canvas.get_tk_widget().pack(fill=X, padx=5)

# Footer
footer_label = ttk.Label(dashboard, text="© 2023 Security Scanner App. All rights reserved.")
footer_label.pack(side="bottom", pady=10)


# Scan tab
scan = ttk.Frame(notebook)
lbl1 = ttk.Label(scan)
lbl1.pack()
scan.pack(expand=1, fill="both", padx=5, pady=5)

scan_notebook = ttk.Notebook(scan, padding=5)
scan_notebook.pack(expand=1, fill="both", anchor="center")

scan_ec2 = ttk.Frame(scan_notebook, padding=5)
scan_s3 = ttk.Frame(scan_notebook, padding=5)
scan_sg = ttk.Frame(scan_notebook, padding=5)
scan_iam = ttk.Frame(scan_notebook, padding=5)

scan_ec2.pack(expand=1, fill="both")
scan_s3.pack(expand=1, fill="both")
scan_sg.pack(expand=1, fill="both")
scan_iam.pack(expand=1, fill="both")

scan_notebook.add(scan_ec2, text="EC2")
scan_notebook.add(scan_s3, text="S3")
scan_notebook.add(scan_sg, text="Security Groups")
scan_notebook.add(scan_iam, text="IAM")

enum = "Enumeration"
misconfig = "Misconfiguration Check"

choice = StringVar(value=enum)

ec2_enum_btn = ttk.Radiobutton(scan_ec2, text=enum, value=enum, variable=choice, command=select_scan)
ec2_misconfig_btn = ttk.Radiobutton(scan_ec2, text=misconfig, value=misconfig, variable=choice, command=select_scan)

ec2_enum_btn.pack(anchor="w")
ec2_misconfig_btn.pack(anchor="w")

# EC2 Enumeration Frame
ec2_enum_frame = ttk.Frame(scan_ec2)
ec2_lbl = ttk.Label(ec2_enum_frame, text="Instance ID: ")
ec2_lbl.grid(row=0, column=0, sticky="w")
ec2_entry = ttk.Entry(ec2_enum_frame)
ec2_entry.grid(row=1, column=0, sticky="w")
ec2_btn1 = ttk.Button(ec2_enum_frame, text="GO!", command=lambda: threading.Thread(target=ec2_enumeration).start())
ec2_btn1.grid(row=2, column=0, sticky="w", pady=5)
ec2_enum_lbl = ttk.Label(ec2_enum_frame, text="Result will be here", padding=10)
ec2_enum_lbl.grid(row=3, column=0, sticky="w", columnspan=3)
ec2_enum_frame.pack(expand=1, fill="both")

# EC2 Misconf frame
ec2_misconfig_frame = ttk.Frame(scan_ec2)
ec2_btn2 = ttk.Button(ec2_misconfig_frame, text="Start Check", command=lambda: threading.Thread(target=ec2_misconfiguration).start())
ec2_btn2.grid(row=0, column=0, sticky="w")
ec2_misconfig_lbl = ttk.Label(ec2_misconfig_frame, padding=10)
ec2_misconfig_lbl.grid(row=1, column=0, sticky="w")
# Output table
ec2_misconfig_table = ttk.Treeview(ec2_misconfig_frame)
# Define columns
ec2_misconfig_table['columns'] = ("Misconfiguration", "Severity level")
# Formate columns
ec2_misconfig_table.column("#0", width=0, stretch=NO)
ec2_misconfig_table.column("Misconfiguration", anchor="w", width=600, minwidth=80)
ec2_misconfig_table.column("Severity level", anchor="e", width=100, minwidth=50)
# Create headings
ec2_misconfig_table.heading("#0", text="", anchor="w")
ec2_misconfig_table.heading("Misconfiguration", text="Misconfiguration", anchor="w")
ec2_misconfig_table.heading("Severity level", text="Severity level", anchor="w")

ec2_misconfig_table.grid(row=2, column=0, sticky=N)

# Text widget for the scan report
report_text = Text(ec2_misconfig_frame, height=20, width=80)
report_text.grid(padx=5, row=2, column=1, sticky=N)

# Example scan report
sample_report = """
=== Security Scan Report ===

Scan ID: SCAN-001
Date: 2023-05-01
Target: EC2 Instance (i-1234567890abcdef0)

Summary:
- Unrestricted SSH Access: Port 22 is open to the public.
- Unencrypted AMI: The AMI used by the instance is not encrypted.
- Insecure Security Group: Security Group SG-12345678 allows unrestricted inbound access to all ports.

Recommendations:
- Restrict SSH access by allowing only specific IP addresses or IP ranges.
- Use encrypted AMIs to ensure data-at-rest encryption.
- Review and tighten the security group rules to limit access to necessary ports and sources.

"""

# Insert the sample report into the text widget
report_text.insert(END, sample_report)

# Disable editing of the report text
report_text.config(state=DISABLED)


# S3 Misconfiguration Frame
s3_misconfig_frame = ttk.Frame(scan_s3)
s3_misconfig_frame.pack(expand=1, fill="both")
s3_btn2 = ttk.Button(s3_misconfig_frame, text="Start Check", command=lambda: threading.Thread(target=s3_misconfiguration).start())
s3_btn2.grid(row=0, column=0, sticky="w")
s3_misconfig_lbl = ttk.Label(s3_misconfig_frame, padding=10)
s3_misconfig_lbl.grid(row=1, column=0, sticky="w")
# Output table
s3_misconfig_table = ttk.Treeview(s3_misconfig_frame)
# Define columns
s3_misconfig_table['columns'] = ("Misconfiguration", "Severity level")
# Formate columns
s3_misconfig_table.column("#0", width=0, stretch=NO)
s3_misconfig_table.column("Misconfiguration", anchor="w", width=520, minwidth=80)
s3_misconfig_table.column("Severity level", anchor="e", width=100, minwidth=50)
# Create headings
s3_misconfig_table.heading("#0", text="", anchor="w")
s3_misconfig_table.heading("Misconfiguration", text="Misconfiguration", anchor="w")
s3_misconfig_table.heading("Severity level", text="Severity level", anchor="w")

s3_misconfig_table.grid(row=2, column=0, sticky=N)

# Text widget for the scan report
report_text = Text(s3_misconfig_frame, height=20, width=80)
report_text.grid(padx=5, row=2, column=1, sticky=N)

# Example scan report
sample_report = """
=== Security Scan Report ===

Scan ID: SCAN-001
Date: 2023-05-01
Target: EC2 Instance (i-1234567890abcdef0)

Summary:
- Unrestricted SSH Access: Port 22 is open to the public.
- Unencrypted AMI: The AMI used by the instance is not encrypted.
- Insecure Security Group: Security Group SG-12345678 allows unrestricted inbound access to all ports.

Recommendations:
- Restrict SSH access by allowing only specific IP addresses or IP ranges.
- Use encrypted AMIs to ensure data-at-rest encryption.
- Review and tighten the security group rules to limit access to necessary ports and sources.

"""

# Insert the sample report into the text widget
report_text.insert(END, sample_report)

# Disable editing of the report text
report_text.config(state=DISABLED)


# Security Groups scan
sg_misconfig_frame = ttk.Frame(scan_sg)
sg_misconfig_frame.pack(expand=1, fill="both")
sg_btn2 = ttk.Button(sg_misconfig_frame, text="Start Check", command=lambda: threading.Thread(target=sg_misconfiguration).start())
sg_btn2.grid(row=0, column=0, sticky="w")
sg_misconfig_lbl = ttk.Label(sg_misconfig_frame, padding=10)
sg_misconfig_lbl.grid(row=1, column=0, sticky="w")
# Output table
sg_misconfig_table = ttk.Treeview(sg_misconfig_frame)
# Define columns
sg_misconfig_table['columns'] = ("Misconfiguration", "Severity level")
# Formate columns
sg_misconfig_table.column("#0", width=0, stretch=NO)
sg_misconfig_table.column("Misconfiguration", anchor="w", width=520, minwidth=80)
sg_misconfig_table.column("Severity level", anchor="e", width=100, minwidth=50)
# Create headings
sg_misconfig_table.heading("#0", text="", anchor="w")
sg_misconfig_table.heading("Misconfiguration", text="Misconfiguration", anchor="w")
sg_misconfig_table.heading("Severity level", text="Severity level", anchor="w")

sg_misconfig_table.grid(row=2, column=0, sticky=N)


# IAM scan tab
iam_misconfig_frame = ttk.Frame(scan_iam)
iam_misconfig_frame.pack(expand=1, fill="both")
iam_btn2 = ttk.Button(iam_misconfig_frame, text="Start Check", command=lambda: threading.Thread(target=iam_misconfiguration).start())
iam_btn2.grid(row=0, column=0, sticky="w")
iam_misconfig_lbl = ttk.Label(iam_misconfig_frame, padding=10)
iam_misconfig_lbl.grid(row=1, column=0, sticky="w")
# Output table
iam_misconfig_table = ttk.Treeview(iam_misconfig_frame)
# Define columns
iam_misconfig_table['columns'] = ("Misconfiguration", "Severity level")
# Formate columns
iam_misconfig_table.column("#0", width=0, stretch=NO)
iam_misconfig_table.column("Misconfiguration", anchor="w", width=520, minwidth=80)
iam_misconfig_table.column("Severity level", anchor="e", width=100, minwidth=50)
# Create headings
iam_misconfig_table.heading("#0", text="", anchor="w")
iam_misconfig_table.heading("Misconfiguration", text="Misconfiguration", anchor="w")
iam_misconfig_table.heading("Severity level", text="Severity level", anchor="w")

iam_misconfig_table.grid(row=2, column=0, sticky=N)


# Checklist tab
check_list = ttk.Frame(notebook, padding=[10, 10, 0, 0])
lbl2 = ttk.Label(check_list)
lbl2.pack()
check_list.pack(expand=1, fill="both")

check_list_combobox = ttk.Combobox(check_list, values=services_list, state="readonly")
check_list_combobox.pack()
check_list_combobox.bind("<<ComboboxSelected>>", show_selected)

info_frame = ttk.Frame(check_list)
info_frame.pack(expand=1, fill="both")

# for thing in service_checklist:
#     index = service_checklist.index(thing)
#     Label(inner_frame, text=list_of_lists[index], wraplength=820, background="#FFFFFF").grid(row=index, sticky="nw", column=0, pady=10)
# for thing in range(100):
# 	Label(inner_frame, text=f'Button {thing} Yo!').grid(row=thing, column=0, pady=10, padx=10)


# History tab
history = ttk.Frame(notebook, padding=10)
lbl3 = ttk.Label(history)
lbl3.pack()
history.pack(expand=1, fill="both", padx=5, pady=5)

# Header
header_label = ttk.Label(history, text="History", font=("Arial", 16, "bold"))
header_label.pack(pady=10)

# Treeview to display scan history
history_treeview = ttk.Treeview(history)
history_treeview["columns"] = ("Scan ID", "Date", "Status")
history_treeview.column("#0", width=0, stretch=NO)
history_treeview.column("Scan ID", anchor=CENTER, width=100)
history_treeview.column("Date", anchor=CENTER, width=150)
history_treeview.column("Status", anchor=CENTER, width=100)

history_treeview.heading("Scan ID", text="Scan ID")
history_treeview.heading("Date", text="Date")
history_treeview.heading("Status", text="Status")

# Insert sample data into the treeview
history_treeview.insert("", "end", text="1", values=("SCAN-001", "2023-05-01", "Completed"))
history_treeview.insert("", "end", text="2", values=("SCAN-002", "2023-05-05", "Completed"))
history_treeview.insert("", "end", text="3", values=("SCAN-003", "2023-05-10", "In Progress"))

history_treeview.pack(pady=10)

# Button for viewing scan details
view_details_button = ttk.Button(history, text="View Details")
view_details_button.pack(pady=10)

# Button for deleting selected scan
delete_scan_button = ttk.Button(history, text="Delete Scan")
delete_scan_button.pack(pady=10)

# Footer
footer_label = ttk.Label(history, text="© 2023 Security Scanner App. All rights reserved.")
footer_label.pack(side=BOTTOM, pady=10)


# Settings tab
settings = ttk.Frame(notebook, padding=10)
lbl4 = ttk.Label(settings)
lbl4.pack()
settings.pack(expand=1, fill="both", padx=5, pady=5)

apply_settings_btn = ttk.Button(settings, text="Apply", command=apply_settings)
apply_settings_btn.pack(anchor="e")

credentials_key_lbl = ttk.Label(settings, text=f"Access Key Id: {os.environ['AWS_ACCESS_KEY_ID']}")
credentials_key_lbl.pack(anchor="w")

set_credentials_btn = ttk.Button(settings, text="Change credentials", command=set_credentials)
set_credentials_btn.pack(anchor="w")

# Adding all tabs to notebook
notebook.add(dashboard, text="Dashboard")
notebook.add(scan, text="Scan")
notebook.add(check_list, text="Checklist")
notebook.add(history, text="History")
notebook.add(settings, text="Settings")

root.mainloop()
