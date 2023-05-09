from tkinter import *
from tkinter import ttk
from main import connect
import json
from awsconnect import AWSCredentialsWindow

# CHECKLIST PROCESSING
# Load list of services for Checklist combobox
operation = "get_list_of_services"
data = {"operation": "get_list_of_services"}
tmp = connect(operation, json.dumps(data))
services_list = json.loads(tmp)
service_checklist = []
list_of_lists = []


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

    global list_of_lists

    for obj in service_checklist:
        obj_text = "\t" + obj[0] + "\n" + obj[1]
        list_of_lists.append(obj_text)

    print(list_of_lists)

    #Remove existing widgets
    try:
        print(info_frame.winfo_children())
        if len(info_frame.winfo_children()) >= 2:
            for widget in info_frame.winfo_children():
                widget.destroy()
                # print(widget)
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
        Label(inner_frame, text=list_of_lists[index], wraplength=820, background="#FFFFFF").grid(row=index, sticky="ew",
                                                                                                 column=0, pady=10, ipadx=5, ipady=5)


def start_ec2_scan():
    ec2_instance_id = ec2_entry.get()
    operation = "start_ec2_scan"
    data = {"operation": "start_ec2_scan", "instance_id": ec2_instance_id}
    tmp = connect(operation, json.dumps(data))
    ec2_output_lbl["text"] = tmp
    print("Scanning EC2. Please Wait...")


# Create the credentials window and show it
credentials_window = AWSCredentialsWindow()
credentials_window.show()

# Create main window
root = Tk()
root.title("Cloud Scanner")
root.geometry("900x500")

# Create tab bar
notebook = ttk.Notebook()
notebook.pack(expand=1, fill="both", anchor="center")


# Main tab
main = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl0 = ttk.Label(main, text="MAIN")
lbl0.pack()
main.pack(expand=1, fill="both", padx=5, pady=5)


# Scan tab
scan = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl1 = ttk.Label(scan, text="SCAN")
lbl1.pack()
scan.pack(expand=1, fill="both", padx=5, pady=5)

scan_notebook = ttk.Notebook(scan)
scan_notebook.pack(expand=1, fill="both", anchor="center")

scan_ec2 = ttk.Frame(scan_notebook, borderwidth=1, relief="solid", padding=10)
scan_s3 = ttk.Frame(scan_notebook, borderwidth=1, relief="solid", padding=10)
scan_iam = ttk.Frame(scan_notebook, borderwidth=1, relief="solid", padding=10)

scan_ec2.pack(expand=1, fill="both", padx=5, pady=5)
scan_s3.pack(expand=1, fill="both", padx=5, pady=5)
scan_iam.pack(expand=1, fill="both", padx=5, pady=5)

scan_notebook.add(scan_ec2, text="EC2")
scan_notebook.add(scan_s3, text="S3")
scan_notebook.add(scan_iam, text="IAM")

ec2_lbl = ttk.Label(scan_ec2, text="Instance ID: ")
ec2_lbl.grid(row=0, column=0, sticky="w")
ec2_entry = ttk.Entry(scan_ec2)
ec2_entry.grid(row=1, column=0, sticky="w")
ec2_btn = ttk.Button(scan_ec2, text="GO!", command=start_ec2_scan)
ec2_btn.grid(row=2, column=0, sticky="w", pady=5)

ec2_output_lbl = ttk.Label(scan_ec2, text="Result will be here", padding=10, borderwidth=1, relief="solid")
ec2_output_lbl.grid(row=3, column=0, sticky="w", columnspan=3)

# Checklist tab
check_list = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=[10, 10, 0, 0])
lbl2 = ttk.Label(check_list, text="CHECKLIST")
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
history = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl3 = ttk.Label(history, text="HISTORY")
lbl3.pack()
history.pack(expand=1, fill="both", padx=5, pady=5)


# Settings tab
settings = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl4 = ttk.Label(settings, text="SETTINGS")
lbl4.pack()
settings.pack(expand=1, fill="both", padx=5, pady=5)


# Adding all tabs to notebook
notebook.add(main, text="Main")
notebook.add(scan, text="Scan")
notebook.add(check_list, text="Checklist")
notebook.add(history, text="History")
notebook.add(settings, text="Settings")

root.mainloop()
