import tkinter as tk
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


# Load checklist for selected service
def show_selected(event):
    global operation
    global data
    global tmp
    selected_service = check_list_combobox.get()
    operation = "get_service_checklist"
    data = {"operation": "get_service_checklist", "service": selected_service}
    tmp = connect(operation, json.dumps(data))
    service_checklist = json.loads(tmp)


# Create the credentials window and show it
credentials_window = AWSCredentialsWindow()
credentials_window.show()

# Create main window
root = tk.Tk()
root.title("Cloud Scanner")
root.geometry("900x500")

# Create tab bar
notebook = ttk.Notebook()
notebook.pack(expand=True, fill="both", anchor="center")


main = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl0 = ttk.Label(main, text="MAIN")
lbl0.pack()
main.pack(expand=True, fill="both", padx=5, pady=5)


scan = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl1 = ttk.Label(scan, text="SCAN")
lbl1.pack()
scan.pack(expand=True, fill="both", padx=5, pady=5)


check_list = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl2 = ttk.Label(check_list, text="CHECKLIST")
lbl2.pack()
check_list.pack(expand=True, fill="both", padx=5, pady=5)

check_list_combobox = ttk.Combobox(check_list, values=services_list, state="readonly")
check_list_combobox.pack()
check_list_combobox.bind("<<ComboboxSelected>>", show_selected)


history = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl3 = ttk.Label(history, text="HISTORY")
lbl3.pack()
history.pack(expand=True, fill="both", padx=5, pady=5)


settings = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
lbl4 = ttk.Label(settings, text="SETTINGS")
lbl4.pack()
settings.pack(expand=True, fill="both", padx=5, pady=5)


notebook.add(main, text="Main")
notebook.add(scan, text="Scan")
notebook.add(check_list, text="Checklist")
notebook.add(history, text="History")
notebook.add(settings, text="Settings")

root.mainloop()

