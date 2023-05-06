import tkinter as tk
from tkinter import ttk
from awsconnect import AWSCredentialsWindow


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

