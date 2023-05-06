from tkinter import ttk


def upper_bar_frame():
    frame = ttk.Frame(borderwidth=1, relief="solid", padding=10)

    for c in range(6):
        frame.columnconfigure(index=c, weight=1)
    for r in range(6):
        frame.rowconfigure(index=r, weight=1)

    btn1 = ttk.Button(frame, text="SCAN")
    btn2 = ttk.Button(frame, text="CHECKLIST")
    btn3 = ttk.Button(frame, text="HISTORY")
    btn4 = ttk.Button(frame, text="SETTINGS")
    btn1.grid(column=1, row=0, sticky="ew")
    btn2.grid(column=2, row=0, sticky="nsew")
    btn3.grid(column=3, row=0, sticky="nsew")
    btn4.grid(column=4, row=0, sticky="nsew")


def to_scan():
    scan = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
    lbl = ttk.Label(scan, text="SCAN")
    lbl.pack()
    scan.pack(expand=True, fill="both", padx=5, pady=5)
    # btn1["state"] = "disabled"
    # btn2["state"] = "enabled"
    # btn3["state"] = "enabled"
    # btn4["state"] = "enabled"


def to_checklist():
    check_list = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
    lbl = ttk.Label(check_list, text="CHECKLIST")
    lbl.pack()
    check_list.pack(expand=True, fill="both", padx=5, pady=5)
    # btn1["state"] = "enabled"
    # btn2["state"] = "disabled"
    # btn3["state"] = "enabled"
    # btn4["state"] = "enabled"


def to_history():
    history = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
    lbl = ttk.Label(history, text="HISTORY")
    lbl.pack()
    history.pack(expand=True, fill="both", padx=5, pady=5)
    # btn1["state"] = "enabled"
    # btn2["state"] = "enabled"
    # btn3["state"] = "disabled"
    # btn4["state"] = "enabled"


def to_settings():
    settings = ttk.Frame(notebook, borderwidth=1, relief="solid", padding=10)
    lbl = ttk.Label(settings, text="SETTINGS")
    lbl.pack()
    settings.pack(expand=True, fill="both", padx=5, pady=5)
    # btn1["state"] = "enabled"
    # btn2["state"] = "enabled"
    # btn3["state"] = "enabled"
    # btn4["state"] = "disabled"
