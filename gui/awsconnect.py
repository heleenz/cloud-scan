import os
import tkinter as tk
from main import connect
import json

# Set AWS credentials as environment variables
#os.environ['AWS_ACCESS_KEY_ID'] = "AKIAVN2VQDPCI5SDRBVL"
#os.environ['AWS_SECRET_ACCESS_KEY'] = "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"


class AWSCredentialsWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.geometry("400x200")
        self.window.title("AWS Key Credentials")

        # Set background color
        self.window.configure(bg="#DADADA")

        # Add labels for access key and secret key
        access_key_label = tk.Label(self.window, text="Access Key:", bg="#DADADA", fg="#202020", font=("Segoe UI", 10))
        access_key_label.place(x=20, y=20)
        secret_key_label = tk.Label(self.window, text="Secret Key:", bg="#DADADA", fg="#202020", font=("Segoe UI", 10))
        secret_key_label.place(x=20, y=70)

        # Add entry boxes for access key and secret key
        self.access_key_entry = tk.Entry(self.window, font=("Segoe UI", 10), bg="#F1F1F1", fg="#202020")
        self.access_key_entry.place(x=140, y=20, width=240, height=30)
        self.secret_key_entry = tk.Entry(self.window, show="*", font=("Segoe UI", 10), bg="#F1F1F1", fg="#202020")
        self.secret_key_entry.place(x=140, y=70, width=240, height=30)

        # Add button to submit credentials
        submit_button = tk.Button(self.window, text="Submit", command=self.submit_credentials, font=("Segoe UI", 10), bg="#F1F1F1", fg="#202020")
        submit_button.place(x=20, y=130, width=360, height=50)

    def submit_credentials(self):
        access_key = self.access_key_entry.get()
        secret_key = self.secret_key_entry.get()

        operation = "submit_credentials"
        data = {"operation": "submit_credentials", "access_key": access_key, "secret_key": secret_key}
        connect(operation, json.dumps(data))

        # Close the window after submitting
        self.window.destroy()

    def show(self):
        self.window.mainloop()
