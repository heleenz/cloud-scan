import tkinter as tk
from tkinter import ttk

# Create the main window
window = tk.Tk()
window.title("Security Scanner - Scan Tab")

# Header
header_label = tk.Label(window, text="Scan Tab", font=("Arial", 16, "bold"))
header_label.pack(pady=10)

# Text widget for the scan report
report_text = tk.Text(window, height=20, width=80)
report_text.pack(padx=10, pady=5)

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
report_text.insert(tk.END, sample_report)

# Disable editing of the report text
report_text.config(state=tk.DISABLED)

# Scrollbar for the text widget
scrollbar = tk.Scrollbar(window)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
report_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=report_text.yview)

# Footer
footer_label = tk.Label(window, text="© 2023 Security Scanner App. All rights reserved.")
footer_label.pack(side=tk.BOTTOM, pady=10)

# Run the main event loop
window.mainloop()
