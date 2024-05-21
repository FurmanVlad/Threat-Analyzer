import hashlib
import os
import requests
import tkinter as tk
from tkinter import messagebox


# Function to check the file hash on VirusTotal
def check_hash_on_virustotal(api_key, file_hash):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print('Error: %s' % e)

# Function to download the report from VirusTotal
def download_vt_report(api_key, file_hash):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            # Save the report to a file
            with open(f"{file_hash}_vt_report.txt", "wb") as f:
                f.write(response.content)
            messagebox.showinfo("VirusTotal Report", "Report downloaded successfully.")
        else:
            messagebox.showerror("Error", "Failed to download the report from VirusTotal.")
    except Exception as e:
        print('Error: %s' % e)

# Function to handle button click event for checking file hash
def check_file_hash():
    file_hash = file_hash_entry.get()
    if not file_hash:
        messagebox.showerror("Error", "Please enter a file hash.")
        return
    
    vt_result = check_hash_on_virustotal(vt_api_key_entry.get(), file_hash)

    if vt_result:
        messagebox.showinfo("VirusTotal Report", f"Detections: {vt_result['data']['attributes']['last_analysis_stats']['malicious']}")
    else:
        messagebox.showinfo("VirusTotal Report", "No report available on VirusTotal.")

# Create main application window
root = tk.Tk()
root.title("File Hash Checker")

# Create entry for file hash
tk.Label(root, text="File Hash:").pack()
file_hash_entry = tk.Entry(root, width=50)
file_hash_entry.pack()

# Create entry for VirusTotal API key
tk.Label(root, text="VirusTotal API Key:").pack()
vt_api_key_entry = tk.Entry(root, width=50)
vt_api_key_entry.pack()

# Create button to check file hash
check_button = tk.Button(root, text="Check File Hash", command=check_file_hash)
check_button.pack()

# Create button to download VirusTotal report
download_vt_button = tk.Button(root, text="Download VT Report", command=lambda: download_vt_report(vt_api_key_entry.get(), file_hash_entry.get()))
download_vt_button.pack()

# Run the application
root.mainloop()
