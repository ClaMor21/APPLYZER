#CREATED BY CYSEC
import sys
import requests
import json
import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Text, Button, Label, VERTICAL, END

from androguard.core.bytecodes.apk import APK

# Set your VirusTotal API key here
VIRUSTOTAL_API_KEY = 'cabc5965983f934e1aff7a8a97bb5cf541575292adbaed7a6d5268d9d86bdad5'

class ApplyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('Applyzer')
        self.root.geometry('800x600')
        self.root.resizable(False, False)

        # Dark theme colors
        bg_color = "#1E1E1E"  # Background color
        fg_color = "#FFFFFF"  # Text color
        button_bg = "#333333"  # Button background color
        button_fg = "#FFFFFF"  # Button text color

        # Configure the root window background
        self.root.configure(bg=bg_color)

        # Add the title label with dark theme
        self.title = Label(self.root, text="APPLYZER - APK ANALYSIS TOOL", font="Bold 33", bg=bg_color, fg=fg_color)
        self.title.place(x=48, y=15)

        # Text output with dark theme
        self.text_output = Text(self.root, wrap=tk.WORD, height=40, width=60, bg=bg_color, fg=fg_color)
        self.text_output.place(x=180, y=90, width=1600, height=700)
        self.text_output.pack(pady=100)

        # Scrollbar with dark theme
        self.scrollbar = Scrollbar(self.root)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.scrollbar.place(x=700, y=250)

        # Configure text output and scrollbar
        self.text_output.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.text_output.yview)

        # Dark theme buttons
        self.analyze_button = Button(self.root, text='Analyze APK', command=self.analyze_apk, bg=button_bg, fg=button_fg)
        self.analyze_button.place(x=245, y=530)

        self.browse_button = Button(self.root, text='Browse APK', command=self.open_file_dialog, bg=button_bg, fg=button_fg)
        self.browse_button.place(x=105, y=530)

        self.clear_button = Button(self.root, text='Clear', command=self.clear_output, bg=button_bg, fg=button_fg)
        self.clear_button.place(x=600, y=530)

        self.pre_static_analysis_button = Button(self.root, text='Pre-Static Analysis', command=self.pre_static_analysis, bg=button_bg, fg=button_fg)
        self.pre_static_analysis_button.place(x=400, y=530)

        self.save_report_button = Button(self.root, text='Save Report', command=self.save_report, bg=button_bg, fg=button_fg)
        self.save_report_button.place(x=700, y=565)

        self.apk_file = None

    def open_file_dialog(self):
        file_path = filedialog.askopenfilename(filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")])
        if file_path:
            self.apk_file = file_path

    def analyze_apk(self):
        if self.apk_file:
            try:
                a = APK(self.apk_file)
                permissions = a.get_permissions()

                harmful_permissions = [
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.INTERNET1',
                    'android.permission.ACCESS_COARSE_LOCATION',
                    'android.permission.WRITE_CONTACTS',
                    'android.permission.SEND_SMS',
                    'android.permission.WRITE_CALL_LOG',
                    'android.permission.READ_CALL_LOG',
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.CALL_PHONE',
                ]

                self.text_output.delete(1.0, END)
                self.text_output.insert(tk.END, "Analysis Report for: " + self.apk_file + "\n")
                self.text_output.insert(tk.END, "\nPotentially Harmful Permissions:\n")

                for perm in permissions:
                    if perm in harmful_permissions:
                        self.text_output.insert(tk.END, perm + '\n')

                if 'AndroidManifest.xml' in a.get_files():
                    self.text_output.insert(tk.END, "AndroidManifest.xml found\n")
            except AttributeError:
                self.text_output.delete(1.0, END)
                self.text_output.insert(tk.END, "Please select an APK file for analysis.")
        else:
            messagebox.showwarning("No APK File", "Please select an APK file for analysis.")

    def clear_output(self):
        self.text_output.delete(1.0, END)

    def pre_static_analysis(self):
        if self.apk_file:
            try:
                with open(self.apk_file, 'rb') as file:
                    response = self.scan_apk_with_virustotal(file)

                self.text_output.delete(1.0, END)
                self.text_output.insert(tk.END, "Pre-Static Analysis Report for: " + self.apk_file + "\n")
                self.text_output.insert(tk.END, "\nVirusTotal Analysis:\n")
                self.text_output.insert(tk.END, "Response: " + response + '\n')

                # Fetch and display security vendors' analysis with only flagged vendors
                flagged_vendors = self.fetch_flagged_virustotal_vendors(response)
                self.text_output.insert(tk.END, "\nFlagged Security Vendors' Analysis:\n")
                self.text_output.insert(tk.END, flagged_vendors)
            except FileNotFoundError:
                self.text_output.delete(1.0, END)
                self.text_output.insert(tk.END, "Please select an APK file for analysis.")
        else:
            messagebox.showwarning("No APK File", "Please select an APK file for analysis.")

    def scan_apk_with_virustotal(self, file):
        # You can implement your VirusTotal API call here and return the response.
        # Replace this with your actual VirusTotal API integration.

        # For example, you might use requests to send the file to VirusTotal API:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': VIRUSTOTAL_API_KEY}
        files = {'file': file}
        response = requests.post(url, files=files, params=params)
        return response.text

    def fetch_flagged_virustotal_vendors(self, report_response):
        try:
            # Attempt to parse the response as JSON
            response_data = json.loads(report_response)

            # Get the resource ID from the initial scan response
            resource_id = response_data['resource']

            # Fetch security vendors' analysis using the resource ID
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': VIRUSTOTAL_API_KEY}
            params['resource'] = resource_id
            response = requests.get(url, params=params)
            response_data = json.loads(response.text)

            # Extract and format security vendors' analysis for flagged vendors
            analysis_text = "Flagged Security Vendors' Analysis:\n"
            for vendor, result in response_data['scans'].items():
                if result['result']:
                    analysis_text += f"{vendor}: {result['result']}\n"

            return analysis_text
        except json.JSONDecodeError:
            return "Error: Unable to decode JSON response from VirusTotal API"

    def save_report(self):
        if self.text_output.get(1.0, END) == "\n":
            messagebox.showwarning("No Report", "There is no report to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as report_file:
                report_text = self.text_output.get(1.0, END)
                report_file.write(report_text)
            messagebox.showinfo("Report Saved", "The report has been saved successfully.")

def main():
    root = tk.Tk()
    app = ApplyzerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
