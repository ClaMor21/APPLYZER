import sys
import requests
import json
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QFileDialog, QMessageBox

from androguard.core.bytecodes.apk import APK

class ApplyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Applyzer')
        self.setGeometry(100, 100, 800, 600)

        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)

        self.analyze_button = QPushButton('Analyze APK', self)
        self.analyze_button.clicked.connect(self.analyze_apk)

        self.browse_button = QPushButton('Browse APK', self)
        self.browse_button.clicked.connect(self.open_file_dialog)

        self.clear_button = QPushButton('Clear', self)
        self.clear_button.clicked.connect(self.clear_output)

        self.pre_static_analysis_button = QPushButton('Pre-Static Analysis', self)
        self.pre_static_analysis_button.clicked.connect(self.pre_static_analysis)

        layout = QVBoxLayout()
        layout.addWidget(self.text_output)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.pre_static_analysis_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def open_file_dialog(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Open APK File", "", "APK Files (*.apk);;All Files (*)", options=options)
        if file_path:
            self.apk_file = file_path

    def analyze_apk(self):
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

            self.text_output.clear()
            self.text_output.append("Analysis Report for: " + self.apk_file)
            self.text_output.append("\nPotentially Harmful Permissions:")

            for perm in permissions:
                if perm in harmful_permissions:
                    self.text_output.append(perm)

            if 'AndroidManifest.xml' in a.get_files():
                self.text_output.append("AndroidManifest.xml found")
        except AttributeError:
            self.text_output.clear()
            self.text_output.append("Please select an APK file for analysis.")

    def clear_output(self):
        self.text_output.clear()

    def pre_static_analysis(self):
        try:
            with open(self.apk_file, 'rb') as file:
                response = self.scan_apk_with_virustotal(file)

            self.text_output.clear()
            self.text_output.append("Pre-Static Analysis Report for: " + self.apk_file)
            self.text_output.append("\nVirusTotal Analysis:")
            self.text_output.append("Response: " + response)

            # Fetch and display security vendors' analysis with only flagged vendors
            flagged_vendors = self.fetch_flagged_virustotal_vendors(response)
            self.text_output.append("\nFlagged Security Vendors' Analysis:")
            self.text_output.append(flagged_vendors)

        except FileNotFoundError:
            self.text_output.clear()
            self.text_output.append("Please select an APK file for analysis.")

    def scan_apk_with_virustotal(self, file):
        # You can implement your VirusTotal API call here and return the response.
        # Replace this with your actual VirusTotal API integration.

        # For example, you might use requests to send the file to VirusTotal API:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': 'cabc5965983f934e1aff7a8a97bb5cf541575292adbaed7a6d5268d9d86bdad5'}
        files = {'file': file}
        response = requests.post(url, files=files, params=params)
        return response.text

    def fetch_flagged_virustotal_vendors(self, report_response):
        # Use your VirusTotal API key to fetch more information about the report.
        # Filter and format the security vendors' analysis to show only flagged vendors.

        # Get the resource ID from the initial scan response
        response_data = json.loads(report_response)
        resource_id = response_data['resource']

        # Fetch security vendors' analysis using the resource ID
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': 'cabc5965983f934e1aff7a8a97bb5cf541575292adbaed7a6d5268d9d86bdad5', 'resource': resource_id}
        response = requests.get(url, params=params)
        response_data = json.loads(response.text)

        # Extract and format security vendors' analysis for flagged vendors
        analysis_text = "Flagged Security Vendors' Analysis:\n"
        for vendor, result in response_data['scans'].items():
            if result['result']:  # Check if the result field is not empty (vendor flagged it)
                analysis_text += f"{vendor}: {result['result']}\n"

        return analysis_text

def main():
    app = QApplication(sys.argv)
    window = ApplyzerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
