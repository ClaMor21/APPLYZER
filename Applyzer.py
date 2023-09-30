import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QFileDialog, QDialog, QLabel, QLineEdit, QMessageBox

from androguard.core.bytecodes.apk import APK

class ApplyzerGUI(QMainWindow):  # Changed the class name to ApplyzerGUI
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Applyzer')  # Changed the window title to "Applyzer"
        self.setGeometry(100, 100, 800, 600)

        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)

        self.analyze_button = QPushButton('Analyze APK', self)
        self.analyze_button.clicked.connect(self.analyze_apk)

        self.browse_button = QPushButton('Browse APK', self)
        self.browse_button.clicked.connect(self.open_file_dialog)

        self.clear_button = QPushButton('Clear', self)
        self.clear_button.clicked.connect(self.clear_output)

        self.api_key_label = QLabel('Enter VirusTotal API Key:', self)
        self.api_key_line_edit = QLineEdit(self)
        self.api_key_line_edit.setPlaceholderText('API Key')

        self.pre_static_analysis_button = QPushButton('Pre-Static Analysis', self)
        self.pre_static_analysis_button.clicked.connect(self.open_prestatic_analysis_dialog)

        layout = QVBoxLayout()
        layout.addWidget(self.text_output)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.api_key_label)
        layout.addWidget(self.api_key_line_edit)
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
                'android.permission.INTERNET1' ,
                'android.permission.ACCESS_COARSE_LOCATION' , 
                'android.permission.WRITE_CONTACTS'
                'android.permission.SEND_SMS' ,
                'android.permission.WRITE_CALL_LOG' , 
                'android.permission.READ_CALL_LOG' , 
                'android.permission.WRITE_EXTERNAL_STORAGE' ,
                'android.permission.RECORD_AUDIO' ,
                'android.permission.ACCESS_FINE_LOCATION' ,
                'android.permission.CALL_PHONE' ,
            ]

            self.text_output.clear()  # Clear previous results
            self.text_output.append("Analysis Report for: " + self.apk_file)
            self.text_output.append("\nPotentially Harmful Permissions:")

            for perm in permissions:
                if perm in harmful_permissions:
                    self.text_output.append(perm)

            if 'AndroidManifest.xml' in a.get_files():
                self.text_output.append("AndroidManifest.xml found")
        except AttributeError:
            self.text_output.clear()  # Clear previous results
            self.text_output.append("Please select an APK file for analysis.")

    def clear_output(self):
        self.text_output.clear()  # Clear the analysis report

    def open_prestatic_analysis_dialog(self):
        api_key = self.api_key_line_edit.text()

        if not api_key:
            QMessageBox.critical(self, 'Error', 'Please provide a VirusTotal API key.')
            return

        dialog = PreStaticAnalysisDialog(self.apk_file, api_key)
        dialog.exec_()

class PreStaticAnalysisDialog(QDialog):
    def __init__(self, apk_file, api_key):
        super().__init__()

        self.setWindowTitle('Pre-Static Analysis')
        self.setGeometry(200, 200, 600, 400)

        self.api_key = api_key
        self.apk_file = apk_file

        self.text_output = QTextEdit(self)
        self.text_output.setReadOnly(True)

        self.analyze_button = QPushButton('Analyze with VirusTotal', self)
        self.analyze_button.clicked.connect(self.analyze_with_virustotal)

        layout = QVBoxLayout()
        layout.addWidget(self.text_output)
        layout.addWidget(self.analyze_button)
        self.setLayout(layout)

    def analyze_with_virustotal(self):
        try:
            with open(self.apk_file, 'rb') as file:
                response = self.scan_apk_with_virustotal(file, self.api_key)

            self.text_output.clear()  # Clear previous results
            self.text_output.append("Pre-Static Analysis Report for: " + self.apk_file)
            self.text_output.append("\nVirusTotal Analysis:")
            self.text_output.append("Response: " + response)

        except FileNotFoundError:
            self.text_output.clear()  # Clear previous results
            self.text_output.append("Please select an APK file for analysis.")

    def scan_apk_with_virustotal(self, file, api_key):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': api_key}
        files = {'file': file}
        response = requests.post(url, files=files, params=params)
        return response.text

def main():
    app = QApplication(sys.argv)
    window = ApplyzerGUI()  # Changed the class name here as well
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
