# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JTabbedPane, JFrame, JLabel, JTextField, JCheckBox, SwingUtilities, JOptionPane)
import logging
from java.net import URL
from threading import Thread

class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener):
    MAX_REDIRECTS = 5  # Maximale Anzahl der Umleitungen
    SECLIST_URL = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
    LOG_LEVEL = logging.DEBUG
    RESULTS_FILE_PATH = 'results.txt'  # Benutzerdefinierbarer Pfad für die Ergebnisdatei
    ALLOWED_STATUS_CODES = {200, 301, 403, 500}  # Statuscodes, die als interessant betrachtet werden

    def registerExtenderCallbacks(self, callbacks):
        """
        Diese Methode wird aufgerufen, wenn die Erweiterung geladen wird.
        Registriert notwendige Callbacks und initialisiert die Erweiterung.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory Bruteforcer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        logging.basicConfig(level=self.LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._logger = logging.getLogger("BurpExtender")
        self._logger.setLevel(self.LOG_LEVEL)

        self.directories = []
        self.results = []
        self.processed_urls = set()
        self.selected_status_codes = {200}  # Standardmäßig 200 OK aktiviert

        # GUI initialisieren
        self.initialize_gui()

        # SecList im Hintergrund laden
        self.load_seclist_in_background()

    def initialize_gui(self):
        """
        Initialisiert die GUI-Komponenten.
        """
        # Panels
        self._configuration_panel = JPanel()
        self._results_panel = JPanel()
        self._progress_panel = JPanel()

        # Tabs
        self._tabbed_pane = JTabbedPane()
        self._tabbed_pane.addTab("Configuration", self._configuration_panel)
        self._tabbed_pane.addTab("Results", self._results_panel)
        self._tabbed_pane.addTab("Progress", self._progress_panel)

        # Hauptfenster
        self._frame = JFrame("Directory Bruteforcer", size=(800, 600))
        self._frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
        self._frame.getContentPane().add(self._tabbed_pane)
        self._frame.setVisible(True)

        # Konfiguration
        self._configuration_panel.add(JLabel("Base URL:"))
        self._url_text_field = JTextField(60)
        self._configuration_panel.add(self._url_text_field)

        # Statuscode-Checkboxen
        self._status_code_panel = JPanel()
        self._status_code_panel.add(JLabel("Status Codes:"))

        self._status_code_checkboxes = {
            200: JCheckBox("200 OK", True),
            301: JCheckBox("301 Moved Permanently"),
            403: JCheckBox("403 Forbidden"),
            500: JCheckBox("500 Internal Server Error"),
        }

        for code, checkbox in self._status_code_checkboxes.items():
            self._status_code_panel.add(checkbox)

        self._configuration_panel.add(self._status_code_panel)

        self._start_button = JButton("Start", actionPerformed=self.start_bruteforce)
        self._stop_button = JButton("Stop", actionPerformed=self.stop_bruteforce)
        self._stop_button.setEnabled(False)

        self._configuration_panel.add(self._start_button)
        self._configuration_panel.add(self._stop_button)

        # Ergebnisse
        self._results_text_area = JTextArea(20, 60)
        self._results_text_area.setEditable(False)
        self._results_panel.add(JScrollPane(self._results_text_area))

        # Fortschritt
        self._progress_text_area = JTextArea(10, 60)
        self._progress_text_area.setEditable(False)
        self._progress_panel.add(JScrollPane(self._progress_text_area))

    def load_seclist_in_background(self):
        """
        Lädt die Verzeichnisliste im Hintergrund.
        """
        thread = Thread(target=self.load_seclist)
        thread.start()

    def load_seclist(self):
        """
        Lädt die Verzeichnisliste (SecList) von der angegebenen URL.
        """
        try:
            http_service = self._helpers.buildHttpService("raw.githubusercontent.com", 443, True)
            request = self._helpers.buildHttpRequest(URL(self.SECLIST_URL))
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                if response_info.getStatusCode() == 200:
                    body_offset = response_info.getBodyOffset()
                    response_body = raw_response[body_offset:].tostring()
                    self.directories = list(set(response_body.splitlines()))
                    self._logger.info("SecList loaded successfully")
                    update_ui_safe(self.update_progress, "SecList loaded successfully")
                else:
                    self._logger.error("Failed to load SecList, status code: {}".format(response_info.getStatusCode()))
                    update_ui_safe(self.update_progress, "Failed to load SecList, status code: {}".format(response_info.getStatusCode()))
            else:
                self._logger.error("Failed to load SecList: No response received")
                update_ui_safe(self.update_progress, "Failed to load SecList: No response received")
        except Exception as e:
            self._logger.error("Error loading SecList: {}".format(e))
            update_ui_safe(self.update_progress, "Error loading SecList: {}".format(e))

    def start_bruteforce(self, event):
        """
        Startet den Bruteforce-Prozess.
        """
        self._start_button.setEnabled(False)
        self._stop_button.setEnabled(True)
        self.results = []
        self.processed_urls = set()
        self.selected_status_codes = {int(code) for code, checkbox in self._status_code_checkboxes.items() if checkbox.isSelected()}
        base_url = self._url_text_field.getText().strip()
        
        if not base_url:
            JOptionPane.showMessageDialog(self._frame, "Please enter a base URL.", "Error", JOptionPane.ERROR_MESSAGE)
            self._start_button.setEnabled(True)
            self._stop_button.setEnabled(False)
            return

        thread = Thread(target=self.process_url, args=(base_url,))
        thread.start()

    def stop_bruteforce(self, event):
        """
        Stoppt den Bruteforce-Prozess.
        """
        self._start_button.setEnabled(True)
        self._stop_button.setEnabled(False)

    def process_url(self, base_url):
        """
        Verarbeitet die eingegebene Basis-URL und führt Directory-Tests durch.
        """
        try:
            if not base_url.startswith("http://") and not base_url.startswith("https://"):
                base_url = "http://" + base_url

            if base_url in self.processed_urls:
                self._logger.debug("Base URL already processed: {}".format(base_url))
                return

            self.processed_urls.add(base_url)

            for directory in self.directories:
                new_url = self.construct_full_url(base_url, directory.strip())
                self._logger.debug("Constructed URL: {}".format(new_url))
                self.send_request(new_url)

            self._logger.info("Completed processing all directories for base URL: {}".format(base_url))
        except Exception as e:
            self._logger.error("Error processing URL: {}".format(e))

    def send_request(self, url):
        """
        Sendet eine HTTP-Anfrage an die angegebene URL und prüft die Antwort.
        """
        try:
            parsed_url = URL(url)
            host = parsed_url.getHost()
            if not host:
                raise ValueError("Invalid host in URL: {}".format(url))

            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"
            
            http_service = self._helpers.buildHttpService(host, port, use_https)
            request = self._helpers.buildHttpRequest(parsed_url)
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                status_code = response_info.getStatusCode()
                if status_code in self.selected_status_codes:
                    self.results.append((url, status_code))
                    self._logger.debug("Directory found with status code {}: {}".format(status_code, url))
                    update_ui_safe(self.update_results, url, status_code)
                else:
                    self._logger.debug("Received status code {} for URL: {}".format(status_code, url))
            else:
                self._logger.error("Request error for {}: No response received".format(url))
        except Exception as e:
            self._logger.error("Request error for {}: {}".format(url, e))

    def extensionUnloaded(self):
        """
        Wird aufgerufen, wenn die Erweiterung entladen wird.
        """
        self.save_results()

    def save_results(self):
        """
        Speichert die gefundenen Verzeichnisse in einer Datei.
        """
        try:
            with open(self.RESULTS_FILE_PATH, 'w') as f:
                for url, status_code in self.results:
                    f.write("{} - {}\n".format(url, status_code))
        except IOError as e:
            self._logger.error("File error: {}".format(e))

    def construct_full_url(self, base_url, path):
        """
        Konstruiert die vollständige URL aus der Basis-URL und dem Pfad.
        """
        if base_url.endswith('/'):
            base_url = base_url[:-1]
        if not path.startswith('/'):
            path = '/' + path
        return base_url + path

    def update_results(self, url, status_code):
        """
        Aktualisiert das Ergebnisfeld mit neuen Ergebnissen.
        """
        result_entry = "{} - {}\n".format(url, status_code)
        self._results_text_area.append(result_entry)
        self.save_results()  # Speichert alle Ergebnisse bei jeder Aktualisierung

    def update_progress(self, message):
        """
        Aktualisiert das Fortschrittsfeld mit neuen Nachrichten.
        """
        self._progress_text_area.append(message + '\n')

def update_ui_safe(method, *args):
    """
    Führt die übergebene Methode sicher im Event-Dispatch-Thread aus.
    """
    SwingUtilities.invokeLater(lambda: method(*args))
