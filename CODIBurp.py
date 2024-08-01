# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JTabbedPane, JFrame, JOptionPane, SwingUtilities)
from javax.swing.event import DocumentEvent, DocumentListener
import logging
from java.net import URL
from java.util import ArrayList
from threading import Thread

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
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
        thread = Thread(target=self.process_all_urls)
        thread.start()

    def stop_bruteforce(self, event):
        """
        Stoppt den Bruteforce-Prozess.
        """
        self._start_button.setEnabled(True)
        self._stop_button.setEnabled(False)

    def process_all_urls(self):
        """
        Verarbeitet alle URLs.
        """
        # Implementiere die Logik für die Verarbeitung von URLs hier
        # Dies könnte ein Loop über die Verzeichnisse und URLs sein
        pass

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Verarbeitet HTTP-Nachrichten. Wenn es sich um eine Anfrage handelt,
        wird die Basis-URL extrahiert und Directory-Tests durchgeführt.
        """
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                base_url = self.get_base_url(headers)
                if not base_url:
                    self._logger.error("Base URL could not be determined")
                    return

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
                self._logger.error("Error processing HTTP message: {}".format(e))

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
                if status_code in self.ALLOWED_STATUS_CODES:
                    self.results.append(url)
                    self._logger.debug("Directory found with status code {}: {}".format(status_code, url))
                    update_ui_safe(self.update_results, url)
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
                for result in self.results:
                    f.write(result + '\n')
        except IOError as e:
            self._logger.error("File error: {}".format(e))

    def get_base_url(self, headers):
        """
        Extrahiert die Basis-URL aus den Anfrage-Headern.
        """
        request_line = headers[0]
        method, path, _ = request_line.split(' ', 2)

        if not path.startswith('/'):
            path = '/' + path

        for header in headers:
            if header.lower().startswith("host:"):
                host = header.split(':', 1)[1].strip()
                break
        else:
            host = ""

        return "http://" + host

    def construct_full_url(self, base_url, directory):
        """
        Konstruiert eine vollständige URL durch Hinzufügen des Verzeichnisnamens zur Basis-URL.
        """
        if not base_url.endswith('/'):
            base_url += '/'
        
        if directory.startswith('/'):
            directory = directory[1:]
        
        return base_url + directory

    def update_results(self, url):
        """
        Aktualisiert das Ergebnis-Textfeld mit neuen URLs.
        """
        self._results_text_area.append(url + '\n')

    def update_progress(self, message):
        """
        Aktualisiert das Fortschritts-Textfeld mit neuen Nachrichten.
        """
        self._progress_text_area.append(message + '\n')

def update_ui_safe(ui_update_function, *args):
    """
    Führt die UI-Aktualisierung im Event-Dispatch-Thread aus.
    """
    SwingUtilities.invokeLater(lambda: ui_update_function(*args))
