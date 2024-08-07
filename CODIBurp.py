# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JTabbedPane, JFrame, JLabel, JTextField, JCheckBox, SwingUtilities, JOptionPane, BoxLayout, BorderFactory, Box, UIManager)
import logging
from java.net import URL
import threading
import java.awt.Font as Font
import java.awt.Component as Component

class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener):
    MAX_REDIRECTS = 5
    SECLIST_URL = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
    LOG_LEVEL = logging.DEBUG
    RESULTS_FILE_PATH = 'results.txt'
    ALLOWED_STATUS_CODES = {200, 301, 403, 500}

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

        self.directories = []
        self.results = []
        self.processed_urls = set()
        self.selected_status_codes = {200}

        self.initialize_gui()
        self.load_seclist_in_background()

    def initialize_gui(self):
        """
        Initialisiert die GUI-Komponenten.
        """
        # Panels
        self._main_panel = JPanel()
        self._results_panel = JPanel()
        
        # Tabs
        self._tabbed_pane = JTabbedPane()
        self._tabbed_pane.addTab("Configuration and Progress", self._main_panel)
        self._tabbed_pane.addTab("Results", self._results_panel)

        # Hauptfenster
        self._frame = JFrame("Directory Bruteforcer", size=(600, 400))
        self._frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
        self._frame.getContentPane().add(self._tabbed_pane)
        self._frame.setVisible(True)

        # Layout-Manager
        self._main_panel.setLayout(BoxLayout(self._main_panel, BoxLayout.Y_AXIS))
        self._results_panel.setLayout(BoxLayout(self._results_panel, BoxLayout.Y_AXIS))

        # Konfiguration
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(BorderFactory.createTitledBorder("Configuration"))

        label_panel = JPanel()
        label_panel.setLayout(BoxLayout(label_panel, BoxLayout.X_AXIS))
        label_panel.setAlignmentX(Component.CENTER_ALIGNMENT)
        base_url_label = JLabel("Base URL:")
        base_url_label.setFont(Font("Arial", Font.PLAIN, 10))  # Schriftgröße und Stil angepasst
        label_panel.add(Box.createHorizontalGlue())
        label_panel.add(base_url_label)
        label_panel.add(Box.createHorizontalGlue())
        config_panel.add(label_panel)

        text_field_panel = JPanel()
        text_field_panel.setLayout(BoxLayout(text_field_panel, BoxLayout.X_AXIS))
        text_field_panel.setAlignmentX(Component.CENTER_ALIGNMENT)
        self._url_text_field = JTextField(40)
        text_field_panel.add(Box.createHorizontalGlue())
        text_field_panel.add(self._url_text_field)
        text_field_panel.add(Box.createHorizontalGlue())
        config_panel.add(text_field_panel)

        # Statuscode-Checkboxen
        self._status_code_panel = JPanel()
        self._status_code_panel.setLayout(BoxLayout(self._status_code_panel, BoxLayout.Y_AXIS))
        self._status_code_panel.setBorder(BorderFactory.createTitledBorder("Status Codes"))
        self._status_code_panel.setAlignmentX(Component.CENTER_ALIGNMENT)

        self._status_code_checkboxes = {
            200: JCheckBox("200 OK", True),
            301: JCheckBox("301 Moved Permanently"),
            403: JCheckBox("403 Forbidden"),
            500: JCheckBox("500 Internal Server Error"),
        }

        for code, checkbox in self._status_code_checkboxes.items():
            checkbox.setAlignmentX(Component.CENTER_ALIGNMENT)
            checkbox.setFont(Font("Arial", Font.PLAIN, 12))
            self._status_code_panel.add(checkbox)

        config_panel.add(self._status_code_panel)

        buttons_panel = JPanel()
        buttons_panel.setLayout(BoxLayout(buttons_panel, BoxLayout.X_AXIS))
        buttons_panel.setAlignmentX(Component.CENTER_ALIGNMENT)

        self._start_button = JButton("Start", actionPerformed=self.start_bruteforce)
        self._stop_button = JButton("Stop", actionPerformed=self.stop_bruteforce)
        self._stop_button.setEnabled(False)

        buttons_panel.add(Box.createHorizontalGlue())
        buttons_panel.add(self._start_button)
        buttons_panel.add(Box.createHorizontalStrut(10))
        buttons_panel.add(self._stop_button)
        buttons_panel.add(Box.createHorizontalGlue())
        
        config_panel.add(buttons_panel)

        self._main_panel.add(config_panel)

        # Fortschritt
        progress_panel = JPanel()
        progress_panel.setLayout(BoxLayout(progress_panel, BoxLayout.Y_AXIS))
        progress_panel.setBorder(BorderFactory.createTitledBorder("Progress"))

        self._progress_text_area = JTextArea(10, 50)
        self._progress_text_area.setEditable(False)
        progress_panel.add(JScrollPane(self._progress_text_area))

        self._main_panel.add(progress_panel)

        # Ergebnisse
        self._results_text_area = JTextArea(20, 50)
        self._results_text_area.setEditable(False)
        self._results_panel.add(JScrollPane(self._results_text_area))

    def load_seclist_in_background(self):
        """
        Lädt die Verzeichnisliste im Hintergrund.
        """
        threading.Thread(target=self.load_seclist).start()

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

        threading.Thread(target=self.process_url, args=(base_url,)).start()

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
            if not base_url.startswith(("http://", "https://")):
                base_url = "http://" + base_url

            if base_url in self.processed_urls:
                self._logger.debug("Base URL already processed: {}".format(base_url))
                return

            self.processed_urls.add(base_url)

            threads = []
            for directory in self.directories:
                new_url = self.construct_full_url(base_url, directory.strip())
                self._logger.debug("Constructed URL: {}".format(new_url))
                thread = threading.Thread(target=self.send_request, args=(new_url,))
                thread.start()
                threads.append(thread)

            # Warten bis alle Threads abgeschlossen sind
            for thread in threads:
                thread.join()

            self._logger.info("Completed processing all directories for base URL: {}".format(base_url))
            update_ui_safe(self.update_progress, "Completed processing all directories for base URL: {}".format(base_url))
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
                    result_entry = "{} - {}\n".format(url, status_code)
                    self.results.append((url, status_code))
                    update_ui_safe(self.update_results, result_entry)
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
            self._logger.info("Results saved to {}".format(self.RESULTS_FILE_PATH))
        except Exception as e:
            self._logger.error("Failed to save results: {}".format(e))

    def update_results(self, result_entry):
        """
        Aktualisiert die Ergebnisse in der GUI.
        """
        self._results_text_area.append(result_entry)
        self._results_text_area.setCaretPosition(self._results_text_area.getDocument().getLength())

    def update_progress(self, progress_message):
        """
        Aktualisiert die Fortschrittsanzeige in der GUI.
        """
        self._progress_text_area.append(progress_message + "\n")
        self._progress_text_area.setCaretPosition(self._progress_text_area.getDocument().getLength())

    def construct_full_url(self, base_url, directory):
        """
        Konstruiert die vollständige URL durch Anhängen des Verzeichnisses an die Basis-URL.
        """
        if base_url.endswith("/"):
            return base_url + directory
        return base_url + "/" + directory

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Verarbeitet HTTP-Nachrichten, die in Burp Suite empfangen werden.
        """
        if messageIsRequest:
            # Hier können Sie Anfragen verarbeiten, wenn nötig
            pass
        else:
            # Hier können Sie Antworten verarbeiten, wenn nötig
            pass

def update_ui_safe(method, *args):
    """
    Führt eine Methode im Event-Dispatch-Thread aus, um sicherzustellen,
    dass die GUI sicher aktualisiert wird.
    """
    SwingUtilities.invokeLater(lambda: method(*args))
