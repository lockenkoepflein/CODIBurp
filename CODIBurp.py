# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane, JTabbedPane, JFrame, JLabel, JTextField, JCheckBox, 
                         SwingUtilities, JOptionPane, BoxLayout, BorderFactory, Box, UIManager, JProgressBar)
import logging
from java.net import URL
import java.awt.Font as Font
import java.awt.Component as Component
import threading
import re
import random
import time

class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener):
    MAX_REDIRECTS = 5
    LOG_LEVEL = logging.DEBUG
    RESULTS_FILE_PATH = 'Results.txt'
    ALLOWED_STATUS_CODES = {200, 301, 403, 500}

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory and File Bruteforcer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        logging.basicConfig(level=self.LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._logger = logging.getLogger("BurpExtender")

        self.directories = []
        self.files = []
        self.results = []
        self.processed_urls = set()
        self.selected_status_codes = {200}
        self._stop_requested = False

        self.initialize_gui()

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
        self._frame = JFrame("Directory and File Bruteforcer", size=(800, 600))  # Größe auf 800x600 erhöht
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

        # Base URL
        label_panel = JPanel()
        label_panel.setLayout(BoxLayout(label_panel, BoxLayout.X_AXIS))
        label_panel.setAlignmentX(Component.CENTER_ALIGNMENT)
        base_url_label = JLabel("Base URL:")
        base_url_label.setFont(Font("Arial", Font.PLAIN, 12))  # Schriftgröße auf 12 erhöht
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

        # Verzeichnisliste
        directory_label = JLabel("Directory List URL:")
        directory_label.setFont(Font("Arial", Font.PLAIN, 12))
        config_panel.add(directory_label)

        self._directory_url_text_field = JTextField(40)
        config_panel.add(self._directory_url_text_field)

        # Dateiliste
        file_label = JLabel("File List URL:")
        file_label.setFont(Font("Arial", Font.PLAIN, 12))
        config_panel.add(file_label)

        self._file_url_text_field = JTextField(40)
        config_panel.add(self._file_url_text_field)

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
        self._save_button = JButton("Save Results", actionPerformed=self.save_results_to_file)
        
        self._stop_button.setEnabled(False)
        self._save_button.setEnabled(False)

        buttons_panel.add(Box.createHorizontalGlue())
        buttons_panel.add(self._start_button)
        buttons_panel.add(Box.createHorizontalStrut(10))
        buttons_panel.add(self._stop_button)
        buttons_panel.add(Box.createHorizontalStrut(10))
        buttons_panel.add(self._save_button)
        buttons_panel.add(Box.createHorizontalGlue())
        
        config_panel.add(buttons_panel)

        # Fortschritt
        progress_panel = JPanel()
        progress_panel.setLayout(BoxLayout(progress_panel, BoxLayout.Y_AXIS))
        progress_panel.setBorder(BorderFactory.createTitledBorder("Progress"))

        self._progress_text_area = JTextArea(10, 50)
        self._progress_text_area.setEditable(False)
        progress_panel.add(JScrollPane(self._progress_text_area))
        
        # Fortschrittsbalken
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        progress_panel.add(self._progress_bar)

        self._main_panel.add(config_panel)
        self._main_panel.add(progress_panel)

        # Ergebnisse
        self._results_text_area = JTextArea(20, 50)
        self._results_text_area.setEditable(False)
        self._results_panel.add(JScrollPane(self._results_text_area))

    def start_bruteforce(self, event):
        """
        Startet den Bruteforce-Prozess. Liest die Eingaben aus, überprüft die URLs und startet den Verarbeitungsprozess.
        """
        self._start_button.setEnabled(False)
        self._stop_button.setEnabled(True)
        self._save_button.setEnabled(False)
        self.results = []
        self.processed_urls = set()
        self.selected_status_codes = {int(code) for code, checkbox in self._status_code_checkboxes.items() if checkbox.isSelected()}

        base_url = self._url_text_field.getText().strip()
        directory_url = self._directory_url_text_field.getText().strip()
        file_url = self._file_url_text_field.getText().strip()

        # Überprüfen, ob alle Felder ausgefüllt sind
        if not base_url or not directory_url or not file_url:
            JOptionPane.showMessageDialog(self._frame, "Please fill in all URL fields.", "Error", JOptionPane.ERROR_MESSAGE)
            self._start_button.setEnabled(True)
            self._stop_button.setEnabled(False)
            return

        # Validieren der Basis-URL
        if not self.is_valid_url(base_url):
            JOptionPane.showMessageDialog(self._frame, "The Base URL is invalid. Please enter a valid URL.", "Error", JOptionPane.ERROR_MESSAGE)
            self._start_button.setEnabled(True)
            self._stop_button.setEnabled(False)
            return

        update_ui_safe(self._progress_bar.setValue, 0)
        threading.Thread(target=self.load_lists_and_process, args=(base_url, directory_url, file_url)).start()

    def is_valid_url(self, url):
        """
        Überprüft, ob die angegebene URL gültig ist.
        Eine URL ist gültig, wenn sie entweder ein vollständiges Format wie 'http://host:port/path' oder 'https://host/path' hat.
        """
        # Regex für einfache URL-Validierung
        regex = re.compile(
            r'^(?:http|https)://'  # Protokoll
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,})|'  # Domäne
            r'localhost|'  # oder localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # oder IPv4-Adresse
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # oder IPv6-Adresse
            r'(?::\d+)?'  # Port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # Pfad
        return re.match(regex, url) is not None

    def load_lists_and_process(self, base_url, directory_url, file_url):
        """
        Lädt die Verzeichnisse und Dateien von den angegebenen URLs und beginnt mit der Verarbeitung.
        """
        try:
            self.directories = self.load_list_from_url(directory_url)
            self.files = self.load_list_from_url(file_url)

            total_items = len(self.directories) + len(self.files)
            update_ui_safe(self._progress_bar.setMaximum, total_items)

            self.process_url(base_url)
        except Exception as e:
            self._logger.error("Error loading lists or processing: {}".format(e))
            update_ui_safe(self.update_progress, "Error: {}".format(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Verarbeitet HTTP-Nachrichten, die an Burp Suite gesendet werden.
        """
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            if url.toString() not in self.processed_urls:
                self.processed_urls.add(url.toString())
                threading.Thread(target=self.send_request, args=(url.toString(),)).start()

    def send_request(self, url):
        """
        Sendet eine HTTP-Anfrage an die angegebene URL und verarbeitet die Antwort.
        """
        try:
            parsed_url = URL(url)
            host = parsed_url.getHost()
            
            if not host:
                raise ValueError("Invalid host in URL: {}".format(url))

            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"

            self._logger.debug("Sending request to {} on port {}".format(url, port))

            http_service = self._helpers.buildHttpService(host, port, use_https)
            request = self._helpers.buildHttpRequest(parsed_url)
            response = self._callbacks.makeHttpRequest(http_service, request)

            # Zeitliche Verzögerung hinzufügen
            time.sleep(random.uniform(0.01, 0.05))

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
        finally:
            update_ui_safe(self.increment_progress)

    def stop_bruteforce(self, event):
        """
        Stoppt den Bruteforce-Prozess.
        """
        self._stop_requested = True
        self._start_button.setEnabled(True)
        self._stop_button.setEnabled(False)
        self._save_button.setEnabled(True)

    def load_list_from_url(self, list_url):
        """
        Lädt eine Liste von der angegebenen URL.
        """
        try:
            http_service = self._helpers.buildHttpService("raw.githubusercontent.com", 443, True)
            request = self._helpers.buildHttpRequest(URL(list_url))
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                if response_info.getStatusCode() == 200:
                    body_offset = response_info.getBodyOffset()
                    response_body = raw_response[body_offset:].tostring()
                    return list(set(response_body.splitlines()))
                else:
                    self._logger.error("Failed to load list from {}, status code: {}".format(list_url, response_info.getStatusCode()))
            else:
                self._logger.error("No response received when loading list from {}".format(list_url))
        except Exception as e:
            self._logger.error("Error loading list from {}: {}".format(list_url, e))
        return []

    def process_url(self, base_url):
        """
        Verarbeitet die eingegebene Basis-URL und führt Directory- und Dateitests durch.
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
                self._logger.debug("Constructed URL for directory: {}".format(new_url))
                thread = threading.Thread(target=self.send_request, args=(new_url,))
                thread.start()
                threads.append(thread)

            for file in self.files:
                new_url = self.construct_full_url(base_url, file.strip())
                self._logger.debug("Constructed URL for file: {}".format(new_url))
                thread = threading.Thread(target=self.send_request, args=(new_url,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

            self._logger.info("Completed processing all directories and files for base URL: {}".format(base_url))
            update_ui_safe(self.update_progress, "Completed processing all directories and files for base URL: {}".format(base_url))
            # Aktivierung des Save-Buttons nach Abschluss der Verarbeitung
            update_ui_safe(self._save_button.setEnabled, True)
        except Exception as e:
            self._logger.error("Error processing URL: {}".format(e))

    def construct_full_url(self, base_url, path):
        """
        Baut eine vollständige URL basierend auf der Basis-URL und dem Pfad.
        """
        if not base_url.endswith("/"):
            base_url += "/"
        return base_url + path

    def update_results(self, result_entry):
        """
        Aktualisiert den Ergebnisbereich der GUI.
        """
        self._results_text_area.append(result_entry)

    def update_progress(self, progress_message):
        """
        Aktualisiert den Fortschrittsbereich der GUI.
        """
        self._progress_text_area.append(progress_message + "\n")

    def increment_progress(self):
        """
        Erhöht den Fortschrittsbalken um einen Schritt.
        """
        current_value = self._progress_bar.getValue()
        max_value = self._progress_bar.getMaximum()
        if current_value < max_value:
            self._progress_bar.setValue(current_value + 1)

    def save_results_to_file(self, event=None):
        """
        Speichert die Ergebnisse in die RESULTS_FILE_PATH-Datei.
        """
        try:
            with open(self.RESULTS_FILE_PATH, 'w') as file:
                for url, status_code in self.results:
                    file.write("{} - {}\n".format(url, status_code))
            self._logger.info("Results saved to file: {}".format(self.RESULTS_FILE_PATH))
        except Exception as e:
            self._logger.error("Error saving results to file: {}".format(e))

    def extensionUnloaded(self):
        """
        Wird aufgerufen, wenn die Erweiterung entladen wird.
        """
        self._logger.info("Extension was unloaded.")
        self.save_results_to_file()

def update_ui_safe(func, *args, **kwargs):
    """
    Führt eine GUI-Änderung sicher im Event-Dispatch-Thread (EDT) aus.
    """
    SwingUtilities.invokeLater(lambda: func(*args, **kwargs))
