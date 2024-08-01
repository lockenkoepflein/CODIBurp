# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import logging
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    MAX_REDIRECTS = 5  # Maximale Anzahl der Umleitungen
    SECLIST_URL = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
    LOG_LEVEL = logging.DEBUG
    RESULTS_FILE_PATH = 'results.txt'  # Benutzerdefinierbarer Pfad für die Ergebnisdatei
    ALLOWED_STATUS_CODES = {200, 403, 500}  # Statuscodes, die als interessant betrachtet werden

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
        self.load_seclist()

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
                else:
                    self._logger.error("Failed to load SecList, status code: {}".format(response_info.getStatusCode()))
            else:
                self._logger.error("Failed to load SecList: No response received")
        except Exception as e:
            self._logger.error("Error loading SecList: {}".format(e))

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
