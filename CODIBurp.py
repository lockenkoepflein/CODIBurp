# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import logging
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        """
        Diese Methode wird aufgerufen, wenn die Erweiterung geladen wird.
        Registriert notwendige Callbacks und initialisiert die Erweiterung.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()  # Helferfunktionen von Burp API abrufen
        callbacks.setExtensionName("Directory Bruteforcer")  # Name der Erweiterung festlegen
        callbacks.registerHttpListener(self)  # HTTP-Listener registrieren
        callbacks.registerExtensionStateListener(self)  # Erweiterungsstatus-Listener registrieren

        self.directories = []  # Liste für Verzeichnisnamen initialisieren
        self.results = []  # Liste für gefundene Verzeichnisse initialisieren
        self.load_seclist()  # SecList von URL laden

    def load_seclist(self):
        """
        Lädt die Verzeichnisliste (SecList) von der angegebenen URL.
        """
        seclist_url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            # HTTP-Service für die SecList-URL erstellen
            http_service = self._helpers.buildHttpService("raw.githubusercontent.com", 443, True)
            # HTTP-Anfrage für die SecList-URL erstellen
            request = self._helpers.buildHttpRequest(URL(seclist_url))
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                if response_info.getStatusCode() == 200:
                    # Antwort erfolgreich - Verzeichnisnamen extrahieren
                    body_offset = response_info.getBodyOffset()
                    response_body = raw_response[body_offset:].tostring()
                    self.directories = response_body.splitlines()  # Verzeichnisnamen in Liste speichern
                    logging.info("SecList loaded successfully")  # Erfolgsmeldung loggen
                else:
                    logging.error("Failed to load SecList, status code: {}".format(response_info.getStatusCode()))  # Fehlermeldung loggen
            else:
                logging.error("Failed to load SecList: No response received")  # Fehler loggen, wenn keine Antwort erhalten
        except Exception as e:
            logging.error("Error loading SecList: {}".format(e))  # Fehler loggen, wenn beim Laden der SecList ein Problem auftritt

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Verarbeitet HTTP-Nachrichten. Wenn es sich um eine Anfrage handelt,
        wird die Basis-URL extrahiert und Directory-Tests durchgeführt.
        """
        if messageIsRequest:
            try:
                # HTTP-Anfrage analysieren
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                logging.debug("Request Headers: {}".format(headers))  # Debug-Ausgabe der Anfrage-Header

                # Basis-URL aus den Anfrage-Headern extrahieren
                base_url = self.get_base_url(headers)
                logging.debug("Extracted Base URL: {}".format(base_url))  # Debug-Ausgabe der extrahierten Basis-URL

                if not base_url:
                    logging.error("Base URL could not be determined")  # Fehlermeldung, wenn Basis-URL nicht ermittelt werden konnte
                    return

                # Wenn die Basis-URL kein Protokoll enthält, füge http:// hinzu
                if not base_url.startswith("http://") and not base_url.startswith("https://"):
                    base_url = "http://" + base_url
                    logging.debug("Modified Base URL with http://: {}".format(base_url))  # Debug-Ausgabe der modifizierten Basis-URL

                # Für jeden Verzeichnisnamen in der SecList
                for directory in self.directories:
                    # Vollständige URL durch Hinzufügen des Verzeichnisnamens zur Basis-URL erstellen
                    new_url = self.construct_full_url(base_url, directory.strip())
                    logging.debug("Constructed URL: {}".format(new_url))  # Debug-Nachricht mit der konstruierten URL loggen
                    self.send_request(new_url)  # HTTP-Anfrage an die neue URL senden
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))  # Fehler loggen, wenn beim Verarbeiten der HTTP-Nachricht ein Problem auftritt

    def send_request(self, url):
        """
        Sendet eine HTTP-Anfrage an die angegebene URL und prüft die Antwort.
        """
        try:
            # URL parsen
            parsed_url = URL(url)
            host = parsed_url.getHost()
            if not host:
                raise ValueError("Invalid host in URL: {}".format(url))  # Fehler, wenn der Host ungültig ist
            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService(host, port, use_https)
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(parsed_url)
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                if response_info.getStatusCode() == 200:
                    self.results.append(url)  # Gefundene URL zu den Ergebnissen hinzufügen
                    logging.debug("Directory found: {}".format(url))  # Debug-Nachricht loggen
                else:
                    logging.debug("Received status code {} for URL: {}".format(response_info.getStatusCode(), url))  # Debug-Nachricht mit erhaltenem Statuscode loggen
            else:
                logging.error("Request error for {}: No response received".format(url))  # Fehler loggen, wenn keine Antwort erhalten
        except Exception as e:
            logging.error("Request error for {}: {}".format(url, e))  # Fehler loggen, wenn beim Senden der Anfrage ein Problem auftritt

    def extensionUnloaded(self):
        """
        Wird aufgerufen, wenn die Erweiterung entladen wird.
        """
        self.save_results()  # Ergebnisse speichern

    def save_results(self):
        """
        Speichert die gefundenen Verzeichnisse in einer Datei.
        """
        try:
            with open('results.txt', 'w') as f:
                for result in self.results:
                    f.write(result + '\n')  # Ergebnisse in results.txt schreiben
        except IOError as e:
            logging.error("File error: {}".format(e))  # Fehler loggen, wenn die Datei nicht gespeichert werden kann

    def get_base_url(self, headers):
        """
        Extrahiert die Basis-URL aus den Anfrage-Headern.
        """
        logging.debug("Getting base URL from headers")  # Debug-Nachricht, dass get_base_url aufgerufen wurde
        if not headers:
            logging.debug("No headers provided")  # Debug-Nachricht, wenn keine Header vorhanden sind
            return ""
        first_line = headers[0].split()
        logging.debug("First header line: {}".format(first_line))  # Debug-Nachricht für die erste Zeile der Header
        if len(first_line) > 1:
            base_url = first_line[1]
            logging.debug("Extracted base URL: {}".format(base_url))  # Debug-Ausgabe der extrahierten Basis-URL
            return base_url
        logging.debug("Could not extract base URL")  # Debug-Nachricht, wenn die Basis-URL nicht extrahiert werden konnte
        return ""

    def construct_full_url(self, base_url, directory):
        """
        Konstruiert eine vollständige URL durch Hinzufügen des Verzeichnisnamens zur Basis-URL.
        """
        return base_url.rstrip("/") + "/" + directory.lstrip("/")  # Basis-URL und Verzeichnis korrekt zusammensetzen

    def get_host(self, url):
        """
        Extrahiert den Hostnamen aus der URL.
        """
        return URL(url).getHost()  # Hostnamen aus der URL extrahieren
