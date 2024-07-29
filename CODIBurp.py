# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import logging
from java.net import URL

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()  # Helper-Funktionen von Burp API abrufen
        callbacks.setExtensionName("Directory Bruteforcer")  # Name der Erweiterung festlegen
        callbacks.registerHttpListener(self)  # HTTP-Listener registrieren
        callbacks.registerExtensionStateListener(self)  # Erweiterungsstatus-Listener registrieren

        self.directories = []  # Liste für Verzeichnisnamen initialisieren
        self.results = []  # Liste für gefundene Verzeichnisse initialisieren
        self.load_seclist()  # SecList von URL laden

    def load_seclist(self):
        # URL zur SecList definieren
        url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            # URL Objekt erstellen
            parsed_url = URL(url)
            host = parsed_url.getHost()
            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"
            
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService(host, port, use_https)
            
            # Den vollständigen Pfad (mit Query-Parametern) erstellen
            path = parsed_url.getPath() + ("?" + parsed_url.getQuery() if parsed_url.getQuery() else "")
            
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(path)
            
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                response_info = self._helpers.analyzeResponse(response)
                body_offset = response_info.getBodyOffset()
                response_body = response.getResponse()[body_offset:].tostring()
                self.directories = response_body.splitlines()
                logging.info("SecList loaded successfully")  # Erfolgsmeldung loggen
            else:
                logging.error("Failed to load SecList")  # Fehlermeldung loggen, wenn Laden fehlschlägt
        except Exception as e:
            logging.error("Error loading SecList: {}".format(e))  # Fehler loggen

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                # HTTP-Anfrage analysieren
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()  # Header der Anfrage abrufen
                base_url = self.get_base_url(headers)  # Basis-URL aus der Anfrage extrahieren
                
                # Für jeden Verzeichnisnamen in der SecList
                for directory in self.directories:
                    # Neue URL erstellen durch Hinzufügen des Verzeichnisnamens
                    new_url = base_url + "/" + directory.strip()
                    self.send_request(new_url)  # HTTP-Anfrage senden
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))  # Fehler loggen

    def send_request(self, url):
        try:
            # URL parsen
            parsed_url = URL(url)
            host = parsed_url.getHost()
            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"
            
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService(host, port, use_https)
            
            # Den vollständigen Pfad (mit Query-Parametern) erstellen
            path = parsed_url.getPath() + ("?" + parsed_url.getQuery() if parsed_url.getQuery() else "")
            
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(path)
            logging.debug("Sending request to URL: {}".format(url))  # Loggen, welche Anfrage gesendet wird
            
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                response_info = self._helpers.analyzeResponse(response)
                status_code = response_info.getStatusCode()
                if status_code == 200:
                    self.results.append(url)  # URL zu den Ergebnissen hinzufügen
                    logging.debug("Directory found: {}".format(url))  # Debug-Nachricht loggen
                else:
                    logging.debug("Received status code {} for URL: {}".format(status_code, url))
            else:
                logging.debug("No response for URL: {}".format(url))
        except Exception as e:
            logging.error("Request error for {}: {}".format(url, e))  # Fehler loggen

    def extensionUnloaded(self):
        self.save_results()  # Ergebnisse speichern, wenn die Erweiterung entladen wird

    def save_results(self):
        try:
            with open('results.txt', 'w') as f:
                for result in self.results:
                    f.write(result + '\n')  # Ergebnisse in results.txt schreiben
        except IOError as e:
            logging.error("File error: {}".format(e))  # Fehler loggen, wenn Datei nicht gespeichert werden kann

    def get_base_url(self, headers):
        # Basis-URL aus den Anfrage-Headern extrahieren
        first_line = headers[0].split()
        if len(first_line) > 1:
            return first_line[1]
        return ""

    def get_host(self, url):
        return URL(url).getHost()  # Hostnamen aus der URL extrahieren
