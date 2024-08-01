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

        # Setze Logging-Level und Format
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self._logger = logging.getLogger("BurpExtender")
        self._logger.setLevel(logging.DEBUG)

        self.directories = []  # Liste für Verzeichnisnamen initialisieren
        self.results = []  # Liste für gefundene Verzeichnisse initialisieren
        self.processed_urls = set()  # Set zur Speicherung der verarbeiteten URLs
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
                    self.directories = list(set(response_body.splitlines()))  # Verzeichnisnamen in Liste speichern, Duplikate entfernen
                    self._logger.info("SecList loaded successfully")  # Erfolgsmeldung loggen
                else:
                    self._logger.error("Failed to load SecList, status code: {}".format(response_info.getStatusCode()))  # Fehlermeldung loggen
            else:
                self._logger.error("Failed to load SecList: No response received")  # Fehler loggen, wenn keine Antwort erhalten
        except Exception as e:
            self._logger.error("Error loading SecList: {}".format(e))  # Fehler loggen, wenn beim Laden der SecList ein Problem auftritt

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
                # Basis-URL aus den Anfrage-Headern extrahieren
                base_url = self.get_base_url(headers)
                if not base_url:
                    self._logger.error("Base URL could not be determined")  # Fehlermeldung, wenn Basis-URL nicht ermittelt werden konnte
                    return

                # Wenn die Basis-URL kein Protokoll enthält, füge http:// hinzu
                if not base_url.startswith("http://") and not base_url.startswith("https://"):
                    base_url = "http://" + base_url

                # Überprüfen, ob die Basis-URL bereits verarbeitet wurde
                if base_url in self.processed_urls:
                    self._logger.debug("Base URL already processed: {}".format(base_url))
                    return

                # Basis-URL zur Liste der verarbeiteten URLs hinzufügen
                self.processed_urls.add(base_url)

                # Verzeichnisse durchlaufen und Anfragen senden
                for directory in self.directories:
                    # Vollständige URL durch Hinzufügen des Verzeichnisnamens zur Basis-URL erstellen
                    new_url = self.construct_full_url(base_url, directory.strip())
                    self._logger.debug("Constructed URL: {}".format(new_url))  # Debug-Nachricht mit der konstruierten URL loggen
                    self.send_request(new_url)  # HTTP-Anfrage an die neue URL senden

                # Bestätigungs-Log, dass alle Verzeichnisse durchlaufen wurden
                self._logger.info("Completed processing all directories for base URL: {}".format(base_url))
            except Exception as e:
                self._logger.error("Error processing HTTP message: {}".format(e))  # Fehler loggen, wenn beim Verarbeiten der HTTP-Nachricht ein Problem auftritt

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

            # Bestimme den Port, falls nicht angegeben
            port = parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80)
            use_https = parsed_url.getProtocol() == "https"
            
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService(host, port, use_https)
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(parsed_url)
            
            # Umleitung verfolgen
            max_redirects = 5
            current_url = url
            for i in range(max_redirects):
                response = self._callbacks.makeHttpRequest(http_service, request)
                if response:
                    raw_response = response.getResponse()
                    if raw_response:
                        response_info = self._helpers.analyzeResponse(raw_response)
                        if response_info:
                            status_code = response_info.getStatusCode()
                            if status_code == 200:
                                self.results.append(current_url)  # Gefundene URL zu den Ergebnissen hinzufügen
                                self._logger.debug("Directory found: {}".format(current_url))  # Debug-Nachricht loggen
                                break
                            elif status_code in [301, 302]:
                                # Umleitungs-URL extrahieren
                                headers = response_info.getHeaders()
                                for header in headers:
                                    if header.lower().startswith("location:"):
                                        redirect_url = header.split(':', 1)[1].strip()
                                        if not redirect_url.startswith("http"):
                                            redirect_url = "{}{}".format(current_url.rstrip('/'), redirect_url)
                                        current_url = redirect_url
                                        parsed_url = URL(current_url)
                                        http_service = self._helpers.buildHttpService(parsed_url.getHost(), parsed_url.getPort() if parsed_url.getPort() != -1 else (443 if parsed_url.getProtocol() == "https" else 80), parsed_url.getProtocol() == "https")
                                        request = self._helpers.buildHttpRequest(parsed_url)
                                        self._logger.debug("Redirecting to: {}".format(current_url))  # Debug-Nachricht loggen
                                        break
                                else:
                                    self._logger.error("No location header found for redirect")  # Fehler loggen, wenn kein Location-Header gefunden wurde
                                    break
                            else:
                                self._logger.debug("Received status code {} for URL: {}".format(status_code, current_url))  # Debug-Nachricht mit erhaltenem Statuscode loggen
                                break
                        else:
                            self._logger.error("Failed to analyze response for URL: {}".format(current_url))  # Fehler loggen, wenn analyzeResponse null ist
                            break
                    else:
                        self._logger.error("Request error for {}: No raw response received".format(current_url))  # Fehler loggen, wenn keine Rohantwort erhalten
        except Exception as e:
            self._logger.error("Request error for {}: {}".format(url, e))  # Fehler loggen, wenn beim Senden der Anfrage ein Problem auftritt

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
            self._logger.error("File error: {}".format(e))  # Fehler loggen, wenn die Datei nicht gespeichert werden kann

    def get_base_url(self, headers):
        """
        Extrahiert die Basis-URL aus den Anfrage-Headern.
        """
        # Die erste Zeile der Header ist die Request Line (z.B. "GET /Test/Admin HTTP/1.1")
        request_line = headers[0]
        method, path, _ = request_line.split(' ', 2)  # Teilt die Zeile in Methode, Pfad und Version

        # Falls der Pfad keinen führenden Schrägstrich hat, fügen Sie einen hinzu
        if not path.startswith('/'):
            path = '/' + path

        # Extrahieren des Hostnamens aus den Headern
        for header in headers:
            if header.lower().startswith("host:"):
                host = header.split(':', 1)[1].strip()  # Hostnamen aus dem Header extrahieren
                break
        else:
            host = ""  # Falls kein Host-Header vorhanden ist, leere Zeichenfolge zurückgeben

        return "http://" + host

    def construct_full_url(self, base_url, directory):
        """
        Konstruiert eine vollständige URL durch Hinzufügen des Verzeichnisnamens zur Basis-URL.
        """
        # Sicherstellen, dass die Basis-URL mit einem Schrägstrich endet
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Falls das Verzeichnis einen führenden Schrägstrich hat, entfernen
        if directory.startswith('/'):
            directory = directory[1:]
        
        # Kombiniere Basis-URL und Verzeichnisnamen
        return base_url + directory
