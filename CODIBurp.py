# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener
import logging

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
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService("raw.githubusercontent.com", 443, True)
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(http_service)
            request.setUrl(url)
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            # Wenn Antwort erfolgreich (Statuscode 200), Verzeichnisnamen auslesen
            if response and response.getStatusCode() == 200:
                # Antwort analysieren und in Zeilen aufteilen
                analyzed_response = self._helpers.analyzeResponse(response)
                self.directories = analyzed_response.getResponse().tostring().splitlines()
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
                base_url = headers[0].split()[1]  # Basis-URL aus der ersten Zeile der Anfrage extrahieren
                # Für jeden Verzeichnisnamen in der SecList
                for directory in self.directories:
                    # Neue URL erstellen durch Hinzufügen des Verzeichnisnamens
                    new_url = base_url + "/" + directory.strip().decode('utf-8')  # Strip und Decode anpassen
                    self.send_request(new_url)  # HTTP-Anfrage senden
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))  # Fehler loggen

    def send_request(self, url):
        try:
            # HTTP-Service für die URL erstellen
            http_service = self._helpers.buildHttpService(self.get_host(url), 443, True)
            # HTTP-Anfrage für die URL erstellen
            request = self._helpers.buildHttpRequest(http_service, url)
            # HTTP-Anfrage senden und Antwort erhalten
            response = self._callbacks.makeHttpRequest(http_service, request)
            # Wenn Antwort erfolgreich (Statuscode 200), URL zu den Ergebnissen hinzufügen
            if response and response.getStatusCode() == 200:
                self.results.append(url)  # URL zu den Ergebnissen hinzufügen
                logging.debug("Directory found: {}".format(url))  # Debug-Nachricht loggen
            else:
                logging.debug("Received status code {} for URL: {}".format(response.getStatusCode(), url))
                # Debug-Nachricht mit erhaltenem Statuscode loggen
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

    def get_host(self, url):
        return self._helpers.analyzeRequest(url).getUrl().getHost()  # Hostnamen aus der URL extrahieren
