# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import urllib2
import logging
import os

logging.basicConfig(level=logging.DEBUG)

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        # Speichert die Referenz auf die BurpSuite Callbacks und Helferobjekte
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Setzt den Namen der Erweiterung in BurpSuite
        callbacks.setExtensionName("Directory Bruteforcer")
        
        # Registriert die HTTP- und Zustandshörer für diese Erweiterung
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        # Initialisiert leere Listen für Verzeichnisse und Ergebnisse
        self.directories = []
        self.results = []
        
        # Lädt die Liste der zu testenden Verzeichnisse von einer URL
        self.load_seclist()
        
    def load_seclist(self):
        # Lädt die SecList von einer URL und speichert sie in self.directories
        url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            response = urllib2.urlopen(url)
            self.directories = response.read().splitlines()
        except urllib2.URLError as e:
            logging.error("Error loading SecList: {}".format(e))
            self.directories = []
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Verarbeitet eingehende HTTP-Nachrichten, um Verzeichnisscans durchzuführen
        if messageIsRequest:
            try:
                # Analysiert die HTTP-Anfrage mit Hilfe von BurpSuite Helferobjekten
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                
                # Überprüft, ob gültige Header vorhanden sind
                if headers and len(headers) > 0:
                    base_url = headers[0].split()[1]  # Extrahiert die Basis-URL aus den Headern
                    for directory in self.directories:
                        new_url = urllib2.urljoin(base_url, directory.strip())  # Kombiniert Basis-URL mit Verzeichnis
                        self.send_request(new_url)  # Sendet die Anfrage an die kombinierte URL
                else:
                    logging.error("Empty or invalid headers found in HTTP request")
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))
                
    def send_request(self, url):
        # Sendet eine HTTP-Anfrage und speichert gültige Verzeichnisse in self.results
        try:
            request = urllib2.Request(url)
            response = urllib2.urlopen(request, timeout=10)  # Timeout nach 10 Sekunden
            if response.getcode() == 200:
                self.results.append(url)  # Fügt gültige URLs zu den Ergebnissen hinzu
                logging.debug("Directory found: {}".format(url))
            else:
                logging.debug("Received status code {} for URL: {}".format(response.getcode(), url))
        except urllib2.URLError as e:
            logging.error("Request error for {}: {}".format(url, e))
            
    def extensionUnloaded(self):
        # Wird aufgerufen, wenn die Erweiterung entladen wird, um Ergebnisse zu speichern oder Aufräumarbeiten durchzuführen
        self.save_results()
        
    def save_results(self):
        # Speichert die gefundenen Verzeichnisse in einer Datei oder gibt sie aus
        for result in self.results:
            logging.info("Directory found: {}".format(result))
