# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import urllib2
import logging
import os

logging.basicConfig(level=logging.DEBUG)

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    # Diese Methode registriert die Erweiterungs-Callbacks bei BurpSuite
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory Bruteforcer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        self.directories = []
        self.load_seclist()
        
    # Diese Methode lädt die SecList von einer URL und speichert sie in einer Liste
    def load_seclist(self):
        url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            response = urllib2.urlopen(url)
            self.directories = response.read().splitlines()
        except urllib2.URLError as e:
            logging.error("Error loading SecList: {}".format(e))
            self.directories = []  # Handle appropriately
        
    # Diese Methode verarbeitet HTTP-Anfragen, um Verzeichnisscans durchzuführen
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                base_url = headers[0].split()[1]
                for directory in self.directories:
                    new_url = self._helpers.buildHttpMessage([base_url, directory], None)
                    self.send_request(new_url)
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))
                
    # Diese Methode sendet eine HTTP-Anfrage und protokolliert gültige Verzeichnisse
    def send_request(self, url):
        try:
            request = urllib2.Request(url)
            response = urllib2.urlopen(request, timeout=10)  # Timeout nach 10 Sekunden
            if response.getcode() == 200:
                logging.info("Directory found: {}".format(url))
            else:
                logging.debug("Received status code {} for URL: {}".format(response.getcode(), url))
        except urllib2.URLError as e:
            logging.error("Request error for {}: {}".format(url, e))
            
    # Diese Methode wird aufgerufen, wenn die Erweiterung entladen wird
    def extensionUnloaded(self):
        pass  # Hier könnte z.B. aufgeräumt werden, wenn nötig
