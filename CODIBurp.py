# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import logging
import os
from java.net import URL, MalformedURLException

logging.basicConfig(level=logging.DEBUG)

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory Bruteforcer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        self.directories = []
        self.results = []
        self.load_seclist()
        
    def load_seclist(self):
        url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            url_obj = URL(url)
            input_stream = url_obj.openStream()
            content = input_stream.read()
            self.directories = content.splitlines()
        except MalformedURLException as e:
            logging.error("Malformed URL error: {}".format(e))
            self.directories = []
        except IOException as e:
            logging.error("Error loading SecList: {}".format(e))
            self.directories = []
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                if headers and len(headers) > 0:
                    base_url = headers[0].split()[1]
                    for directory in self.directories:
                        new_url = self.join_url(base_url, directory.strip())
                        self.send_request(new_url)
                else:
                    logging.error("Empty or invalid headers found in HTTP request")
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))
                
    def join_url(self, base_url, path):
        try:
            url = URL(base_url)
            return URL(url, path).toString()
        except MalformedURLException as e:
            logging.error("Malformed URL error: {}".format(e))
            return None
        
    def send_request(self, url):
        try:
            url_obj = URL(url)
            connection = url_obj.openConnection()
            connection.connectTimeout = 10000  # Timeout nach 10 Sekunden
            connection.readTimeout = 10000  # Timeout nach 10 Sekunden
            response_code = connection.getResponseCode()
            if response_code == 200:
                self.results.append(url)
                logging.debug("Directory found: {}".format(url))
            else:
                logging.debug("Received status code {} for URL: {}".format(response_code, url))
        except IOException as e:
            logging.error("Request error for {}: {}".format(url, e))
            
    def extensionUnloaded(self):
        self.save_results()
        
    def save_results(self):
        for result in self.results:
            logging.info("Directory found: {}".format(result))
