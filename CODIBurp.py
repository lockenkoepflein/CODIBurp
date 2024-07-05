# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse, IHttpService
import logging

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
            # Get the IHttpService for the URL from the current request
            http_service = self.get_http_service_from_request()
            
            # Make the HTTP request to load the SecList
            response = self._callbacks.makeHttpRequest(http_service, self._helpers.buildHttpRequest(self.get_target_url(), None))
            
            if response.getStatusCode() == 200:
                content = response.getResponse()
                self.directories = content.splitlines()
                logging.debug("SecList loaded successfully")
            else:
                logging.error("Failed to load SecList: HTTP %d" % response.getStatusCode())
                self.directories = []
        except Exception as e:
            logging.error("Error loading SecList: %s" % str(e))
            self.directories = []
        
    def get_http_service_from_request(self):
        # Get the IHttpService for the URL from the current request
        request_info = self._helpers.analyzeRequest(self._callbacks.getProxyHistory()[-1])  # Get the latest intercepted request
        return request_info.getHttpService()
    
    def get_target_url(self):
        # Get the target URL from the current request
        request_info = self._helpers.analyzeRequest(self._callbacks.getProxyHistory()[-1])  # Get the latest intercepted request
        return self._helpers.buildHttpService(request_info.getHost(), request_info.getPort(), request_info.getProtocol())
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                base_url = headers[0].split()[1]
                for directory in self.directories:
                    new_url = self.build_url(base_url, directory.strip())
                    self.send_request(new_url)
            except Exception as e:
                logging.error("Error processing HTTP message: %s" % str(e))
    
    def build_url(self, base_url, directory):
        if not base_url.startswith("http"):
            base_url = "http://" + base_url  # prepend http if not present
        if base_url.endswith("/"):
            return base_url + directory
        else:
            return base_url + "/" + directory
    
    def send_request(self, url):
        try:
            # Make HTTP request to the constructed URL
            http_service = self.get_http_service_from_request()
            response = self._callbacks.makeHttpRequest(http_service, self._helpers.buildHttpRequest(url))
            
            if response.getStatusCode() == 200:
                self.results.append(url)
                logging.debug("Directory found: %s" % url)
            else:
                logging.debug("Received status code %d for URL: %s" % (response.getStatusCode(), url))
        except Exception as e:
            logging.error("Request error for %s: %s" % (url, str(e)))
    
    def extensionUnloaded(self):
        self.save_results()
    
    def save_results(self):
        try:
            with open('results.txt', 'w') as f:
                for result in self.results:
                    f.write(result + '\n')
        except IOError as e:
            logging.error("File error: %s" % str(e))
