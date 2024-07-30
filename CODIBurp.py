# -*- coding: utf-8 -*-
from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import logging
from java.net import URL

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
        seclist_url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            http_service = self._helpers.buildHttpService("raw.githubusercontent.com", 443, True)
            request = self._helpers.buildHttpRequest(URL(seclist_url))
            response = self._callbacks.makeHttpRequest(http_service, request)
            if response:
                raw_response = response.getResponse()
                response_info = self._helpers.analyzeResponse(raw_response)
                if response_info.getStatusCode() == 200:
                    body_offset = response_info.getBodyOffset()
                    response_body = raw_response[body_offset:].tostring()
                    self.directories = response_body.splitlines()
                    logging.info("SecList loaded successfully")
                else:
                    logging.error("Failed to load SecList, status code: {}".format(response_info.getStatusCode()))
            else:
                logging.error("Failed to load SecList: No response received")
        except Exception as e:
            logging.error("Error loading SecList: {}".format(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                base_url = self.get_base_url(request, headers)
                if not base_url:
                    logging.error("Base URL could not be determined")
                    return

                for directory in self.directories:
                    new_url = self.construct_full_url(base_url, directory.strip())
                    logging.debug("Constructed URL: {}".format(new_url))
                    self.send_request(new_url)
            except Exception as e:
                logging.error("Error processing HTTP message: {}".format(e))

    def send_request(self, url):
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
                if response_info.getStatusCode() == 200:
                    self.results.append(url)
                    logging.debug("Directory found: {}".format(url))
                else:
                    logging.debug("Received status code {} for URL: {}".format(response_info.getStatusCode(), url))
            else:
                logging.error("Request error for {}: No response received".format(url))
        except Exception as e:
            logging.error("Request error for {}: {}".format(url, e))

    def extensionUnloaded(self):
        self.save_results()

    def save_results(self):
        try:
            with open('results.txt', 'w') as f:
                for result in self.results:
                    f.write(result + '\n')
        except IOError as e:
            logging.error("File error: {}".format(e))

    def get_base_url(self, request, headers):
        http_service = request.getHttpService()
        protocol = http_service.getProtocol()

        # Finde den "Host" Header
        host_header = ""
        for header in headers:
            if header.lower().startswith("host:"):
                host_header = header.split(":", 1)[1].strip()
                break

        # Extrahiere das Verzeichnis aus der ersten Zeile der Header
        first_line = headers[0].split()
        path = first_line[1] if len(first_line) > 1 else ""

        # Konstruiere die Basis-URL
        return f"{protocol}://{host_header}{path}"

    def construct_full_url(self, base_url, directory):
        return base_url.rstrip("/") + "/" + directory.lstrip("/")
