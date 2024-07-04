from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse
import sqlite3
import requests
from urllib.parse import urljoin
import logging

logging.basicConfig(level=logging.DEBUG)

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    # Diese Methode registriert die Erweiterungs-Callbacks bei BurpSuite
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory Bruteforcer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        self.init_db()
        self.load_seclist()
        
    # Diese Methode initialisiert die SQLite-Datenbank
    def init_db(self):
        try:
            self.conn = sqlite3.connect(':memory:')  # In-memory database for simplicity
            self.cursor = self.conn.cursor()
            self.cursor.execute('CREATE TABLE directories (name TEXT)')
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            self.conn = None
        
    # Diese Methode lädt die SecList von einer URL und speichert sie in einer Liste
    def load_seclist(self):
        url = 'https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/main/testdirectories.txt'
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an HTTPError for bad responses
            self.directories = response.text.splitlines()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error loading SecList: {e}")
            self.directories = []  # Handle appropriately
        
    # Diese Methode verarbeitet HTTP-Anfragen, um Verzeichnisscans durchzuführen
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            try:
                request = self._helpers.analyzeRequest(messageInfo)
                headers = request.getHeaders()
                url = headers[0].split()[1]
                for directory in self.directories:
                    new_url = url + directory
                    self.send_request(new_url)
            except Exception as e:
                logging.error(f"Error processing HTTP message: {e}")
                
    # Diese Methode sendet eine HTTP-Anfrage und speichert gültige Verzeichnisse in der Datenbank
    def send_request(self, url):
        try:
            response = requests.get(url, timeout=10)  # Timeout nach 10 Sekunden
            if response.status_code == 200:
                self.cursor.execute('INSERT INTO directories (name) VALUES (?)', (url,))
                self.conn.commit()
                logging.debug(f"Directory found: {url}")
            else:
                logging.debug(f"Received status code {response.status_code} for URL: {url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            
    # Diese Methode wird aufgerufen, wenn die Erweiterung entladen wird
    def extensionUnloaded(self):
        self.save_results()
        if self.conn:
            self.conn.close()
        
    # Diese Methode speichert die Ergebnisse aus der Datenbank in einer Datei
    def save_results(self):
        try:
            with open('results.txt', 'w') as f:
                self.cursor.execute('SELECT name FROM directories')
                rows = self.cursor.fetchall()
                for row in rows:
                    f.write(row[0] + '\n')
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
        except IOError as e:
            logging.error(f"File error: {e}")