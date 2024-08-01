# BurpSuite Extension - Content Discovery/Inhaltserkennung

## Status
This project is under development. Features and implementations may not yet be complete or stable.<br>Dieses Projekt befindet sich in der Entwicklung. Funktionen und Implementierungen sind möglicherweise noch nicht vollständig oder stabil.

## Description/Beschreibung
A Content Discovery Extension for Burp Suite - The automated discovery of hidden directories on web servers to identify potential security vulnerabilities.<br>Eine Inhaltserkennungs-Erweiterung für Burp Suite - Das automatisierte Auffinden verborgener Verzeichnisse auf Webservern zur Identifizierung potenzieller Sicherheitslücken.

## Setup/Einrichtung

1. **Jython einrichten**:
   - Laden Sie die [jython.jar](https://www.jython.org/downloads.html) herunter.
   - Öffnen Sie Burp Suite und gehen Sie zu `Extender` > `Options`.
   - Fügen Sie die heruntergeladene `jython.jar`-Datei unter "Python Environment" hinzu.

2. **Erweiterung herunterladen**:
   - Laden Sie die neueste Version der Erweiterung von [GitHub](https://github.com/lockenkoepflein/CODIBurp/releases/latest) herunter.

3. **Erweiterung hinzufügen**:
   - Gehen Sie zu `Extender` > `Extensions` und klicken Sie auf `Add`.
   - Ändern Sie den Erweiterungstyp auf `Python`.
   - Wählen Sie die heruntergeladene `.py`-Datei und klicken Sie auf `Next`.

## Verwendung/Usage

1. **Erweiterung starten**:
   - Nachdem die Erweiterung erfolgreich geladen wurde, sehen Sie eine neue Registerkarte „Directory Bruteforcer“ in Burp Suite.
   - Geben Sie die Basis-URL für den Bruteforce-Angriff in das Textfeld unter „Configuration“ ein.

2. **Verzeichnisliste laden**:
   - Die Verzeichnisliste (SecList) wird beim Start der Erweiterung automatisch im Hintergrund geladen. Sie können den Fortschritt in der Registerkarte „Progress“ verfolgen.

3. **Bruteforce starten**:
   - Klicken Sie auf „Start“, um den Bruteforce-Prozess zu beginnen. Die Erweiterung wird die angegebenen Verzeichnisse gegen die Basis-URL testen.

4. **Bruteforce stoppen**:
   - Klicken Sie auf „Stop“, um den Bruteforce-Prozess jederzeit zu stoppen.

5. **Ergebnisse anzeigen**:
   - Ergebnisse werden in der Registerkarte „Results“ angezeigt und in der Datei `results.txt` gespeichert, die im Verzeichnis der Erweiterung abgelegt wird.

## Anforderungen/Requirements

- [Jython 2.7.0](https://www.jython.org/downloads.html)
- [Burp Suite Pro v2.1](https://portswigger.net/burp)

---

## Setup/Installation

1. **Set up Jython**:
   - Download the [jython.jar](https://www.jython.org/downloads.html).
   - Open Burp Suite and go to `Extender` > `Options`.
   - Add the downloaded `jython.jar` file under "Python Environment".

2. **Download the Extension**:
   - Download the latest version of the extension from [GitHub](https://github.com/lockenkoepflein/CODIBurp/releases/latest).

3. **Add the Extension**:
   - Go to `Extender` > `Extensions` and click `Add`.
   - Change the extension type to `Python`.
   - Select the downloaded `.py` file and click `Next`.

## Usage

1. **Start the Extension**:
   - Once the extension is successfully loaded, you will see a new tab named "Directory Bruteforcer" in Burp Suite.
   - Enter the base URL for the brute force attack in the text field under "Configuration".

2. **Load the Directory List**:
   - The directory list (SecList) will be loaded in the background when the extension starts. You can track the progress in the "Progress" tab.

3. **Start Brute Force**:
   - Click "Start" to begin the brute force process. The extension will test the specified directories against the base URL.

4. **Stop Brute Force**:
   - Click "Stop" to halt the brute force process at any time.

5. **View Results**:
   - Results will be displayed in the "Results" tab and saved in the `results.txt` file located in the extension's directory.


## Code Credits
A large portion of the base code has been taken from the following sources:<br>Ein großer Teil des Basiscodes stammt aus den folgenden Quellen:

## License/Lizenz
The project is available under MIT license, see [LICENSE](https://github.com/lockenkoepfein/CODIBurp/LICENSE) file.<br>Das Projekt ist unter der MIT-Lizenz verfügbar, siehe [LICENSE](https://github.com/lockenkoepfein/CODIBurp/LICENSE)-Datei.
