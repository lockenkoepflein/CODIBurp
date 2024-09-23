# Burp Suite Extension „CODIBurp“

## Beschreibung
Eine Inhaltserkennungs-Erweiterung für Burp Suite – das automatisierte Auffinden verborgener Verzeichnisse und Dateien auf Webservern zur Identifizierung potenzieller Sicherheitslücken.

## Installation/Einrichtung

1. **Burp Suite Community Edition installieren:**  
   [Download Burp Suite Community Edition - PortSwigger](https://portswigger.net/burp/communitydownload)

2. **Jython standalone jar-Datei herunterladen:**  
   [Downloads | Jython](https://www.jython.org/download)  
   (hier unter Jython Standalone); es ist die Datei mit dem Format „jython-standalone-X.X.X.jar“.

3. **Burp Suite starten:**  
   ![Screenshot1](images/Bild1.png)  
   ![Screenshot2](images/Bild2.png)

4. **Einstellungen in Burp Suite Settings unter Extensions vornehmen:**  
   ![Screenshot3](images/Bild3.png)  
   Hier in die entsprechenden Felder die Jython Standalone JAR-Datei und ggf. den Pfad für die Extension hinterlegen.

5. **CODIBurp.py-Datei aus GitHub-Repository herunterladen:**  
   [CODIBurp/CODIBurp.py at main · lockenkoepflein/CODIBurp · GitHub](https://github.com/lockenkoepflein/CODIBurp/blob/main/CODIBurp.py)  
   Speichern Sie die Datei im Verzeichnis, das im Feld „Folder for loading modules“ angegeben wurde.

6. **In Burp Suite unter „Extensions“ den Button „Add“ betätigen:**  
   ![Screenshot4](images/Bild4.png)

   - **Extension type:** Python wählen.
   - **Als Extension file** die heruntergeladene .py-Datei auswählen.
   - Dann den Button „Next“ betätigen.  
   ![Screenshot5](images/Bild5.png)

   Die Extension wird nun in die Burp Suite geladen, und die GUI des Tools sollte sich aufbauen.  
   Falls Probleme beim Laden bestehen, werden diese unter „Errors“ ausgegeben:  
   ![Screenshot6](images/Bild6.png)

## Verwendung

**GUI mit Kurzbeschreibung:**  
![Screenshot7](images/Bild7.png)

Nach beispielhafter Konfiguration und Starten des Bruteforce-Prozesses über den „Start“-Button sieht man den aktuellen Fortschritt auf dem Fortschrittsbalken:  
![Screenshot8](images/Bild8.png)

Für den Bruteforce-Prozess können folgende Listen (aber auch andere) verwendet werden:
- [common_directorynames.txt](https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/refs/heads/main/common_directorynames.txt)
- [common_filenames.txt](https://raw.githubusercontent.com/lockenkoepflein/CODIBurp/refs/heads/main/common_filenames.txt)

Zu beachten ist, dass die URLs auf eine Liste verweisen, in der sich in jeder neuen Zeile ein Datei- bzw. Verzeichnisname befindet.

Ist der Bruteforce-Prozess anhand der konfigurierten Listen abgeschlossen, wird der Button „Save Results“ aktiv und es erscheint unter „Progress“ folgende Meldung:  
![Screenshot9](images/Bild9.png)

Beim Wechsel in den Reiter „Results“ werden die gefundenen Dateien und Verzeichnisse aufgelistet (nur Ergebnisse mit den gewünschten Statuscodes werden angezeigt):  
![Screenshot10](images/Bild10.png)

Wird der Button „Save Results“ betätigt, wird eine .txt-Datei im Verzeichnis angelegt, in dem sich die .py-Datei befindet. Diese enthält die gefundenen Verzeichnisse und Dateien:  
![Screenshot11](images/Bild11.png)

## Lizenz
Das Projekt ist unter der MIT-Lizenz verfügbar, siehe [LICENSE](https://github.com/lockenkoepflein/CODIBurp/LICENSE)-Datei.
