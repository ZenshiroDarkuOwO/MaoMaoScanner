<div align="center">

# 🐈 MaoMaoScanner

**Scharfe Krallen für scharfe Logs**

*Ein modernes, Sigma-basiertes Tool zur Erkennung von Cyberangriffen in Windows-Ereignisprotokollen (EVTX).*

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-1f6feb)](https://github.com/TomSchimansky/CustomTkinter)
[![Sigma](https://img.shields.io/badge/Rules-Sigma-a371f7)](https://github.com/SigmaHQ/sigma)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-ff5c57)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 📖 Über das Projekt

**ZenPCanalys** ist ein leichtgewichtiges, aber leistungsfähiges Security-Tool, das Windows-Ereignisprotokolle (`.evtx`) analysiert. Es nutzt das weltweit standardisierte **Sigma-Regelformat**, um Bedrohungen zu erkennen, und bietet eine moderne, dunkle Benutzeroberfläche für die tägliche Arbeit im Security Operations Center (SOC) oder für DFIR-Analysten.

Das Tool wurde entwickelt, um die Lücke zwischen einfachen Log-Parsern und komplexen, teuren SIEM-Lösungen zu schließen. Es ist schnell, lokal ausführbar und benötigt keine Cloud-Anbindung.

> *„Die Katze lässt das Log nicht aus.“*

---

## ✨ Hauptfunktionen

- **🔍 Umfassende Erkennung:** Über 26 Sigma-Regeln, die **24 Techniken** aus **8 Taktiken** des MITRE ATT&CK-Frameworks abdecken.
- **📁 Einzel- und Batch-Scan:** Analysiere eine einzelne `.evtx`-Datei oder einen ganzen Ordner voller Logs mit einem Klick.
- **📡 Live-Überwachung:** Überwache Windows-Kanäle (`System`, `Application`, `Security`) in Echtzeit und erhalte sofortige Warnungen bei verdächtigen Aktivitäten.
- **🎨 Moderne Benutzeroberfläche:** Eine übersichtliche, dunkle Oberfläche mit animierten Statistiken, Filtern nach Schweregrad und einem Detail-Panel für jedes Ereignis.
- **📄 Export-Funktionen:** Speichere die Ergebnisse als strukturiertes JSON oder als eleganten HTML-Bericht für Präsentationen und Reports.
- **🧠 Sigma-Standard:** Alle Regeln sind im standardisierten YAML-Format (Sigma) geschrieben und können leicht angepasst oder erweitert werden.
- **🐈 Mao Mao Edition:** Ein Hauch von Persönlichkeit – mit einer Katze, die über die Logs wacht.

---

## 🛡️ Abgedeckte MITRE ATT&CK Taktiken

| Taktik | Abgedeckte Techniken (Auszug) |
| :--- | :--- |
| **Initial Access** | Phishing (T1566.001) |
| **Execution** | PowerShell (T1059.001), WMI (T1047) |
| **Persistence** | Scheduled Tasks (T1053.005), Service Creation (T1543.003) |
| **Privilege Escalation** | UAC Bypass (T1548.002), Process Injection (T1055) |
| **Defense Evasion** | Indicator Removal (T1070.001), Security Log Cleared |
| **Credential Access** | LSASS Access (T1003.001), Kerberoasting (T1558.003), Brute Force (T1110) |
| **Lateral Movement** | RDP/SMB (T1021.001, T1021.002) |
| **Impact** | Inhibit System Recovery (T1490), Ransomware Extensions (T1486) |

---

## 🚀 Installation & Ausführung

### Voraussetzungen
- Windows 10 oder 11
- Python 3.11 oder neuer (nur für die Entwicklung)

### Als ausführbare Datei (.exe)

Die einfachste Methode ist die Verwendung der vorkompilierten `ZenPCanalys.exe`:

1. Lade die `ZenPCanalys.exe` aus dem `dist`-Ordner herunter.
2. Führe die Datei aus. Es ist keine Installation erforderlich.
3. *Hinweis:* Für die Live-Überwachung des `Security`-Kanals werden Administrator-Rechte benötigt.

### Aus dem Quellcode (für Entwickler)

```bash
# 1. Repository klonen
git clone https://github.com/dein-benutzername/ZenPCanalys.git
cd ZenPCanalys

# 2. Virtuelle Umgebung erstellen und aktivieren
python -m venv .venv
.\.venv\Scripts\activate

# 3. Abhängigkeiten installieren
python -m pip install -r requirements.txt

# 4. Anwendung starten
python -m zen.gui