# Windows-Setup — Abweichungen zur SKILL.md

Die Befehle in `SKILL.md` sind für Linux/macOS geschrieben. Dieses Setup läuft native auf
Windows 11 in **Git Bash** (`C:\Program Files\Git\bin\bash.exe`). Alles unten ist auf dieser
Maschine installiert und einzeln geprüft — die Tabellen nennen den echten Pfad, nicht den
aus der SKILL.md.

**Shell:** Git Bash. `/tmp` existiert und zeigt auf `C:\Users\adam\AppData\Local\Temp`, die
`/tmp/...`-Pipelines der SKILL.md laufen also unverändert. PowerShell ist für diese Pipelines
ungeeignet (kein `|` für Textzeilen, kein `tee`-Verhalten wie POSIX).

---

## Installierte Tools

Go-Binaries in `C:\Users\adam\go\bin` (liegt im User-PATH):

| Tool | Version | Aufruf |
|---|---|---|
| subfinder | v2.17.0 | `subfinder` |
| httpx | v1.12.0 | `httpx` |
| dnsx | aktuell | `dnsx` |
| katana | v1.8.0 | `katana` |
| nuclei | v3.11.1 | `nuclei` |
| naabu | aktuell | `naabu` |
| interactsh-client | aktuell | `interactsh-client` |
| ffuf | 2.1.0-dev | `ffuf` |
| gau | 2.2.4 | `gau` |
| waybackurls | aktuell | `waybackurls` |
| assetfinder | aktuell | `assetfinder` |
| anew | aktuell | `anew` |
| gf | aktuell | `gf` |
| unfurl | aktuell | `unfurl` |
| dalfox | aktuell | `dalfox` |
| trufflehog | 3.99.2 | `trufflehog` |
| git-dumper | via Shim | `git-dumper` |

Weitere: `jq` 1.8.2, `sqlite3`, `wget`, `perl`, `strings`, `vim` — alle im PATH.

Python-Tools unter `C:\Users\adam\tools\`, jedes mit eigenem venv:

| Tool | Aufruf (Git Bash) |
|---|---|
| SecretFinder | `~/tools/SecretFinder/.venv/Scripts/python.exe ~/tools/SecretFinder/SecretFinder.py -i <url> -o cli` |
| LinkFinder | `~/tools/LinkFinder/.venv/Scripts/python.exe ~/tools/LinkFinder/linkfinder.py -i <url> -o cli` |
| ds_store_exp | `~/tools/ds_store_exp/.venv/Scripts/python.exe ~/tools/ds_store_exp/ds_store_exp.py <url>/.DS_Store` |
| GitTools | `bash ~/tools/GitTools/Dumper/gitdumper.sh <url>/.git/ <dir>` |
| dvcs-ripper | `perl ~/tools/dvcs-ripper/rip-hg.pl -v -u <url>/.hg/` |

---

## Die sieben Abweichungen

**1. venv aktivieren — `Scripts`, nicht `bin`.**
SKILL.md schreibt `source ~/tools/SecretFinder/.venv/bin/activate`. Auf Windows:

```bash
source ~/tools/SecretFinder/.venv/Scripts/activate
```

Besser: gar nicht aktivieren, sondern das venv-Python direkt aufrufen (siehe Tabelle oben) —
dann kann kein falsches Python erwischt werden.

**2. subfinder-Config liegt anderswo und heißt anders.**
SKILL.md legt `~/.config/subfinder/config.yaml` mit `virustotal: [KEY]` an. Aktuelles subfinder
nutzt auf Windows:

```
C:\Users\adam\AppData\Roaming\subfinder\provider-config.yaml
```

Das Format ist eine flache Liste pro Quelle, nicht das alte `config.yaml`-Schema:

```yaml
virustotal: [DEIN_KEY]
securitytrails: [DEIN_KEY]
shodan: [DEIN_KEY]
censys: [ID:SECRET]
chaos: [DEIN_KEY]
github: [DEIN_PAT]
```

Die Datei existiert schon mit 40 Quellen, alle Werte leer (`[]`). subfinder läuft auch ohne
Keys — dann nur mit den schlüssellosen Quellen, also deutlich weniger Treffer.

**3. Environment-Variablen persistent setzen.**
SKILL.md schreibt in `~/.zshrc`. Hier entweder Git Bash:

```bash
echo 'export CHAOS_API_KEY="dein-key"' >> ~/.bashrc
```

oder als Windows-User-Variable (gilt dann auch in PowerShell und für Scheduled Tasks):

```powershell
[Environment]::SetEnvironmentVariable('CHAOS_API_KEY', 'dein-key', 'User')
```

**4. nuclei-Templates — Pfad stimmt.**
`~/nuclei-templates/` existiert mit 14.036 Templates (88 MB), also läuft
`nuclei -t ~/nuclei-templates/` wie dokumentiert. `nuclei -update-templates` wöchentlich.

**5. Wordlists — `BackupFiles.fuzz.txt` gibt es nicht mehr.**
SecLists liegt unter `C:\Users\adam\wordlists\SecLists` (2,7 GB, depth-1-Clone), die
SKILL.md-Pfade `~/wordlists/SecLists/Discovery/Web-Content/...` passen also. Zwei Ausnahmen:

| SKILL.md | Realität |
|---|---|
| `~/wordlists/common.txt` | angelegt (4.751 Zeilen, aus `Discovery/Web-Content/common.txt`) |
| `~/wordlists/api-endpoints.txt` | angelegt (295 Zeilen, aus `Discovery/Web-Content/api/api-endpoints.txt`) |
| `SecLists/.../BackupFiles.fuzz.txt` | **aus SecLists entfernt** — Ersatz siehe unten |
| `SecLists/.../raft-large-files.txt` | vorhanden (37.050 Zeilen) |

Ersatz für den Backup-Fuzzing-Schritt:

```bash
# Extension-Mutationen auf bekanntem Basename
ffuf -u "https://target.com/configFUZZ" -w ~/wordlists/backup-ext.txt -mc 200 -ac -t 20

# Backup-/Archivnamen im Webroot (DB-Dumps + Archiv-Extensions)
ffuf -u "https://target.com/FUZZ" -w ~/wordlists/backup-files.txt -mc 200 -ac -fs 0 -t 30
```

**6. Continuous Monitoring — kein cron.**
Statt `crontab -e` die Windows-Aufgabenplanung. Das Monitoring-Script aus der SKILL.md
unverändert lassen und über Git Bash starten:

```powershell
schtasks /create /tn "BB-SubsWatch" /tr "\"C:\Program Files\Git\bin\bash.exe\" -lc \"~/monitors/subs-watch.sh\"" /sc daily /st 08:00
schtasks /create /tn "BB-GitHubWatch" /tr "\"C:\Program Files\Git\bin\bash.exe\" -lc \"~/monitors/github-watch.sh\"" /sc minute /mo 30
```

**7. Zwei Tools fehlen bzw. weichen ab.**

| Betroffen | Lage |
|---|---|
| `pipx install git-dumper` | Kein pipx. git-dumper liegt im venv `~/tools/git-dumper`, erreichbar über die Shims `go\bin\git-dumper` (Git Bash) und `go\bin\git-dumper.cmd` (PowerShell). Aufruf wie dokumentiert. |
| `rip-svn.pl` | Läuft **nicht** — Perl-Modul `DBI` fehlt in Git Bash. Kein Problem: der SVN-Weg der SKILL.md geht über `curl .svn/wc.db` + `sqlite3`, und sqlite3 ist installiert. `rip-hg.pl` und `rip-bzr.pl` laufen. |
| `trufflehog` | `go install` schlägt fehl (replace-Direktiven in der go.mod). Installiert ist das Release-Binary v3.99.2 aus GitHub Releases. Funktional identisch. |
| naabu SYN-Scan | `naabu -s s` funktioniert hier, ebenso `-s c` (Connect). Falls nach einem Windows-Update ein npcap-Fehler kommt: `-s c` nehmen, das braucht keinen Treiber. |

---

## gf-Patterns

`~/.gf` enthält 37 Patterns (aus `1ndianl33t/Gf-Patterns` und `tomnomnom/gf`), darunter alle
in der SKILL.md benutzten: `xss`, `ssrf`, `idor`, `sqli`, `redirect`, `lfi`, `rce`, dazu
`debug-pages`, `takeovers`, `aws-keys`, `s3-buckets`, `upload-fields`, `interestingparams`.

```bash
gf -list   # alle anzeigen
```

---

## Was noch fehlt

- **API-Keys.** `CHAOS_API_KEY` ist nicht gesetzt, und alle 40 subfinder-Quellen sind ohne Key.
  Bis das nachgeholt ist, liefert Step 1 der Pipeline (Chaos) nichts und Step 2 (subfinder)
  nur die schlüssellosen Quellen. Kostenlose Keys: chaos.projectdiscovery.io, virustotal.com,
  securitytrails.com, censys.io, shodan.io.
- **Burp Suite.** Die SKILL.md verlangt in „Minutes 25-30" einen Proxy-Durchlauf. Nicht
  installiert.
- **End-to-End-Test.** Die Tools sind einzeln geprüft (Resolve, HTTP-Request, Port-Scan auf
  127.0.0.1, Text-Pipeline mit anew/unfurl/gf, alle `-h`/`-version`). Die komplette Pipeline
  ist **nicht** gegen ein echtes Ziel gelaufen — das braucht ein Target im Scope.
