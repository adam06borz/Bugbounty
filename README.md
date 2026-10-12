# Bugbounty

Claude Code Skills für Bug-Bounty-Arbeit: Recon, Vuln-Hunting, Validierung, Reporting.

## Enthaltene Skills

| Skill | Inhalt |
|---|---|
| [`skills/bug-bounty`](skills/bug-bounty/SKILL.md) | Komplette Pipeline: Recon → Learn → Hunt → Validate → Report. IDOR, SSRF, XSS, Auth-Bypass, CSRF, Race Conditions, SQLi, XXE, File Upload, Business Logic, GraphQL, HTTP Smuggling, Cache Poisoning, OAuth/OIDC, SSTI, Subdomain Takeover, Cloud Misconfig, ATO-Chains, LLM/AI-Security (ASI01–ASI10). Dazu 7-Question Gate, 4 Validation Gates, CVSS 3.1, Report-Templates. |
| [`skills/web2-vuln-classes`](skills/web2-vuln-classes/SKILL.md) | Referenz zu 26 Web2-Bugklassen mit Root Causes, Detection-Patterns, Bypass-Tabellen und bezahlten Beispielen: SSRF (11 IP-Bypasses), File Upload (10 Bypasses), MFA-Bypass (7 Patterns), ATO (9 Pfade), JWT/Mass Assignment/Prototype Pollution/CORS, SAML, LFI/RCE, Deserialisierung, Dependency Confusion, Padding Oracle, LLM/AI inkl. MCP- und RAG-Angriffe. |
| [`skills/web2-recon`](skills/web2-recon/SKILL.md) | Recon-Pipeline von null bis priorisierter URL-Liste: Subdomain-Enum (crt.sh, Chaos API, subfinder, assetfinder), Live-Hosts (dnsx, httpx), Crawling (katana, waybackurls, gau), Fuzzing (ffuf), Port-Scan (naabu), JS-Analyse (LinkFinder, SecretFinder, trufflehog), Source-Disclosure (`.git`/`.svn`/`.DS_Store`-Dumps, Backup-/Swap-Files, `php://filter`, Env-/Config-Leaks), GitHub-Dorking, Tech-Stack→Bugklasse-Mapping, Target-Scoring (Go/No-Go), 30-Minuten-Protokoll und Continuous Monitoring. |

Die drei greifen ineinander: `web2-recon` liefert die Angriffsfläche, `bug-bounty` ist der Workflow darüber, und beide verweisen für Detailtechniken auf `web2-vuln-classes` (z. B. postMessage-Testing, Error-Disclosure-/Debug-Endpoints).

## Installation

Als persönliche Skills (gelten in allen Projekten):

```bash
BASE=https://raw.githubusercontent.com/adam06borz/Bugbounty/main/skills

for s in bug-bounty web2-vuln-classes web2-recon; do
  mkdir -p ~/.claude/skills/$s
  curl -sSL -o ~/.claude/skills/$s/SKILL.md "$BASE/$s/SKILL.md"
done

# web2-recon hat eine Referenzdatei
mkdir -p ~/.claude/skills/web2-recon/references
curl -sSL -o ~/.claude/skills/web2-recon/references/windows-setup.md \
  "$BASE/web2-recon/references/windows-setup.md"
```

Oder gleich das ganze Repo klonen, dann bleiben Referenzdateien automatisch dabei:

```bash
git clone --depth 1 https://github.com/adam06borz/Bugbounty.git /tmp/bb
cp -r /tmp/bb/skills/* ~/.claude/skills/
```

Oder projektbezogen: Datei nach `.claude/skills/<name>/SKILL.md` im Projekt legen.

Claude Code lädt einen Skill automatisch, sobald das Thema passt — `bug-bounty` beim Hunten und Reporting, `web2-recon` beim Start auf einem neuen Target, `web2-vuln-classes` beim Nachschlagen einer konkreten Bugklasse.

## Scope-Hinweis

Die Skills setzen eine Autorisierung voraus — ein Bug-Bounty-Programm im Scope, ein beauftragtes Pentest-Engagement oder eigene Systeme. Vor jedem Hunt den Programm-Scope lesen und jeden Asset/Domain gegen die Freigabe prüfen.

## Herkunft

Die Skills stammen aus [Awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (MIT, siehe [LICENSE](LICENSE)). Das Upstream-Repo hat 19 Skills, von denen hier 3 liegen — die übrigen 16 sind u. a. `llm-redteam`, `report-writing`, `triage-validation`, `cloud-pentest`, `graphql-audit`, `mobile-pentest`, `mcp-server-audit`, `cicd-security`, `credential-attack`, `agentic-app-audit`, `web3-audit`, `security-arsenal`, `bb-methodology`, `argus`, `client-reverse`, `meme-coin-audit`.
