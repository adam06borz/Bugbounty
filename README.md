# Bugbounty

Claude Code Skills für Bug-Bounty-Arbeit: Recon, Vuln-Hunting, Validierung, Reporting.

## Enthaltene Skills

| Skill | Inhalt |
|---|---|
| [`skills/bug-bounty`](skills/bug-bounty/SKILL.md) | Komplette Pipeline: Recon → Learn → Hunt → Validate → Report. IDOR, SSRF, XSS, Auth-Bypass, CSRF, Race Conditions, SQLi, XXE, File Upload, Business Logic, GraphQL, HTTP Smuggling, Cache Poisoning, OAuth/OIDC, SSTI, Subdomain Takeover, Cloud Misconfig, ATO-Chains, LLM/AI-Security (ASI01–ASI10). Dazu 7-Question Gate, 4 Validation Gates, CVSS 3.1, Report-Templates. |
| [`skills/web2-vuln-classes`](skills/web2-vuln-classes/SKILL.md) | Referenz zu 26 Web2-Bugklassen mit Root Causes, Detection-Patterns, Bypass-Tabellen und bezahlten Beispielen: SSRF (11 IP-Bypasses), File Upload (10 Bypasses), MFA-Bypass (7 Patterns), ATO (9 Pfade), JWT/Mass Assignment/Prototype Pollution/CORS, SAML, LFI/RCE, Deserialisierung, Dependency Confusion, Padding Oracle, LLM/AI inkl. MCP- und RAG-Angriffe. |

Die beiden greifen ineinander: `bug-bounty` ist der Workflow und verweist für Detailtechniken auf `web2-vuln-classes` (z. B. postMessage-Testing, Error-Disclosure-/Debug-Endpoints).

## Installation

Als persönliche Skills (gelten in allen Projekten):

```bash
for s in bug-bounty web2-vuln-classes; do
  mkdir -p ~/.claude/skills/$s
  curl -sSL -o ~/.claude/skills/$s/SKILL.md \
    https://raw.githubusercontent.com/adam06borz/Bugbounty/main/skills/$s/SKILL.md
done
```

Oder projektbezogen: Datei nach `.claude/skills/<name>/SKILL.md` im Projekt legen.

Claude Code lädt einen Skill automatisch, sobald das Thema passt — `bug-bounty` beim Hunten, Recon und Reporting, `web2-vuln-classes` beim Nachschlagen einer konkreten Bugklasse.

## Scope-Hinweis

Die Skills setzen eine Autorisierung voraus — ein Bug-Bounty-Programm im Scope, ein beauftragtes Pentest-Engagement oder eigene Systeme. Vor jedem Hunt den Programm-Scope lesen und jeden Asset/Domain gegen die Freigabe prüfen.

## Herkunft

Die Skills stammen aus [Awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (MIT, siehe [LICENSE](LICENSE)). Das Upstream-Repo enthält 19 weitere Skills (`web2-recon`, `llm-redteam`, `report-writing`, `triage-validation`, `cloud-pentest`, `graphql-audit`, `mobile-pentest`, …).
