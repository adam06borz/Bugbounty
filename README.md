# Bugbounty

Claude Code Skills für Bug-Bounty-Arbeit: Recon, Vuln-Hunting, Validierung, Reporting.

## Enthaltene Skills

| Skill | Inhalt |
|---|---|
| [`skills/bug-bounty`](skills/bug-bounty/SKILL.md) | Komplette Pipeline: Recon → Learn → Hunt → Validate → Report. IDOR, SSRF, XSS, Auth-Bypass, CSRF, Race Conditions, SQLi, XXE, File Upload, Business Logic, GraphQL, HTTP Smuggling, Cache Poisoning, OAuth/OIDC, SSTI, Subdomain Takeover, Cloud Misconfig, ATO-Chains, LLM/AI-Security (ASI01–ASI10). Dazu 7-Question Gate, 4 Validation Gates, CVSS 3.1, Report-Templates. |

## Installation

Als persönlicher Skill (alle Projekte):

```bash
mkdir -p ~/.claude/skills/bug-bounty
curl -sSL -o ~/.claude/skills/bug-bounty/SKILL.md \
  https://raw.githubusercontent.com/adam06borz/Bugbounty/main/skills/bug-bounty/SKILL.md
```

Oder projektbezogen: Datei nach `.claude/skills/bug-bounty/SKILL.md` im Projekt legen.

Claude Code lädt den Skill danach automatisch, sobald es um Bug Bounty, Recon oder Vulnerability Hunting geht.

## Scope-Hinweis

Die Skills setzen eine Autorisierung voraus — ein Bug-Bounty-Programm im Scope, ein beauftragtes Pentest-Engagement oder eigene Systeme. Vor jedem Hunt den Programm-Scope lesen und jeden Asset/Domain gegen die Freigabe prüfen.

## Herkunft

`skills/bug-bounty/SKILL.md` stammt aus [Awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (MIT, siehe [LICENSE](LICENSE)). Das Upstream-Repo enthält 20 weitere Skills (`web2-vuln-classes`, `llm-redteam`, `web3-audit`, `report-writing`, `cloud-pentest`, …).
