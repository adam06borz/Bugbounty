# Bugbounty

Claude Code Skills für Bug-Bounty-Arbeit: Recon, Vuln-Hunting, Validierung, Reporting.

## Enthaltene Skills

| Skill | Inhalt |
|---|---|
| [`skills/bug-bounty`](skills/bug-bounty/SKILL.md) | Komplette Pipeline: Recon → Learn → Hunt → Validate → Report. IDOR, SSRF, XSS, Auth-Bypass, CSRF, Race Conditions, SQLi, XXE, File Upload, Business Logic, GraphQL, HTTP Smuggling, Cache Poisoning, OAuth/OIDC, SSTI, Subdomain Takeover, Cloud Misconfig, ATO-Chains, LLM/AI-Security (ASI01–ASI10). Dazu 7-Question Gate, 4 Validation Gates, CVSS 3.1, Report-Templates. |
| [`skills/web3-audit`](skills/web3-audit/SKILL.md) | Smart-Contract-Audit: 10 DeFi-Bugklassen (Accounting-Desync, Access Control, Incomplete Path, Off-by-One, Oracle-Manipulation, ERC4626, Reentrancy, Flash Loan, Signature Replay, Proxy/Upgrade). Dazu Pre-Dive Kill Signals, Foundry-PoC-Template, Grep-Patterns pro Klasse, bezahlte Immunefi-Beispiele. |

## Installation

Als persönliche Skills (gelten in allen Projekten):

```bash
for s in bug-bounty web3-audit; do
  mkdir -p ~/.claude/skills/$s
  curl -sSL -o ~/.claude/skills/$s/SKILL.md \
    https://raw.githubusercontent.com/adam06borz/Bugbounty/main/skills/$s/SKILL.md
done
```

Oder projektbezogen: Datei nach `.claude/skills/<name>/SKILL.md` im Projekt legen.

Claude Code lädt einen Skill automatisch, sobald das Thema passt — Bug Bounty, Recon und Vulnerability Hunting für `bug-bounty`, Solidity-/Rust-Contract-Audits für `web3-audit`.

## Scope-Hinweis

Die Skills setzen eine Autorisierung voraus — ein Bug-Bounty-Programm im Scope, ein beauftragtes Pentest-Engagement oder eigene Systeme. Vor jedem Hunt den Programm-Scope lesen und jeden Asset/Domain gegen die Freigabe prüfen.

## Herkunft

Die Skills stammen aus [Awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (MIT, siehe [LICENSE](LICENSE)). Das Upstream-Repo enthält 19 weitere Skills (`web2-vuln-classes`, `llm-redteam`, `report-writing`, `cloud-pentest`, `graphql-audit`, `mobile-pentest`, …).
