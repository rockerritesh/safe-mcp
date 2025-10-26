# SAFE-T1404 Documentation Checklist

This checklist mirrors techniques/TEMPLATE-CHECKLIST.md and tracks completion for SAFE-T1404.

## Required Sections
- [x] Overview — Tactic, ID, Severity, First Observed, Last Updated
- [x] Description — Clear 2–3 paragraph explanation
- [x] Attack Vectors — Primary and secondary vectors
- [x] Technical Details
  - [x] Prerequisites
  - [x] Attack Flow (numbered stages)
  - [x] Example Scenario (JSON)
  - [x] Advanced Attack Techniques (current research)
- [x] Impact Assessment — CIA + Scope
  - [x] Current Status (controls/mitigations in use)
- [x] Detection Methods
  - [x] IoCs (≥3)
  - [x] Sigma rule with limitations note (standalone detection-rule.yml and excerpt in README)
  - [x] Behavioral indicators
- [x] Mitigation Strategies
  - [x] Preventive controls (SAFE-M-XX references)
  - [x] Detective controls (SAFE-M-XX references)
  - [x] Response procedures
- [x] Related Techniques — Links to other SAFE techniques
- [x] References — MCP spec + sources
- [x] MITRE ATT&CK Mapping — Linked techniques
- [x] Version History — Tracked changes

## Style Guidelines (Applied)
- [x] Objective technical language
- [x] Inline links for sources
- [x] Warning that rules are examples (present in detection-rule.yml comments)
- [x] Valid UUID for Sigma rule
- [x] URLs included in References
- [x] Mitigations use SAFE-M-XX format

## Directory Structure (Compliant)
```
techniques/SAFE-T1404/
├── README.md               # Completed
├── detection-rule.yml      # Completed
├── test-logs.json          # Added
└── test_detection_rule.py  # Added (pytest-style)
```

## Notes
- Severity: High — narrative integrity risks; not direct service disruption.
- First Observed: Not observed in production (theoretical at present).
- Tests validate rule logic against positive/negative cases.

