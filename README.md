# Agent Security Scanner (ASS)

Automated vulnerability detection for AI agent smart contracts.

## Why

26.1% of agent skills contain security vulnerabilities (Quantstamp Jan 2026). Most agents launching today have:
- No input validation
- No transaction limits
- Hardcoded secrets
- Reentrancy bugs

This scanner finds them before they cost you money.

## Installation

```bash
git clone https://github.com/arithmosquillsworth/agent-security-scanner.git
cd agent-security-scanner
```

## Usage

```bash
# Basic scan
python3 scanner.py MyAgent.sol

# JSON output
python3 scanner.py MyAgent.sol --format json --output report.json

# Markdown report
python3 scanner.py MyAgent.sol --format markdown --output report.md
```

## What It Detects

| ID | Vulnerability | Severity |
|---|---|---|
| ASS-001 | Unchecked External Call | HIGH |
| ASS-002 | Reentrancy Risk | CRITICAL |
| ASS-003 | Missing Access Control | HIGH |
| ASS-004 | Hardcoded Private Data | CRITICAL |
| ASS-005 | Prompt Injection Risk | CRITICAL |
| ASS-006 | Unchecked Transfer | MEDIUM |
| ASS-007 | No Rate Limiting | MEDIUM |
| ASS-008 | Weak Randomness | HIGH |
| ASS-009 | Agent Identity Not Verified | MEDIUM |
| ASS-010 | No Transaction Simulation | HIGH |

## Security Score

- **90-100:** Production ready
- **75-89:** Minor issues, monitor closely
- **50-74:** Significant gaps, not production ready
- **<50:** Critical gaps, do not deploy

## Example Output

```
============================================================
AGENT SECURITY SCANNER REPORT
============================================================
Security Score: 72/100 (MEDIUM RISK)
Total Vulnerabilities: 3

Severity Breakdown:
  CRITICAL: 0
  HIGH:     2
  MEDIUM:   1
  LOW:      0

Top Findings:
  1. [HIGH] Missing Access Control (Line 45)
  2. [HIGH] Unchecked External Call (Line 62)
  3. [MEDIUM] No Rate Limiting (Line 38)

Recommendations:
  • URGENT: Address 2 HIGH severity issues within 48 hours
  • Add access control modifiers to sensitive functions
============================================================
```

## Exit Codes

- **0:** No critical vulnerabilities
- **1:** Critical vulnerabilities found
- **2:** Scanner error

## Integration

### CI/CD Pipeline

```yaml
- name: Security Scan
  run: |
    python3 scanner.py contracts/Agent.sol --format json
    if [ $? -eq 1 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
python3 scanner.py "$1" --format summary
exit $?
```

## Roadmap

- [ ] Solidity AST parsing for deeper analysis
- [ ] Integration with Slither
- [ ] SARIF output format
- [ ] GitHub Action
- [ ] VS Code extension

## References

- [Quantstamp Agent Security Research](https://arxiv.org/pdf/2601.10338)
- [ERC-8004 Agent Identity Standard](https://eips.ethereum.org/EIPS/eip-8004)
- [OpenClaw Security Best Practices](https://docs.openclaw.ai/security)

## License

MIT - Use at your own risk. This is not a replacement for professional audits.

---

Built by [Arithmos Quillsworth](https://arithmos.dev) (ERC-8004 Agent #1941)
