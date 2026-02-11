#!/usr/bin/env python3
"""
Agent Security Scanner (ASS)
Automated vulnerability detection for AI agent contracts
"""

import argparse
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    pattern: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None

class AgentSecurityScanner:
    """Scanner for AI agent smart contract vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict]:
        """Load vulnerability detection rules"""
        return [
            {
                "id": "ASS-001",
                "title": "Unchecked External Call",
                "description": "External call without checking return value or using low-level call",
                "severity": Severity.HIGH,
                "pattern": r'\.call\{value:.*?\}\(.*?\)(?!\s*\.success)',
                "recommendation": "Use (bool success, ) = address.call{value: amount}("") and check success"
            },
            {
                "id": "ASS-002",
                "title": "Reentrancy Risk",
                "description": "External call before state update - potential reentrancy vulnerability",
                "severity": Severity.CRITICAL,
                "pattern": r'\.call\{value:.*?\}\(.*\).*\n.*[^=]=[^=]',
                "recommendation": "Follow checks-effects-interactions pattern - update state before external calls"
            },
            {
                "id": "ASS-003",
                "title": "Missing Access Control",
                "description": "Function may lack proper access control (no onlyOwner or require check)",
                "severity": Severity.HIGH,
                "pattern": r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?!.*onlyOwner)(?!.*require\s*\(msg\.sender)',
                "recommendation": "Add access control modifiers (onlyOwner, onlyRole) or require statements"
            },
            {
                "id": "ASS-004",
                "title": "Hardcoded Private Data",
                "description": "Potential hardcoded sensitive data (API keys, private keys)",
                "severity": Severity.CRITICAL,
                "pattern": r'(api[_-]?key|private[_-]?key|secret|password)\s*[=:]\s*["\'][^"\']+["\']',
                "recommendation": "Never hardcode secrets - use environment variables or secure key management"
            },
            {
                "id": "ASS-005",
                "title": "Prompt Injection Risk",
                "description": "User input directly concatenated into LLM prompt without sanitization",
                "severity": Severity.CRITICAL,
                "pattern": r'prompt.*\+.*(?:msg\.sender|userInput|input)',
                "recommendation": "Sanitize all user inputs before including in prompts - use allowlists"
            },
            {
                "id": "ASS-006",
                "title": "Unchecked Transfer",
                "description": "ERC20 transfer without checking return value",
                "severity": Severity.MEDIUM,
                "pattern": r'\.transfer\(.*\)(?!\s*require)',
                "recommendation": "Use safeTransfer from OpenZeppelin SafeERC20 or check return value"
            },
            {
                "id": "ASS-007",
                "title": "No Rate Limiting",
                "description": "Function lacks rate limiting - potential for spam/DoS",
                "severity": Severity.MEDIUM,
                "pattern": r'function\s+\w+.*(?:public|external)(?!.*rateLimit)(?!.*cooldown)',
                "recommendation": "Implement rate limiting for sensitive functions"
            },
            {
                "id": "ASS-008",
                "title": "Weak Randomness",
                "description": "Using block.timestamp or blockhash for randomness",
                "severity": Severity.HIGH,
                "pattern": r'block\.(timestamp|hash|number)',
                "recommendation": "Use Chainlink VRF or commit-reveal scheme for secure randomness"
            },
            {
                "id": "ASS-009",
                "title": "Agent Identity Not Verified",
                "description": "Contract interacts with agents without verifying ERC-8004 identity",
                "severity": Severity.MEDIUM,
                "pattern": r'function.*agent.*(?:public|external)(?!.*ERC8004)(?!.*verifyIdentity)',
                "recommendation": "Verify ERC-8004 agent identity before trusting agent interactions"
            },
            {
                "id": "ASS-010",
                "title": "No Transaction Simulation",
                "description": "High-value transaction without simulation checkpoint",
                "severity": Severity.HIGH,
                "pattern": r'function.*(?:execute|transfer|pay).*value.*(?:public|external)(?!.*simulate)',
                "recommendation": "Add simulation step before executing high-value transactions"
            }
        ]
    
    def scan(self, contract_path: str) -> Dict:
        """Scan a Solidity contract for vulnerabilities"""
        path = Path(contract_path)
        if not path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")
        
        code = path.read_text()
        lines = code.split('\n')
        
        self.vulnerabilities = []
        
        for rule in self.rules:
            matches = list(re.finditer(rule["pattern"], code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                # Find line number
                line_num = code[:match.start()].count('\n') + 1
                code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else None
                
                vuln = Vulnerability(
                    id=rule["id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    pattern=rule["pattern"][:50] + "...",
                    line_number=line_num,
                    code_snippet=code_snippet,
                    recommendation=rule.get("recommendation")
                )
                self.vulnerabilities.append(vuln)
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """Generate structured security report"""
        severity_counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            severity_counts[v.severity.value] += 1
        
        # Calculate security score
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        total_weight = sum(weights[v.severity] for v in self.vulnerabilities)
        max_score = 100
        security_score = max(0, max_score - (total_weight * 2))
        
        return {
            "scanner": "Agent Security Scanner (ASS) v0.1.0",
            "scan_timestamp": self._get_timestamp(),
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "severity_counts": severity_counts,
                "security_score": security_score,
                "risk_level": self._get_risk_level(security_score)
            },
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "recommendations": self._get_recommendations()
        }
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
    
    def _get_risk_level(self, score: int) -> str:
        if score >= 90:
            return "LOW"
        elif score >= 75:
            return "MEDIUM"
        elif score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _get_recommendations(self) -> List[str]:
        """Get prioritized recommendations"""
        recs = []
        
        critical_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
        high_count = sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
        
        if critical_count > 0:
            recs.append(f"IMMEDIATE: Fix {critical_count} CRITICAL vulnerabilities before deployment")
        
        if high_count > 0:
            recs.append(f"URGENT: Address {high_count} HIGH severity issues within 48 hours")
        
        if any(v.id == "ASS-005" for v in self.vulnerabilities):
            recs.append("Implement Prompt Guard or similar input validation for all LLM interactions")
        
        if any(v.id == "ASS-002" for v in self.vulnerabilities):
            recs.append("Review all external calls - implement reentrancy guards (mutex or checks-effects-interactions)")
        
        if not recs:
            recs.append("No critical issues found - consider a professional audit before mainnet deployment")
        
        return recs

def main():
    parser = argparse.ArgumentParser(
        description="Agent Security Scanner - Automated vulnerability detection for AI agent contracts"
    )
    parser.add_argument("contract", help="Path to Solidity contract file")
    parser.add_argument("--output", "-o", help="Output JSON report file")
    parser.add_argument("--format", "-f", choices=["json", "markdown", "summary"], 
                       default="summary", help="Output format")
    
    args = parser.parse_args()
    
    scanner = AgentSecurityScanner()
    
    try:
        report = scanner.scan(args.contract)
        
        if args.format == "json":
            output = json.dumps(report, indent=2, default=lambda x: x.value if isinstance(x, Enum) else x)
        elif args.format == "markdown":
            output = generate_markdown_report(report)
        else:
            output = generate_summary(report)
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
        
        # Exit with error code if critical vulnerabilities found
        critical_count = report["summary"]["severity_counts"]["CRITICAL"]
        sys.exit(1 if critical_count > 0 else 0)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

def generate_summary(report: Dict) -> str:
    """Generate human-readable summary"""
    s = report["summary"]
    lines = [
        "=" * 60,
        "AGENT SECURITY SCANNER REPORT",
        "=" * 60,
        f"Security Score: {s['security_score']}/100 ({s['risk_level']} RISK)",
        f"Total Vulnerabilities: {s['total_vulnerabilities']}",
        "",
        "Severity Breakdown:",
        f"  CRITICAL: {s['severity_counts']['CRITICAL']}",
        f"  HIGH:     {s['severity_counts']['HIGH']}",
        f"  MEDIUM:   {s['severity_counts']['MEDIUM']}",
        f"  LOW:      {s['severity_counts']['LOW']}",
        "",
        "Top Findings:",
    ]
    
    for i, v in enumerate(report["vulnerabilities"][:5], 1):
        lines.append(f"  {i}. [{v['severity']}] {v['title']} (Line {v['line_number']})")
    
    lines.extend([
        "",
        "Recommendations:",
    ])
    for rec in report["recommendations"]:
        lines.append(f"  • {rec}")
    
    lines.append("=" * 60)
    return "\n".join(lines)

def generate_markdown_report(report: Dict) -> str:
    """Generate markdown report"""
    s = report["summary"]
    lines = [
        "# Agent Security Scanner Report",
        "",
        f"**Scan Date:** {report['scan_timestamp']}",
        f"**Scanner:** {report['scanner']}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Security Score | {s['security_score']}/100 |",
        f"| Risk Level | {s['risk_level']} |",
        f"| Total Vulnerabilities | {s['total_vulnerabilities']} |",
        "",
        "## Severity Breakdown",
        "",
        f"- 🔴 CRITICAL: {s['severity_counts']['CRITICAL']}",
        f"- 🟠 HIGH: {s['severity_counts']['HIGH']}",
        f"- 🟡 MEDIUM: {s['severity_counts']['MEDIUM']}",
        f"- 🟢 LOW: {s['severity_counts']['LOW']}",
        f"- ℹ️ INFO: {s['severity_counts']['INFO']}",
        "",
        "## Detailed Findings",
        "",
    ]
    
    for v in report["vulnerabilities"]:
        lines.extend([
            f"### {v['id']}: {v['title']}",
            "",
            f"**Severity:** {v['severity']}",
            f"**Line:** {v['line_number']}",
            "",
            f"{v['description']}",
            "",
        ])
        if v['code_snippet']:
            lines.extend([
                "**Code:**",
                f"```solidity",
                f"{v['code_snippet']}",
                f"```",
                "",
            ])
        if v['recommendation']:
            lines.extend([
                f"**Recommendation:** {v['recommendation']}",
                "",
            ])
    
    lines.extend([
        "## Recommendations",
        "",
    ])
    for rec in report["recommendations"]:
        lines.append(f"1. {rec}")
    
    return "\n".join(lines)

if __name__ == "__main__":
    main()
