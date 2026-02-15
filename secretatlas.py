"""SecretAtlas — Cross-infrastructure secret inventory & lifecycle audit engine."""
import re, json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

@dataclass
class Finding:
    name: str; source: str; path: str; line: int = 0
    severity: str = "medium"; stype: str = "generic"; hardcoded: bool = False
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

PATTERNS = [
    (r'(?i)(api[_-]?key)\s*[=:]\s*["\']?([^\s"\'>]{20,})', "api_key", "high"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'>]{8,})', "password", "critical"),
    (r'(?i)(secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?([^\s"\'>]{16,})', "token", "high"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "private_key", "critical"),
    (r'ghp_[a-zA-Z0-9]{36}', "github_pat", "critical"),
    (r'sk-[a-zA-Z0-9]{20,}', "openai_key", "critical"),
]
EXTS = {'.py','.js','.ts','.yaml','.yml','.json','.tf','.env','.sh','.go','.toml','.cfg','.ini'}
SKIP = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

def _files(root):
    for p in Path(root).rglob("*"):
        if p.is_file() and not SKIP & set(p.parts):
            yield p

def _read(p):
    try: return p.read_text(errors='ignore').splitlines()
    except Exception: return []

def scan_env(root: str) -> List[Finding]:
    findings = []
    for p in _files(root):
        if not (p.name.startswith('.env') or p.suffix == '.env'): continue
        for i, ln in enumerate(_read(p), 1):
            s = ln.strip()
            if s and not s.startswith('#') and '=' in s:
                key = s.split('=', 1)[0].strip()
                if key:
                    findings.append(Finding(key, "env_file", str(p), i, stype="env_var"))
    return findings

def scan_hardcoded(root: str) -> List[Finding]:
    findings = []
    for p in _files(root):
        if p.suffix not in EXTS: continue
        for i, ln in enumerate(_read(p), 1):
            for pat, st, sev in PATTERNS:
                m = re.search(pat, ln)
                if m:
                    nm = m.group(1) if m.lastindex and m.lastindex >= 1 else st
                    findings.append(Finding(nm, "hardcoded", str(p), i, sev, st, True))
    return findings

def scan_k8s(root: str) -> List[Finding]:
    findings = []
    for p in _files(root):
        if p.suffix not in ('.yaml', '.yml'): continue
        lines = _read(p)
        txt = "\n".join(lines)
        if 'kind: Secret' not in txt and 'secretKeyRef' not in txt: continue
        for i, ln in enumerate(lines, 1):
            if 'kind: Secret' in txt:
                m = re.match(r'\s+name:\s+(.+)', ln)
                if m:
                    findings.append(Finding(m.group(1).strip(), "kubernetes", str(p), i, "high", "k8s_secret"))
            if 'secretKeyRef' in ln:
                findings.append(Finding("secretKeyRef", "kubernetes", str(p), i, stype="k8s_ref"))
    return findings

def scan_terraform(root: str) -> List[Finding]:
    findings = []
    for p in _files(root):
        if p.suffix != '.tf': continue
        for i, ln in enumerate(_read(p), 1):
            if 'sensitive' in ln and 'true' in ln:
                findings.append(Finding("sensitive_var", "terraform", str(p), i, stype="tf_sensitive"))
            m = re.search(r'(aws_secretsmanager_secret|vault_generic_secret)\S*\s+"(\w+)"', ln)
            if m:
                findings.append(Finding(m.group(2), "terraform", str(p), i, "high", "tf_secret"))
    return findings

def scan_gha(root: str) -> List[Finding]:
    findings = []
    for p in _files(root):
        if p.suffix not in ('.yaml', '.yml') or '.github' not in p.parts: continue
        for i, ln in enumerate(_read(p), 1):
            for m in re.finditer(r'\$\{\{\s*secrets\.(\w+)\s*\}\}', ln):
                findings.append(Finding(m.group(1), "github_actions", str(p), i, stype="gha_secret"))
    return findings

SCANNERS = {"env": scan_env, "hardcoded": scan_hardcoded, "k8s": scan_k8s,
            "terraform": scan_terraform, "gha": scan_gha}

class SecretAtlas:
    def __init__(self, root: str = "."): self.root, self.findings = root, []
    def scan(self, sources: Optional[List[str]] = None) -> "SecretAtlas":
        for k, fn in SCANNERS.items():
            if sources is None or k in sources:
                self.findings.extend(fn(self.root))
        return self
    def summary(self) -> dict:
        by_src, by_sev = {}, {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            by_src[f.source] = by_src.get(f.source, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_source": by_src,
                "by_severity": by_sev, "hardcoded": sum(1 for f in self.findings if f.hardcoded)}
    def to_json(self) -> str:
        return json.dumps({"findings": [asdict(f) for f in self.findings],
                           "summary": self.summary()}, indent=2)
    def to_table(self) -> str:
        rows = [f"{'NAME':<28} {'SOURCE':<16} {'TYPE':<14} {'SEV':<10} FILE", "-" * 90]
        for f in self.findings:
            rows.append(f"{f.name:<28} {f.source:<16} {f.stype:<14} {f.severity:<10} {f.path}:{f.line}")
        s = self.summary()
        rows.append(f"\n🔍 Total: {s['total']} | 🔴 Critical: {s['by_severity']['critical']} "
                     f"| 🟠 High: {s['by_severity']['high']} | ⚠️  Hardcoded: {s['hardcoded']}")
        return "\n".join(rows)
