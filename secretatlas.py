"""SecretAtlas — Cross-infrastructure secret inventory & lifecycle audit engine."""
import re, json, hashlib, fnmatch

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
@dataclass
class Finding:
    name: str; source: str; path: str; line: int = 0
    severity: str = "medium"; stype: str = "generic"; hardcoded: bool = False
    suppressed: bool = False; suppression_reason: str = ""
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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


class IgnoreManager:
    """Manages .secretatlasignore rules and inline suppression comments."""

    def __init__(self, ignore_file=None):
        self.file_patterns: List[str] = []
        self.dir_patterns: List[str] = []
        self.type_patterns: List[str] = []
        self.hash_patterns: set = set()
        self._file_cache: dict = {}

        if ignore_file:
            p = Path(ignore_file)
            if p.exists():
                self._load(p)

    def _load(self, path: Path):
        for raw in path.read_text(errors='ignore').splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('type:'):
                val = line[5:].strip()
                if val:
                    self.type_patterns.append(val)
            elif line.startswith('hash:'):
                val = line[5:].strip()
                if val:
                    self.hash_patterns.add(val)
            elif line.endswith('/'):
                dp = line.rstrip('/')
                if dp:
                    self.dir_patterns.append(dp)
            else:
                self.file_patterns.append(line)

    @staticmethod
    def compute_hash(finding: Finding) -> str:
        canonical = f"{finding.path}:{finding.line}:{finding.name}:{finding.stype}"
        return hashlib.sha256(canonical.encode()).hexdigest()

    def should_skip_file(self, filepath: str) -> bool:
        """Check if filepath matches any file glob or directory exclusion pattern."""
        p = Path(filepath)
        parts = p.parts
        name = p.name

        # Directory patterns: match any directory component (exclude filename)
        for dp in self.dir_patterns:
            for part in parts[:-1]:
                if fnmatch.fnmatch(part, dp):
                    return True

        # File patterns: match against basename or full path
        for fp in self.file_patterns:
            if fnmatch.fnmatch(name, fp):
                return True
            if fnmatch.fnmatch(str(p), fp):
                return True

        return False

    def _read_line(self, filepath: str, line_num: int) -> Optional[str]:
        if filepath not in self._file_cache:
            try:
                self._file_cache[filepath] = Path(filepath).read_text(errors='ignore').splitlines()
            except Exception:
                self._file_cache[filepath] = []
        lines = self._file_cache[filepath]
        if 0 < line_num <= len(lines):
            return lines[line_num - 1]
        return None

    @staticmethod
    def _parse_inline(line_content: str):
        """Parse inline suppression comment. Returns (suppressed: bool, reason: str|None)."""
        patterns = [
            r'#\s*secretatlas:ignore(?:\s+reason=(\S+))?',
            r'//\s*secretatlas:ignore(?:\s+reason=(\S+))?',
        ]
        for pat in patterns:
            m = re.search(pat, line_content)
            if m:
                reason = m.group(1) if m.group(1) else "inline-ignore"
                return True, reason
        return False, None

    def check_inline_suppression(self, filepath: str, line_num: int):
        """Check if a specific line has an inline suppression comment."""
        line = self._read_line(filepath, line_num)
        if line is not None:
            return self._parse_inline(line)
        return False, None

    def process_findings(self, findings: List[Finding]) -> List[Finding]:
        """Apply all suppression rules. Findings are never dropped, only marked."""
        result = []
        for f in findings:
            # 1. File/directory pattern match
            if self.should_skip_file(f.path):
                f.suppressed = True
                f.suppression_reason = "file-pattern-match"
                result.append(f)
                continue

            # 2. Type-based suppression
            if f.stype in self.type_patterns:
                f.suppressed = True
                f.suppression_reason = f"type-suppressed:{f.stype}"
                result.append(f)
                continue

            # 3. Hash-based suppression (exact finding only)
            fhash = self.compute_hash(f)
            if fhash in self.hash_patterns:
                f.suppressed = True
                f.suppression_reason = f"hash-suppressed:{fhash}"
                result.append(f)
                continue

            # 4. Inline suppression comment
            suppressed, reason = self.check_inline_suppression(f.path, f.line)
            if suppressed:
                f.suppressed = True
                f.suppression_reason = reason
                result.append(f)
                continue

            result.append(f)

        return result
