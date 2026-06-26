# smart_contract_audit/audit_with_mythril.py
from __future__ import annotations
import json, shutil, subprocess, sys
from pathlib import Path
from typing import Tuple, List

# Try common executable names
MYTH_CMDS = ["myth", "mythril"]

def _find_myth() -> str:
    for cmd in MYTH_CMDS:
        if shutil.which(cmd):
            return cmd
    raise FileNotFoundError(
        "Mythril CLI not found. Install with `pipx install mythril` "
        "or use Docker: `docker run --rm mythril/myth --version`."
    )

def audit(file_path: str, fmt: str = "json", timeout: int = 120) -> Tuple[int, str]:
    exe = _find_myth()
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"No such file: {path}")
    cmd = [exe, "analyze", str(path), "-o", fmt]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (res.returncode, res.stdout or res.stderr)

def summarize(json_text: str) -> List[str]:
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []
    issues = []
    items = data if isinstance(data, list) else data.get("issues", [])
    for i in items:
        title = i.get("title") or i.get("check", "Issue")
        severity = i.get("severity", "Unknown")
        swc = ",".join(i.get("swc_id_list", [])) if i.get("swc_id_list") else i.get("swc-id", "")
        issues.append(f"[{severity}] {title}{(' ('+swc+')') if swc else ''}")
    return issues

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "smart_contract_audit/vulnerable_contract.sol"
    code, out = audit(target)
    print(out)
