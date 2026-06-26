# smart_contract_audit/audit_with_slither.py
from __future__ import annotations
import shutil, subprocess
from pathlib import Path
from typing import Tuple

def _find_slither() -> str:
    exe = shutil.which("slither")
    if not exe:
        raise FileNotFoundError(
            "Slither CLI not found. Install with `pipx install slither-analyzer` "
            "or use Docker: `docker run --rm trailofbits/slither .`"
        )
    return exe

def audit(file_path: str, json_output: bool = True, timeout: int = 120) -> Tuple[int, str]:
    exe = _find_slither()
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"No such file: {path}")
    cmd = [exe, str(path), "--json", "-"] if json_output else [exe, str(path)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (res.returncode, res.stdout or res.stderr)

if __name__ == "__main__":
    code, out = audit("smart_contract_audit/vulnerable_contract.sol")
    print(out[:2000])
