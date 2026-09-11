"""一鍵管線：fetch -> refine -> build。給本機與 GitHub Action 共用。"""
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent


def run(mod: str):
    print(f"\n===== {mod} =====")
    r = subprocess.run([sys.executable, str(SRC / f"{mod}.py")])
    if r.returncode != 0:
        sys.exit(r.returncode)


if __name__ == "__main__":
    for m in ("fetch", "refine", "build"):
        run(m)
    print("\n[done] pipeline 完成")
