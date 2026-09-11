"""SSG：data/*.json -> docs/index.html + docs/data/*.json"""
from __future__ import annotations
import json
import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from common import BASE, DATA_DIR, DOCS_DIR

TEMPLATE_DIR = BASE / "templates"


def load_reports() -> list[dict]:
    reps = []
    for p in sorted(DATA_DIR.glob("????-??-??.json"), reverse=True):
        try:
            reps.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"[warn] 跳過 {p.name}: {e}")
    return reps


def main():
    reps = load_reports()
    if not reps:
        print("[build] data/ 無日報，先跑 fetch+refine");
        return
    latest, history = reps[0], [{"date": r["date"], "count": r["count"],
                                 "engine": r.get("engine", "")} for r in reps]
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    html = env.get_template("index.html").render(report=latest, history=history)

    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "index.html").write_text(html, encoding="utf-8")
    dd = DOCS_DIR / "data"
    dd.mkdir(exist_ok=True)
    for r in reps:
        shutil.copy(DATA_DIR / f"{r['date']}.json", dd / f"{r['date']}.json")
    (DOCS_DIR / ".nojekyll").write_text("", encoding="utf-8")
    print(f"[build] latest={latest['date']} count={latest['count']} -> docs/index.html")


if __name__ == "__main__":
    main()
