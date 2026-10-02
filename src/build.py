"""SSG：data/*.json -> docs/index.html + docs/data/*.json + docs/feed.xml"""
from __future__ import annotations
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _esc

from jinja2 import Environment, FileSystemLoader

from common import BASE, DATA_DIR, DOCS_DIR, SITE_URL

TEMPLATE_DIR = BASE / "templates"


def _rfc822(iso: str, fallback: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%a, %d %b %Y %H:%M:%S GMT")
    except Exception:
        return fallback


def build_feed(reps: list[dict]) -> str:
    """RSS 2.0：每天一條 item，內容為當日 Top 條目標題清單。"""
    now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    parts = [f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>網安每日報 SecDaily</title>
<link>{SITE_URL}/</link>
<description>CVSS&gt;=9.0 或在野利用的高危漏洞日報</description>
<language>zh-tw</language>
<lastBuildDate>{now}</lastBuildDate>"""]
    for r in reps[:30]:
        lis = []
        for it in r.get("items", []):
            t = _esc(str(it.get("title_zh") or it["cve"]))
            lis.append(f"<li>{t} (CVSS {it.get('cvss', '?')})</li>")
        desc = f"<ul>{''.join(lis)}</ul>" if lis else "當日無高危項目"
        parts.append(f"""<item>
<title>{_esc(r['date'])} 高危 {r['count']} 則</title>
<link>{SITE_URL}/{_esc(r['date'])}.html</link>
<guid>{SITE_URL}/{_esc(r['date'])}.html</guid>
<pubDate>{_esc(_rfc822(r.get('generated_at', ''), now))}</pubDate>
<description><![CDATA[{desc}]]></description>
</item>""")
    parts.append("</channel></rss>")
    return "\n".join(parts)


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
                                 "engine": r.get("engine", ""),
                                 "url": f"{r['date']}.html"} for r in reps]
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    tpl = env.get_template("index.html")

    DOCS_DIR.mkdir(exist_ok=True)
    dd = DOCS_DIR / "data"
    dd.mkdir(exist_ok=True)
    for r in reps:
        shutil.copy(DATA_DIR / f"{r['date']}.json", dd / f"{r['date']}.json")
    (DOCS_DIR / ".nojekyll").write_text("", encoding="utf-8")
    (DOCS_DIR / "feed.xml").write_text(build_feed(reps), encoding="utf-8")
    trend = []
    for r in sorted(reps, key=lambda r: r["date"])[-30:]:
        # 用 raw 的 kept 真實數量（Top5 截斷後的 count 全是 5，畫線沒意義）
        n, wild = r["count"], sum(1 for it in r.get("items", []) if it.get("in_wild"))
        try:
            raw = json.loads((DATA_DIR / "raw" / f"{r['date']}_raw.json").read_text(encoding="utf-8"))
            n = raw.get("kept", n)
            wild = sum(1 for it in raw.get("items", []) if it.get("in_kev"))
        except Exception:
            pass
        trend.append({"date": r["date"], "count": n, "wild": wild})
    (DOCS_DIR / "data" / "trend.json").write_text(
        json.dumps(trend, ensure_ascii=False), encoding="utf-8")
    ctx = dict(history=history, latest_date=reps[0]["date"], trend=trend)
    for r in reps:  # 每天一頁存檔，歷史連結點了真的會開
        (DOCS_DIR / f"{r['date']}.html").write_text(
            tpl.render(report=r, **ctx), encoding="utf-8")
    (DOCS_DIR / "index.html").write_text(
        tpl.render(report=latest, **ctx), encoding="utf-8")
    print(f"[build] latest={latest['date']} count={latest['count']} -> docs/index.html + feed.xml")


if __name__ == "__main__":
    main()
