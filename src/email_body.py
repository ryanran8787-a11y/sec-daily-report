"""生成郵件正文 email.html（內聯樣式，郵件客戶端兼容）。"""
from __future__ import annotations
import argparse
import html
import json

from common import DATA_DIR, DOCS_DIR, taipei_today_str

E = html.escape


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="")
    args = ap.parse_args()
    target = args.date or taipei_today_str()
    p = DATA_DIR / f"{target}.json"
    if not p.exists():
        print(f"[email] 找不到 {p}")
        return
    rep = json.loads(p.read_text(encoding="utf-8"))
    rows = []
    for it in rep.get("items", []):
        tag = "在野利用" if it.get("in_wild") else ("利用預警" if it.get("epss_warn") else f"CVSS {it.get('cvss', '?')}")
        rows.append(
            f"<tr><td style='padding:10px 12px;border-bottom:1px solid #eee'>"
            f"<b>{E(str(it.get('title_zh', it['cve'])))}</b><br>"
            f"<span style='color:#666;font-size:12px'>{E(str(it.get('summary_zh', '')))}</span><br>"
            f"<span style='font-size:12px'>{E(it['cve'])} · {E(str(it.get('affected', '')))} · {E(tag)}</span>"
            f"</td></tr>")
    body = (f"<div style='font-family:sans-serif;max-width:640px;margin:auto'>"
            f"<h2>SecDaily {E(rep['date'])}｜高危{E(str(rep['count']))}則</h2>"
            + (f"<p style='background:#fff8e6;border-left:3px solid #f5a524;padding:10px 14px'>{E(rep['brief_zh'])}</p>" if rep.get("brief_zh") else "")
            + f"<table style='border-collapse:collapse;width:100%'>{''.join(rows) or '<tr><td>今日無高危</td></tr>'}</table>"
            f"<p><a href='https://ryanran8787-a11y.github.io/sec-daily-report/{E(rep['date'])}.html'>在網站查看完整版</a></p>"
            f"<p style='color:#999;font-size:12px'>資料 NVD/KEV/EPSS/OSV/GitHub/Cisco · AI 提煉僅供參考</p></div>")
    out = DOCS_DIR / "email.html"
    out.write_text(body, encoding="utf-8")
    subj = DOCS_DIR / "email_subject.txt"
    subj.write_text(f"[SecDaily {rep['date']}] 高危{rep['count']}則" + ("（含在野利用）" if any(i.get("in_wild") for i in rep.get("items", [])) else ""), encoding="utf-8")
    print(f"[email] -> {out}")


if __name__ == "__main__":
    main()
