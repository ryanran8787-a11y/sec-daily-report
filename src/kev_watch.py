"""KEV 變更監控：對比昨日快照，有新收錄立刻推 Telegram。不設 secrets 則只更新快照。"""
from __future__ import annotations
import argparse
import json
import os

import requests

from common import DATA_DIR, save_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "daily-sec-report/0.1 (+github-pages-mvp)"}
SNAP = DATA_DIR / "kev_snapshot.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="")
    args = ap.parse_args()
    r = requests.get(KEV_URL, headers=UA, timeout=60)
    r.raise_for_status()
    cur = {v["cveID"].upper(): v for v in r.json().get("vulnerabilities", []) if v.get("cveID")}
    old = json.loads(SNAP.read_text(encoding="utf-8")) if SNAP.exists() else {}
    new_ids = sorted(set(cur) - set(old))
    save_json(SNAP, {k: {"vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                         "dateAdded": v.get("dateAdded", "")} for k, v in cur.items()})
    print(f"[kev] 總數={len(cur)} 新增={len(new_ids)}")
    if not new_ids:
        return
    for cid in new_ids:
        v = cur[cid]
        print(f"[kev] NEW {cid} {v.get('vendorProject', '')} {v.get('product', '')}")
    token, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    if not (token and chat):
        print("[kev] 無 TELEGRAM secrets，只更新快照")
        return
    lines = ["🚨 KEV 新增在野利用："]
    for cid in new_ids[:10]:
        v = cur[cid]
        lines.append(f"• {cid}｜{v.get('vendorProject', '')} {v.get('product', '')}")
    if len(new_ids) > 10:
        lines.append(f"…等共 {len(new_ids)} 則")
    t = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat, "text": "\n".join(lines),
                            "disable_web_page_preview": True}, timeout=30)
    print("[kev] telegram:", t.status_code)


if __name__ == "__main__":
    main()
