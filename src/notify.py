"""Telegram 推送：當日 Top N 一句一條。無 secrets 時靜默跳過，不卡主流程。"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

import requests

from common import DATA_DIR, taipei_today_str


def build_msg(rep: dict, top: int = 5) -> str:
    L = [f"SecDaily {rep['date']}｜高危{rep['count']}則"]
    if rep.get("brief_zh"):
        L.append(rep["brief_zh"])
    for i, it in enumerate(rep.get("items", [])[:top], 1):
        tag = "在野" if it.get("in_wild") else ("預警" if it.get("epss_warn") else f"{it.get('cvss', '?')}")
        L.append(f"{i}. [{tag}] {it.get('title_zh', it['cve'])}")
    L.append(f"https://ryanran8787-a11y.github.io/sec-daily-report/{rep['date']}.html")
    msg = "\n".join(L)
    return msg[:3800]  # Bot API 上限 4096，留餘


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="")
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()
    token, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("[notify] 無 TELEGRAM secrets，跳過")
        return
    target = args.date or taipei_today_str()
    p = DATA_DIR / f"{target}.json"
    if not p.exists():
        print(f"[notify] 找不到 {p}")
        return
    rep = json.loads(p.read_text(encoding="utf-8"))
    if not rep.get("items"):
        print("[notify] 今日無高危，不打擾")
        return
    r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      json={"chat_id": chat, "text": build_msg(rep, args.top),
                            "disable_web_page_preview": True}, timeout=30)
    print("[notify] telegram:", r.status_code, r.text[:200])


if __name__ == "__main__":
    main()
