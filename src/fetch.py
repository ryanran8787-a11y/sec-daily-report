"""定時爬蟲：NVD + CISA KEV + EPSS，輸出 raw JSON。"""
from __future__ import annotations
import argparse
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests

from common import (
    DATA_DIR, RAW_DIR, extract_cvss, extract_cwes, extract_desc,
    guess_type, save_json, taipei_today_str,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = {"User-Agent": "daily-sec-report/0.1 (+github-pages-mvp)"}


def fetch_nvd(pub_start: str, pub_end: str, api_key: str | None) -> list[dict]:
    """pub_start/end: ISO8601 UTC 如 2026-09-10T00:00:00.000Z。
    強健版：Key 無效(401/403/404)自動降級匿名重試；429/5xx 指數退避重試 3 次。"""
    api_key = (api_key or "").strip() or None
    session = requests.Session()
    session.headers.update(UA)
    if api_key:
        session.headers["apiKey"] = api_key
    out, start, per = [], 0, 2000
    anonymous_fallback_done = not api_key
    retries = 0
    while True:
        q = urlencode({"pubStartDate": pub_start, "pubEndDate": pub_end,
                        "resultsPerPage": per, "startIndex": start})
        try:
            r = session.get(f"{NVD_URL}?{q}", timeout=60)
            r.raise_for_status()
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else 0
            if code in (401, 403, 404) and not anonymous_fallback_done:
                print("[warn] NVD Key 疑似無效/未啟用，改用匿名模式重試（匿名限 5 req/30s）…")
                session.headers.pop("apiKey", None)
                anonymous_fallback_done = True
                retries = 0
                time.sleep(5)
                continue
            retries += 1
            if retries > 3:
                print("[error] NVD 多次重試仍失敗。檢查：1) NVD_API_KEY 是否已點驗證信啟用 "
                      "2) https://nvd.nist.gov 是否正常 3) 明天排程會自動重試")
                raise
            wait = 10 * retries
            print(f"[warn] NVD HTTP {code}，{wait}s 後重試 ({retries}/3)…")
            time.sleep(wait)
            continue
        retries = 0  # 成功就重置
        j = r.json()
        out.extend(j.get("vulnerabilities", []))
        total = j.get("totalResults", 0)
        start += per
        if start >= total or not j.get("vulnerabilities"):
            break
        time.sleep(0.6 if session.headers.get("apiKey") else 6)  # 沒 key 限 5 req/30s
    return out


def fetch_kev() -> dict[str, dict]:
    try:
        r = requests.get(KEV_URL, headers=UA, timeout=60)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        return {v["cveID"].upper(): v for v in vulns if v.get("cveID")}
    except Exception as e:
        print(f"[warn] KEV 抓取失敗: {e}")
        return {}


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(cve_ids), 100):  # EPSS 批次查
        batch = ",".join(cve_ids[i:i + 100])
        try:
            r = requests.get(EPSS_URL, params={"cve": batch}, headers=UA, timeout=60)
            r.raise_for_status()
            for d in r.json().get("data", []):
                out[d["cve"].upper()] = d
        except Exception as e:
            print(f"[warn] EPSS 失敗: {e}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--date", default="")
    args = ap.parse_args()

    target = args.date or taipei_today_str()  # 以台北日為檔名
    # 抓「台北今天 00:00 ~ 明天 00:00」對應的 UTC 區間
    day = datetime.strptime(target, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    # 簡化：抓過去 --days 天的 published（含時區漂移，靠 cve 去重）
    pub_end = datetime.now(timezone.utc)
    pub_start = pub_end - timedelta(days=args.days)
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    print(f"[fetch] NVD {fmt(pub_start)} -> {fmt(pub_end)}")
    vulns = fetch_nvd(fmt(pub_start), fmt(pub_end), os.getenv("NVD_API_KEY") or None)
    print(f"[fetch] NVD 筆數: {len(vulns)}")

    kev = fetch_kev()
    print(f"[fetch] KEV 筆數: {len(kev)}")

    items = []
    for v in vulns:
        c = v.get("cve", {})
        cid = c.get("id", "").upper()
        score, ver = extract_cvss(c)
        cwes = extract_cwes(c)
        desc = extract_desc(c)
        items.append({
            "cve": cid,
            "cvss": score, "cvss_version": ver,
            "cwes": cwes,
            "type_guess": guess_type(cwes, desc),
            "desc_en": desc,
            "published": c.get("published", ""),
            "refs": [r.get("url", "") for r in c.get("references", [])][:5],
            "in_kev": cid in kev,
            "kev": {k: kev[cid].get(k, "") for k in ("vendorProject", "product", "dateAdded", "shortDescription")} if cid in kev else None,
        })

    epss = fetch_epss([x["cve"] for x in items])
    for x in items:
        e = epss.get(x["cve"])
        x["epss"] = float(e["epss"]) if e else None
        x["epss_pct"] = float(e["percentile"]) if e else None

    # 硬過濾：CVSS>=9.0 或 在野
    kept = [x for x in items if (x["cvss"] is not None and x["cvss"] >= 9.0) or x["in_kev"]]
    kept.sort(key=lambda x: (x["in_kev"], x["cvss"] or 0, x["epss"] or 0), reverse=True)

    raw_path = RAW_DIR / f"{target}_raw.json"
    save_json(raw_path, {"date": target, "fetched_at": datetime.now(timezone.utc).isoformat(),
                          "total": len(items), "kept": len(kept), "items": kept})
    print(f"[fetch] total={len(items)} kept={len(kept)} -> {raw_path}")


if __name__ == "__main__":
    main()
