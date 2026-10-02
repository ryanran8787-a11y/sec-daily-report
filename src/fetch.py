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
EPSS_WARN = float(os.getenv("EPSS_WARN", "0.7"))  # 即將被利用預警線


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
        except requests.RequestException as e:
            resp = getattr(e, "response", None)
            code = resp.status_code if resp is not None else 0
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
    # 抓過去 --days 天的 published（排程每天 08:00 台北跑，窗口恰好銜接，不重不漏）
    pub_end = datetime.now(timezone.utc)
    pub_start = pub_end - timedelta(days=args.days)

    def fmt(d: datetime) -> str:
        return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")

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
            "source": "nvd",
        })

    # 補充源：GitHub Advisory + Cisco RSS（NVD 沒有的才補）
    try:
        from extra_sources import fetch_github_advisories, fetch_cisco_rss, enrich_osv
        seen = {x["cve"] for x in items}
        extras = fetch_github_advisories(days=max(args.days, 7)) + fetch_cisco_rss(days=max(args.days, 7))
        n_new = 0
        for x in extras:
            if x["cve"] in seen:
                continue
            if x["cve"] in kev:
                x["in_kev"] = True
                x["kev"] = {k: kev[x["cve"]].get(k, "") for k in ("vendorProject", "product", "dateAdded", "shortDescription")}
            seen.add(x["cve"])
            items.append(x)
            n_new += 1
        print(f"[fetch] 補充源新增: {n_new}")
    except Exception as e:
        print(f"[warn] 補充源略過: {e}")
        enrich_osv = None

    epss = fetch_epss([x["cve"] for x in items if not x["cve"].startswith("CISCO-")])
    for x in items:
        e = epss.get(x["cve"]) or {}
        try:
            x["epss"] = float(e["epss"]) if e.get("epss") not in (None, "") else None
            x["epss_pct"] = float(e["percentile"]) if e.get("percentile") not in (None, "") else None
        except (TypeError, ValueError):
            x["epss"], x["epss_pct"] = None, None
        x["epss_warn"] = bool(x["epss"] is not None and x["epss"] >= EPSS_WARN and not x["in_kev"])

    # 硬過濾：CVSS>=9.0 或 在野 或 EPSS 預警（補充源無分數靠在野/關鍵詞已先收斂）
    kept = [x for x in items if (x["cvss"] is not None and x["cvss"] >= 9.0) or x["in_kev"] or x["epss_warn"]]
    kept.sort(key=lambda x: (x["in_kev"], x["epss_warn"], x["cvss"] or 0, x["epss"] or 0), reverse=True)

    # OSV 反查 enrichment（只對 kept 做，每天約 50 次小請求）
    try:
        if enrich_osv:
            enrich_osv(kept)
    except Exception as e:
        print(f"[warn] OSV enrichment 略過: {e}")

    raw_path = RAW_DIR / f"{target}_raw.json"
    save_json(raw_path, {"date": target, "fetched_at": datetime.now(timezone.utc).isoformat(),
                          "total": len(items), "kept": len(kept), "items": kept})
    print(f"[fetch] total={len(items)} kept={len(kept)} -> {raw_path}")


if __name__ == "__main__":
    main()
