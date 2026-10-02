"""補充源：GitHub Advisory + Cisco PSIRT RSS。輸出與 fetch.py 同結構的 item。"""
from __future__ import annotations
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import requests

from common import CVE_RE, guess_type

UA = {"User-Agent": "daily-sec-report/0.1 (+github-pages-mvp)"}
GH_URL = "https://api.github.com/advisories"
CISCO_RSS = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"


def _within(dt_str: str, days: int) -> bool:
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) - dt <= timedelta(days=days)
    except Exception:
        return False


def fetch_github_advisories(days: int = 7) -> list[dict]:
    """GitHub Reviewed Advisory：補 NVD 還沒收錄的新 CVE + 生態/修復版本。"""
    headers = dict(UA)
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"
    try:
        r = requests.get(GH_URL, params={"per_page": 100, "type": "reviewed",
                                         "order": "desc", "sort": "published"},
                         headers=headers, timeout=60)
        r.raise_for_status()
        advis = r.json()
    except Exception as e:
        print(f"[warn] GitHub Advisory 失敗: {e}")
        return []
    out = []
    for a in advis if isinstance(advis, list) else []:
        if not _within(a.get("published_at", ""), days):
            continue
        score = (a.get("cvss") or {}).get("score")
        if score is None or score < 9.0:
            continue
        cid = (a.get("cve_id") or "").upper()
        if not cid:  # 無 CVE 的只留 GHSA 編號，避免空 CVE 污染去重與 EPSS 整批
            cid = (a.get("ghsa_id") or "").upper()
            if not cid:
                continue
        cwes = [(w.get("cwe_id", "")) for w in a.get("cwes", []) if w.get("cwe_id")]
        desc = a.get("description", "") or ""
        vulns = a.get("vulnerabilities", []) or []
        eco = vulns[0].get("package", {}).get("ecosystem", "") if vulns else ""
        fixed = vulns[0].get("first_patched_version", "") if vulns else ""
        out.append({
            "cve": cid, "cvss": float(score), "cvss_version": "gh",
            "cwes": cwes, "type_guess": guess_type(cwes, desc[:2000]),
            "desc_en": (a.get("summary", "") + "\n" + desc)[:2000],
            "published": a.get("published_at", ""),
            "refs": [a.get("html_url", "")],
            "in_kev": False, "kev": None,
            "epss": None, "epss_pct": None, "epss_warn": False,
            "source": "github", "ecosystem": eco, "fixed_in": fixed,
        })
    print(f"[extra] GitHub Advisory 近{days}天 CVSS>=9: {len(out)}")
    return out


def fetch_cisco_rss(days: int = 7) -> list[dict]:
    """Cisco PSIRT RSS：廠商視角補充，無 CVE 的也收（cve=''，靠 link 去重）。"""
    try:
        r = requests.get(CISCO_RSS, headers=UA, timeout=60)
        r.raise_for_status()
        root = ET.fromstring(r.content)
    except Exception as e:
        print(f"[warn] Cisco RSS 失敗: {e}")
        return []
    out = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        pub = (it.findtext("pubDate") or "").strip()
        desc = (it.findtext("description") or "").strip()
        try:
            dt = datetime.strptime(pub[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - dt > timedelta(days=days):
                continue
        except Exception:
            continue
        text = f"{title}\n{desc}"
        m = CVE_RE.search(text)
        cid = m.group(0).upper() if m else ""
        # 收斂：有 CVE 或提到 critical/CVSS 9 才收，避免通告噪音
        if not cid and not re.search(r"(?i)critical|CVSS[^0-9]*9\.\d|severity[^0-9]*9", text):
            continue
        out.append({
            "cve": cid or f"CISCO-{abs(hash(link)) % 10**8:08d}",
            "cvss": None, "cvss_version": "", "cwes": [],
            "type_guess": guess_type([], text[:2000]),
            "desc_en": text[:2000], "published": pub, "refs": [link],
            "in_kev": False, "kev": None,
            "epss": None, "epss_pct": None, "epss_warn": False,
            "source": "cisco",
        })
    print(f"[extra] Cisco RSS 近{days}天: {len(out)}")
    return out


def enrich_osv(items: list[dict]) -> int:
    """OSV 反查：給 kept 條目補 affected 生態包 / 修復版 / GHSA 別名。404 靜默跳過。"""
    import time as _t
    n = 0
    for x in items:
        cid = x.get("cve", "")
        if not cid or cid.startswith("CISCO-") or x.get("osv_packages") is not None:
            continue
        try:
            r = requests.get(f"https://api.osv.dev/v1/vulns/{cid}", headers=UA, timeout=30)
            if r.status_code != 200:
                continue
            d = r.json()
            pkgs, fixed = [], []
            for a in d.get("affected", [])[:4]:
                pkg = a.get("package", {}) or {}
                eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
                if eco and name and f"{eco}:{name}" not in pkgs:
                    pkgs.append(f"{eco}:{name}")
                for rg in a.get("ranges", [])[:2]:
                    for ev in rg.get("events", []):
                        fx = str(ev.get("fixed", "") or "")
                        # 跳過 git commit hash（40 hex），只留語義版本
                        if fx and not re.fullmatch(r"[0-9a-f]{40}", fx) and fx not in fixed:
                            fixed.append(fx[:24])
            x["osv_packages"] = pkgs[:3]
            x["osv_fixed"] = fixed[:3]
            x["osv_alias"] = [a for a in (d.get("aliases") or []) if str(a).startswith("GHSA")][:2]
            n += 1
        except Exception:
            continue
        _t.sleep(0.2)
    print(f"[extra] OSV 命中: {n}/{len(items)}")
    return n
