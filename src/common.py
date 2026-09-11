"""共用工具：時區、CVSS 擷取、CWE->中文類型映射."""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

TAIPEI = timezone(timedelta(hours=8))
BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
RAW_DIR = DATA_DIR / "raw"
DOCS_DIR = BASE / "docs"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def taipei_today_str() -> str:
    return datetime.now(TAIPEI).strftime("%Y-%m-%d")


def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def save_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def extract_cvss(cve_obj: dict) -> tuple[float | None, str]:
    """從 NVD metrics 抓最高分，回 (score, version)。"""
    metrics = cve_obj.get("metrics", {})
    best, best_v = None, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            s = data.get("baseScore")
            if s is None:
                continue
            if best is None or s > best:
                best, best_v = float(s), data.get("version", key)
    return best, best_v


def extract_cwes(cve_obj: dict) -> list[str]:
    out = []
    for w in cve_obj.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE"):
                out.append(v)
    return sorted(set(out))


def extract_desc(cve_obj: dict) -> str:
    descs = cve_obj.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descs[0].get("value", "") if descs else ""


# CWE -> 中文大類（精簡版，夠日報用）
CWE_TYPE_MAP = {
    "CWE-78": "RCE", "CWE-77": "RCE", "CWE-88": "RCE", "CWE-94": "RCE",
    "CWE-95": "RCE", "CWE-96": "RCE", "CWE-502": "反序列化RCE",
    "CWE-434": "RCE", "CWE-787": "RCE", "CWE-119": "RCE", "CWE-125": "RCE",
    "CWE-416": "RCE", "CWE-190": "RCE",
    "CWE-79": "XSS", "CWE-80": "XSS", "CWE-87": "XSS",
    "CWE-89": "SQL注入", "CWE-90": "LDAP注入", "CWE-91": "XPath注入",
    "CWE-918": "SSRF", "CWE-611": "XXE", "CWE-601": "開放重導向",
    "CWE-22": "目錄遍歷", "CWE-23": "目錄遍歷", "CWE-24": "目錄遍歷",
    "CWE-287": "身份繞過/接管", "CWE-288": "身份繞過/接管",
    "CWE-290": "身份繞過/接管", "CWE-639": "越權/接管", "CWE-862": "越權",
    "CWE-863": "越權", "CWE-269": "權限提升", "CWE-264": "權限提升",
    "CWE-276": "權限提升", "CWE-732": "權限提升",
    "CWE-306": "未授權存取", "CWE-862": "未授權存取", "CWE-200": "資訊洩漏",
    "CWE-209": "資訊洩漏", "CWE-532": "資訊洩漏",
    "CWE-400": "DoS", "CWE-401": "DoS", "CWE-404": "DoS", "CWE-770": "DoS",
    "CWE-352": "CSRF", "CWE-798": "硬編碼憑證", "CWE-259": "硬編碼憑證",
    "CWE-303": "錯誤認證", "CWE-304": "錯誤認證",
}

DESC_KEYWORDS = [
    ("sandbox escape", "逃逸"), ("virtual machine escape", "逃逸"),
    ("container escape", "逃逸"), ("vm escape", "逃逸"),
    ("remote code execution", "RCE"), ("arbitrary code", "RCE"),
    ("code injection", "RCE"), ("command injection", "RCE"),
    ("deserialization", "反序列化RCE"), ("privilege escalation", "權限提升"),
    ("authentication bypass", "身份繞過/接管"), ("account takeover", "接管"),
    ("takeover", "接管"), ("use after free", "UAF-RCE"),
    ("buffer overflow", "緩衝區溢位"), ("sql injection", "SQL注入"),
    ("cross-site scripting", "XSS"), ("server-side request forgery", "SSRF"),
    ("directory traversal", "目錄遍歷"), ("path traversal", "目錄遍歷"),
    ("denial of service", "DoS"), ("information disclosure", "資訊洩漏"),
]


def guess_type(cwes: list[str], desc_en: str) -> str:
    dl = desc_en.lower()
    for kw, t in DESC_KEYWORDS:
        if kw in dl:
            return t
    for c in cwes:
        base = c.split()[0]
        if base in CWE_TYPE_MAP:
            return CWE_TYPE_MAP[base]
    return "其他高危"
