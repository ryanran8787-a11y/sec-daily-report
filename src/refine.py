"""LLM 提煉：raw -> 精簡中文日報 JSON。無 key 時用規則式 fallback。"""
from __future__ import annotations
import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

from common import DATA_DIR, RAW_DIR, save_json, taipei_today_str, CVE_RE

SYSTEM = (
    "你是資安日報編輯。把英文 CVE 條目提煉成繁體中文日報。"
    "只輸出 JSON array，不要 markdown。每項欄位："
    "{cve, title_zh, cvss, type, in_wild, summary_zh, affected, affected_versions, fix_hint, patch_url}"
    "規則：1.title_zh 精簡如「Cisco FMC RCE 在野利用」含廠商+類型，20字內"
    "2.summary_zh 30字內繁中 3.type 限 RCE/接管/逃逸/權限提升/未授權存取/XSS/SQL注入/SSRF/反序列化RCE/DoS/資訊洩漏/其他高危"
    "4.in_wild 只能照輸入的 in_kev 5.不要編造 CVSS，照輸入抄"
    "6.affected_versions 從描述挖受影響版本（如「16.0.4 之前」「1.0.5 及更早」），挖不到填空字串"
    "7.patch_url 從 refs 選官方公告/補丁頁，選不到填 refs[0]，都沒有填空字串"
)

BRIEF_SYSTEM = (
    "你是資安日報編輯。把今日高危清單濃縮成一句 50 字內繁體中文總評，"
    "點出數量、主要類型與最值得優先看的一則。只輸出 JSON：{\"brief_zh\": \"...\"}"
)

TOP_N = int(os.getenv("DAILY_TOP_N", "5"))  # 日報只取 Top N：在野優先，其次 CVSS
SKIP_MODEL_KW = ("image", "tts", "audio", "embed", "aqa")  # 非文字模型不試，省 quota


def call_openai(items: list[dict]) -> list[dict] | None:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    body = {"model": model, "temperature": 0.2, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": json.dumps(items, ensure_ascii=False)[:60000]}]}
    r = requests.post(f"{base}/chat/completions", headers={"Authorization": f"Bearer {key}"},
                      json=body, timeout=120)
    r.raise_for_status()
    txt = r.json()["choices"][0]["message"]["content"]
    return json.loads(txt) if isinstance(json.loads(txt), list) else json.loads(txt).get("items", json.loads(txt))


def call_anthropic(items: list[dict]) -> list[dict] | None:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest")
    r = requests.post("https://api.anthropic.com/v1/messages",
                      headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                      json={"model": model, "max_tokens": 4000, "temperature": 0.2,
                            "system": SYSTEM, "messages": [{"role": "user", "content": json.dumps(items, ensure_ascii=False)[:60000]}]},
                      timeout=120)
    r.raise_for_status()
    txt = "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")
    m = re.search(r"\[.*\]", txt, re.S)
    return json.loads(m.group(0) if m else txt)


def _gemini_models(key: str) -> list[str]:
    """問 ListModels 拿可用模型，名字再怎麼改都跟得上。失敗回空。"""
    try:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                         params={"key": key}, timeout=30)
        r.raise_for_status()
        names = []
        for m in r.json().get("models", []):
            if "generateContent" in (m.get("supportedGenerationMethods") or []):
                short = m["name"].split("/")[-1]
                if any(k in short.lower() for k in SKIP_MODEL_KW):
                    continue
                names.append(short)
        # flash 便宜又快，優先
        names.sort(key=lambda n: (0 if "flash" in n else 1, n))
        return names
    except Exception as e:
        print(f"[warn] gemini ListModels 失敗: {e}")
        return []


def call_gemini(items: list[dict]) -> list[dict] | None:
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    primary = os.getenv("GEMINI_MODEL", "")
    discovered = _gemini_models(key)
    cands = dict.fromkeys([m for m in [primary, *discovered,
                                       "gemini-2.5-flash", "gemini-2.0-flash"] if m])
    print(f"[refine] gemini 可用模型: {list(cands)[:5]}")
    last_err = None
    for model in cands:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        try:
            r = requests.post(url, json={"systemInstruction": {"parts": [{"text": SYSTEM}]},
                                     "contents": [{"parts": [{"text": json.dumps(items, ensure_ascii=False)[:60000]}]}],
                                     "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}},
                              timeout=120)
            r.raise_for_status()
            txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(txt)
            return parsed if isinstance(parsed, list) else parsed.get("items")
        except Exception as e:
            last_err = e
            print(f"[warn] gemini 模型 {model} 失敗: {e}")
    raise last_err


def _guess_versions(desc: str) -> str:
    """從英文描述抓版本範圍：before X / prior to X / through X / <=X。"""
    import re as _re
    d = desc or ""
    pats = [
        r"(?i)before\s+([0-9][0-9A-Za-z.\-_]{1,20})",
        r"(?i)prior to\s+([0-9][0-9A-Za-z.\-_]{1,20})",
        r"(?i)through\s+([0-9][0-9A-Za-z.\-_]{1,20})",
        r"(?i)versions?\s+(?:before|prior to|through)\s+([0-9][0-9A-Za-z.\-_]{1,20})",
        r"([<>]=?\s*[0-9][0-9A-Za-z.\-_]{1,20})",
    ]
    for p in pats:
        m = _re.search(p, d)
        if m:
            v = m.group(1).strip()[:24]
            kw = "之前" if "be" in p[:8].lower() or "prior" in p.lower() or "<" in v else ("及更早" if "through" in p.lower() else "")
            return f"{v} {kw}".strip()
    return ""


def _guess_product(desc: str) -> str:
    """從英文描述頭部抓產品名：'The foo bar plugin...' -> 'foo bar'，抓不到回空。"""
    import re as _re
    d = (desc or "").strip()
    m = _re.match(r"(?i)the\s+(.+?)\s+(wordpress\s+)?plugin\b", d)
    if m:
        return m.group(1)[:40]
    m = _re.match(r"(.{3,45}?)\s+(contains|allows|does not|has |is vulnerable|through|before|prior to)\b", d, _re.I)
    if m:
        return m.group(1).strip()[:40]
    return ""


def fallback(items: list[dict]) -> list[dict]:
    """無 LLM 時：規則式標題+摘要（英文截斷），保證 pipeline 可跑。"""
    out = []
    for x in items:
        vendor = ((x.get("kev") or {}).get("vendorProject")
                  or _guess_product(x.get("desc_en", ""))
                  or "待確認產品")
        t = x.get("type_guess", "其他高危")
        wild = "在野利用" if x.get("in_kev") else ("利用預警" if x.get("epss_warn") else f"{x['cvss']}" if x.get("cvss") else "")
        refs = x.get("refs", []) or []
        pkgs = x.get("osv_packages") or []
        aff = vendor + (f"（{pkgs[0]}等）" if pkgs else "")
        fixed = x.get("osv_fixed") or []
        out.append({
            "cve": x["cve"], "title_zh": f"{vendor} {t} {x['cve']} {wild}".strip(),
            "cvss": x.get("cvss"), "type": t, "in_wild": bool(x.get("in_kev")),
            "epss_warn": bool(x.get("epss_warn")),
            "summary_zh": (x.get("desc_en", "")[:120] + "…") if x.get("desc_en") else "",
            "affected": aff, "affected_versions": _guess_versions(x.get("desc_en", "")),
            "fix_hint": ("升至 " + "、".join(fixed[:2]) + " 或官方修補版本") if fixed else "更新至官方修補版本",
            "patch_url": refs[0] if refs else "",
            "epss": x.get("epss"), "refs": refs,
            "desc_en": (x.get("desc_en", "") or "")[:600],
            "source": x.get("source", "nvd"),
            "osv_packages": pkgs, "osv_fixed": fixed,
        })
    return out


def make_brief(items: list[dict], engine: str) -> str:
    """LLM 總評（極小請求：只傳標題清單） Union fallback 規則拼。"""
    if engine != "gemini" or not os.getenv("GEMINI_API_KEY"):
        return fallback_brief(items)
    try:
        key = os.getenv("GEMINI_API_KEY")
        models = _gemini_models(key) or ["gemini-2.5-flash"]
        model = os.getenv("GEMINI_MODEL", "") or models[0]
        titles = [{"cve": x["cve"], "title_zh": x.get("title_zh", ""),
                   "type": x.get("type", ""), "in_wild": x.get("in_wild")} for x in items]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        r = requests.post(url, json={"systemInstruction": {"parts": [{"text": BRIEF_SYSTEM}]},
                                     "contents": [{"parts": [{"text": json.dumps(titles, ensure_ascii=False)}]}],
                                     "generationConfig": {"temperature": 0.3, "responseMimeType": "application/json"}},
                          timeout=60)
        r.raise_for_status()
        txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        b = (json.loads(txt) or {}).get("brief_zh", "")
        return b.strip()[:200] if b else fallback_brief(items)
    except Exception as e:
        print(f"[warn] 總評失敗，用規則版: {e}")
        return fallback_brief(items)


def fallback_brief(items: list[dict]) -> str:
    """規則式總評：數量+類型分佈+最高分一則。"""
    if not items:
        return "今日無高危項目。"
    from collections import Counter
    c = Counter(x.get("type", "其他高危") for x in items)
    top = max(items, key=lambda x: (x.get("in_kev"), x.get("cvss") or 0))
    kinds = "、".join(f"{k}{v}則" for k, v in c.most_common(2))
    wild = sum(1 for x in items if x.get("in_kev"))
    s = f"今日共{len(items)}則高危（{kinds}）"
    s += f"，{wild}則在野利用" if wild else "，無在野利用"
    s += f"，優先看 {top.get('title_zh', top['cve'])}。"
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="")
    args = ap.parse_args()
    target = args.date or taipei_today_str()
    raw_p = RAW_DIR / f"{target}_raw.json"
    if not raw_p.exists():
        print(f"[refine] 找不到 {raw_p}，先跑 fetch.py");
        return
    raw = json.loads(raw_p.read_text(encoding="utf-8"))
    items = raw["items"]
    # 只取 Top N（在野優先，其次 CVSS）：LLM 一天只打一次，省 quota 又精簡
    items = sorted(items, key=lambda x: (x.get("in_kev"), x.get("epss_warn"),
                                         x.get("cvss") or 0,
                                         x.get("epss") or 0), reverse=True)[:TOP_N]
    print(f"[refine] raw={len(raw['items'])} -> top{len(items)}")
    # LLM 輸入瘦身，避免 token 爆炸
    slim = [{"cve": x["cve"], "cvss": x["cvss"], "type_guess": x["type_guess"],
             "in_kev": x["in_kev"], "epss": x.get("epss"), "epss_warn": x.get("epss_warn"),
             "source": x.get("source", "nvd"),
             "osv_packages": x.get("osv_packages"), "osv_fixed": x.get("osv_fixed"),
             "desc_en": x.get("desc_en", "")[:800], "refs": x.get("refs", [])[:2]} for x in items]

    result, used = None, "fallback"
    for name, fn in (("gemini", call_gemini), ("openai", call_openai), ("anthropic", call_anthropic)):
        try:
            if os.getenv(f"{name.upper()}_API_KEY") or (name == "openai" and os.getenv("OPENAI_API_KEY")):
                result = fn(slim)
                used = name
                break
        except Exception as e:
            print(f"[warn] {name} 失敗: {e}")
    if not result:
        result, used = fallback(items), "fallback"
    else:
        # 校驗：CVE 編號必須存在、cvss 照抄 raw（CISCO- 廠商通告無 CVE 也放行）
        by_raw = {x["cve"]: x for x in items}
        clean = []
        for r in result if isinstance(result, list) else []:
            cid = str(r.get("cve", "")).upper()
            m = CVE_RE.search(cid)
            if m and m.group(0) in by_raw:
                cid = m.group(0)
            elif cid not in by_raw:
                continue
            src = by_raw[cid]
            r["cve"], r["cvss"], r["in_wild"] = cid, src["cvss"], src["in_kev"]
            r.setdefault("epss_warn", src.get("epss_warn", False))
            r.setdefault("epss", src.get("epss"));
            r.setdefault("refs", src.get("refs", []))
            r.setdefault("desc_en", (src.get("desc_en", "") or "")[:600])
            r.setdefault("affected_versions", _guess_versions(src.get("desc_en", "")))
            r.setdefault("patch_url", (src.get("refs", []) or [""])[0])
            r.setdefault("source", src.get("source", "nvd"))
            r.setdefault("osv_packages", src.get("osv_packages") or [])
            r.setdefault("osv_fixed", src.get("osv_fixed") or [])
            clean.append(r)
        result = clean or fallback(items)
        if not clean:
            used = "fallback(校驗失敗)"

    out_p = DATA_DIR / f"{target}.json"
    brief = make_brief(result, used)
    print(f"[refine] brief: {brief}")
    save_json(out_p, {"date": target, "generated_at": datetime.now(timezone.utc).isoformat(),
                      "engine": used, "count": len(result), "brief_zh": brief, "items": result})
    print(f"[refine] engine={used} count={len(result)} -> {out_p}")


if __name__ == "__main__":
    main()
