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
    "{cve, title_zh, cvss, type, in_wild, summary_zh, affected, fix_hint}"
    "規則：1.title_zh 精簡如「Cisco FMC RCE 在野利用」含廠商+類型，20字內"
    "2.summary_zh 30字內繁中 3.type 限 RCE/接管/逃逸/權限提升/未授權存取/XSS/SQL注入/SSRF/反序列化RCE/DoS/資訊洩漏/其他高危"
    "4.in_wild 只能照輸入的 in_kev 5.不要編造 CVSS，照輸入抄"
)


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


def call_gemini(items: list[dict]) -> list[dict] | None:
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    r = requests.post(url, json={"systemInstruction": {"parts": [{"text": SYSTEM}]},
                                 "contents": [{"parts": [{"text": json.dumps(items, ensure_ascii=False)[:60000]}]}],
                                 "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}},
                      timeout=120)
    r.raise_for_status()
    txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
    return json.loads(txt) if isinstance(json.loads(txt), list) else json.loads(txt).get("items")


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
        wild = "在野利用" if x.get("in_kev") else f"{x['cvss']}" if x.get("cvss") else ""
        out.append({
            "cve": x["cve"], "title_zh": f"{vendor} {t} {x['cve']} {wild}".strip(),
            "cvss": x.get("cvss"), "type": t, "in_wild": bool(x.get("in_kev")),
            "summary_zh": (x.get("desc_en", "")[:120] + "…") if x.get("desc_en") else "",
            "affected": vendor, "fix_hint": "更新至官方修補版本",
            "epss": x.get("epss"), "refs": x.get("refs", []),
        })
    return out


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
    # LLM 輸入瘦身，避免 token 爆炸
    slim = [{"cve": x["cve"], "cvss": x["cvss"], "type_guess": x["type_guess"],
             "in_kev": x["in_kev"], "epss": x.get("epss"),
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
        # 校驗：CVE 編號必須存在、cvss 照抄 raw
        by_raw = {x["cve"]: x for x in items}
        clean = []
        for r in result if isinstance(result, list) else []:
            cid = str(r.get("cve", "")).upper()
            m = CVE_RE.search(cid)
            if not m or m.group(0) not in by_raw:
                continue
            cid = m.group(0)
            src = by_raw[cid]
            r["cve"], r["cvss"], r["in_wild"] = cid, src["cvss"], src["in_kev"]
            r.setdefault("epss", src.get("epss"));
            r.setdefault("refs", src.get("refs", []))
            clean.append(r)
        result = clean or fallback(items)
        if not clean:
            used = "fallback(校驗失敗)"

    out_p = DATA_DIR / f"{target}.json"
    save_json(out_p, {"date": target, "generated_at": datetime.now(timezone.utc).isoformat(),
                      "engine": used, "count": len(result), "items": result})
    print(f"[refine] engine={used} count={len(result)} -> {out_p}")


if __name__ == "__main__":
    main()
