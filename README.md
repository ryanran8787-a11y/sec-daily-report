# 網安每日報

定時爬蟲（NVD + CISA KEV + EPSS）→ LLM 提煉繁中標題 → Jinja2 靜態站 → GitHub Pages。

## 本機試跑

```powershell
pip install -r requirements.txt
copy .env.example .env   # 填 LLM Key（三選一即可，不填也能跑 fallback）
python src/run.py
```

輸出：`data/YYYY-MM-DD.json`（日報）+ `docs/index.html`（網站）。

## 自動發佈

1. 推到 GitHub，Secrets 加 `NVD_API_KEY`（https://nvd.nist.gov/developers/request-an-api-key）+ 任一 LLM Key
2. Repo Settings → Pages → Deploy from branch → `main` / `docs`
3. 每天 08:00 台北時間自動更新，也可 Actions 手動 `workflow_dispatch`

## 資料格式

`data/2026-09-11.json`：`{date, engine, count, items:[{cve, title_zh, cvss, type, in_wild, summary_zh, affected, fix_hint, epss, refs}]}`

## 要調的兩個地方

- 過濾門檻：`src/fetch.py` 的 `cvss >= 9.0` 那行
- Prompt：`src/refine.py` 的 `SYSTEM`
