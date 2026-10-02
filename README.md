# SecDaily 網安每日報

每天 08:00（台北）自動抓取 6 個漏洞情報源，過濾高危項目，經 AI 提煉成繁中日報，發佈到 GitHub Pages，並可選推送 Telegram / Email / RSS。

線上站：`https://ryanran8787-a11y.github.io/sec-daily-report/`

## 資料源

| 來源 | 用途 | 備註 |
|---|---|---|
| NVD CVE 2.0 API | 主源，每日新增 CVE + CVSS + CWE | 需免費 API Key，否則限速；Key 無效自動降級匿名 |
| CISA KEV | 在野利用標記 | 直接 JSON，`in_wild` 唯一真值來源 |
| FIRST EPSS | 利用機率；`>= 0.7` 觸發「利用預警」 | 可用 `EPSS_WARN` 環境變數調線 |
| OSV.dev | 反查影響的開源生態包與修復版本 | 逐條查 kept，命中率約 20–60% |
| GitHub Advisory | 補 NVD 尚未收錄的新 CVE | reviewed，只取 CVSS ≥ 9.0 |
| Cisco PSIRT RSS | 廠商視角補充 | 無 CVE 的 critical 通告也收（`CISCO-` 編號） |

收錄條件：`CVSS ≥ 9.0` 或在野利用或 EPSS 預警。日報只取 Top 5（在野 > 預警 > CVSS，可用 `DAILY_TOP_N` 調）。

## 管線

```
fetch → refine → build → email_body → notify
  │        │        │          │           └─ Telegram 推送（無 secrets 跳過）
  │        │        │          └─ 生成 docs/email.html（郵件正文）
  │        │        └─ 渲染 docs/*.html + feed.xml + trend.json
  │        └─ LLM 提煉（三選一，無 key 用規則 fallback，CVE 校驗防幻覺）
  └─ 六源抓取 + 去重 + EPSS + OSV enrichment → data/raw/*_raw.json
```

輸出：`data/YYYY-MM-DD.json`（日報）、`docs/index.html`（網站）、`docs/feed.xml`（RSS）、`docs/data/trend.json`（趨勢 API）。

## 本機跑

```powershell
pip install -r requirements.txt
copy .env.example .env   # 填任一 LLM Key，不填也能跑（英文規則版）
python src/run.py
```

單步：`python src/fetch.py --date 2026-10-02 --days 1`，其餘 `refine/build/email_body/notify` 同理支援 `--date`。

## 上線

1. 推到 GitHub；Secrets 加 `NVD_API_KEY`（[申請](https://nvd.nist.gov/developers/request-an-api-key)，記得到信裡點啟用）+ 任一 LLM Key
2. Settings → Pages → Deploy from branch → `main` / `docs`
3. 每天 08:00 自動更新；Actions 可手動 `workflow_dispatch`（當天 LLM quota 用完會自動 fallback，不用重跑）

## 推送（可選，不設不影響主站）

| 通道 | Secrets | 怎麼拿 |
|---|---|---|
| RSS | 無 | 訂 `…/feed.xml` |
| Telegram | `TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID` | BotFather 建 bot；chat id 問 `@userinfobot` |
| Email | `MAIL_USERNAME`、`MAIL_TO`、`MAIL_APP_PASSWORD` | Gmail 開兩步驗證 → 應用程式密碼 |

## 可調參數

| 變數 | 預設 | 位置 |
|---|---|---|
| 過濾 CVSS 線 | `9.0` | `src/fetch.py` kept 條件 |
| `EPSS_WARN` | `0.7` | 環境變數 |
| `DAILY_TOP_N` | `5` | 環境變數 |
| Prompt | — | `src/refine.py` 的 `SYSTEM` / `BRIEF_SYSTEM` |
| 站網址 | github.io 預設 | `SITE_URL` 環境變數 |

## 已知限制

- Fortinet PSIRT feed 拿不到穩定 URL，暫未接入
- OSV 偏開源庫覆蓋，WordPress 插件類基本查無
- Gemini 免費 quota 按帳號計，手動狂點會 429，排程每天只打 2 次小請求一般夠用
