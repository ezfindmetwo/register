# 📅 排程預約系統（Flask + SQLite 版）

零設定、免安裝資料庫 — 開箱即用。

## 系統需求
- Python 3.9+
- pip

## 快速啟動

```bash
# 1. 安裝相依套件（只需兩個）
pip install -r requirements.txt

# 2. 複製設定檔
cp .env.example .env

# 3. 啟動（資料庫會自動建立）
python app.py
```

開啟瀏覽器：http://localhost:5000

**預設管理者密碼：admin123**

---

## 設定說明（.env）

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `FLASK_PORT` | 5000 | 監聽 Port |
| `FLASK_ENV` | development | `production` 上線時驗證碼不會顯示在回應 |
| `SECRET_KEY` | (預設值) | Session 簽名金鑰，正式環境請務必更換 |
| `ADMIN_PASSWORD` | admin123 | 管理者密碼 |
| `DB_PATH` | scheduling.db | SQLite 檔案路徑 |

## Gmail 寄信設定
1. Google 帳戶 → 安全性 → 兩步驟驗證（需先開啟）
2. 搜尋「應用程式密碼」→ 產生新密碼
3. Email 設定：Host=`smtp.gmail.com`、Port=`587`、勾選 SSL/TLS
4. 帳號填 Gmail 地址，密碼填應用程式密碼

## 生產環境部署

```bash
# 安裝 gunicorn
pip install gunicorn

# 啟動（4 個工作程序）
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

搭配 nginx 反向代理 + Let's Encrypt HTTPS 即可上線。

## 專案結構

```
scheduling-flask/
├── app.py          # Flask 主程式（所有路由 & 邏輯）
├── requirements.txt
├── .env            # 環境設定（自行建立）
├── .env.example
├── public/
│   └── index.html  # 前端 SPA（純 HTML/CSS/JS）
└── scheduling.db   # SQLite 資料庫（自動建立）
```

## API 路由

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/auth/status` | 登入狀態 |
| POST | `/api/admin/login` | 管理者登入 |
| GET/PUT | `/api/admin/email-settings` | Email 設定 |
| POST | `/api/admin/email-test` | SMTP 連線測試 |
| GET/POST | `/api/admin/event` | 讀取/儲存活動 |
| PUT | `/api/admin/event/toggle` | 開放/關閉報名 |
| GET | `/api/admin/bookings` | 所有預約清單 |
| GET | `/api/public/event` | 目前開放活動（公開） |
| POST | `/api/user/request-code` | 寄送驗證碼 |
| POST | `/api/user/verify` | 驗證碼登入 |
| GET | `/api/user/event` | 目前活動（需登入） |
| GET | `/api/user/calendar` | 週預約資料 |
| POST | `/api/user/book` | 預約時段 |
| DELETE | `/api/user/book` | 取消預約 |
