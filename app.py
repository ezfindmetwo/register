"""排程預約系統 — Flask + SQLite"""
import os, sqlite3, random, smtplib, ssl, functools, requests as _requests
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from flask import Flask, request, jsonify, session, send_from_directory, redirect
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY', 'sched-secret-change-me')
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

DB_PATH        = os.getenv('DB_PATH',        'scheduling.db')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
IS_DEV         = os.getenv('FLASK_ENV',      'development') != 'production'

# LINE Login config
LINE_CHANNEL_ID     = os.getenv('LINE_CHANNEL_ID', '')
LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET', '')
LINE_REDIRECT_URI   = os.getenv('LINE_REDIRECT_URI', '')  # e.g. https://yourapp.onrender.com/api/auth/line/callback
_raw_domains   = os.getenv('ALLOWED_EMAIL_DOMAINS', '')
ALLOWED_DOMAINS= [d.strip().lower() for d in _raw_domains.split(',') if d.strip()]

# ─── Database ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admin_settings (
            id           INTEGER PRIMARY KEY DEFAULT 1,
            password     TEXT NOT NULL DEFAULT 'admin123',
            auto_logout  INTEGER NOT NULL DEFAULT 30
        );
        INSERT OR IGNORE INTO admin_settings(id, password, auto_logout) VALUES(1, 'admin123', 30);
        CREATE TABLE IF NOT EXISTS email_settings (
            id INTEGER PRIMARY KEY,
            provider   TEXT NOT NULL DEFAULT 'smtp',
            host TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 587,
            username TEXT NOT NULL DEFAULT '', password TEXT NOT NULL DEFAULT '',
            use_ssl INTEGER NOT NULL DEFAULT 1, from_email TEXT NOT NULL DEFAULT '',
            api_key TEXT NOT NULL DEFAULT '',
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
            schedule_mode TEXT NOT NULL DEFAULT 'uniform',
            slot_start_time TEXT NOT NULL DEFAULT '09:00',
            slot_end_time TEXT NOT NULL DEFAULT '17:00',
            slot_duration INTEGER NOT NULL DEFAULT 30,
            max_slots_per_user INTEGER NOT NULL DEFAULT 3,
            is_open INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS event_day_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            day_of_week INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            slot_start_time TEXT NOT NULL DEFAULT '09:00',
            slot_end_time TEXT NOT NULL DEFAULT '17:00',
            slot_duration INTEGER NOT NULL DEFAULT 30,
            UNIQUE(event_id, day_of_week)
        );
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            line_user_id  TEXT UNIQUE,
            email         TEXT,
            chinese_name  TEXT,
            display_name  TEXT,
            picture_url   TEXT,
            created_at    TEXT DEFAULT (datetime('now')),
            last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            code TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL, is_used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS slot_bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL REFERENCES events(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            booking_date TEXT NOT NULL,
            slot_start_time TEXT NOT NULL, slot_end_time TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(event_id, booking_date, slot_start_time)
        );
        CREATE INDEX IF NOT EXISTS idx_bookings_event_date ON slot_bookings(event_id, booking_date);
        CREATE INDEX IF NOT EXISTS idx_bookings_user       ON slot_bookings(event_id, user_id);
        CREATE INDEX IF NOT EXISTS idx_codes_user          ON verification_codes(user_id, is_used);
        CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
        CREATE INDEX IF NOT EXISTS idx_day_sched_event     ON event_day_schedules(event_id);
        -- 舊版相容表 (若已存在則忽略)
        CREATE TABLE IF NOT EXISTS event_allowed_days (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            day_of_week INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            UNIQUE(event_id, day_of_week)
        );
        CREATE TABLE IF NOT EXISTS event_excluded_dates (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id     INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            excluded_date TEXT NOT NULL,
            note         TEXT DEFAULT '',
            UNIQUE(event_id, excluded_date)
        );
        CREATE INDEX IF NOT EXISTS idx_excluded_event ON event_excluded_dates(event_id);
        """)
    # Migration: add columns (idempotent)
    with get_db() as c:
        for col_sql in [
            "ALTER TABLE events ADD COLUMN schedule_mode TEXT NOT NULL DEFAULT 'uniform'",
            "ALTER TABLE email_settings ADD COLUMN provider TEXT NOT NULL DEFAULT 'smtp'",
            "ALTER TABLE email_settings ADD COLUMN api_key TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE users ADD COLUMN line_user_id TEXT",
            "ALTER TABLE users ADD COLUMN chinese_name TEXT",
            "ALTER TABLE users ADD COLUMN display_name TEXT",
            "ALTER TABLE users ADD COLUMN picture_url TEXT",
        ]:
            try: c.execute(col_sql)
            except: pass
        # 建立索引（欄位加完後才能建）
        for idx_sql in [
            "ALTER TABLE admin_settings ADD COLUMN auto_logout INTEGER NOT NULL DEFAULT 30",
            "CREATE INDEX IF NOT EXISTS idx_users_line ON users(line_user_id)",
        ]:
            try: c.execute(idx_sql)
            except: pass
    print(f"[DB] {os.path.abspath(DB_PATH)}")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def get_admin_password():
    """Get admin password from DB (overrides ADMIN_PASSWORD env var)."""
    try:
        with get_db() as c:
            row = c.execute('SELECT password FROM admin_settings WHERE id=1').fetchone()
            if row and row['password']:
                return row['password']
    except: pass
    return ADMIN_PASSWORD

def row_to_dict(r):   return dict(r) if r else None
def rows_to_list(rs): return [dict(r) for r in rs]
def generate_code():  return ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
def now_str():        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
def expires_at(m=10): return (datetime.now(timezone.utc)+timedelta(minutes=m)).strftime('%Y-%m-%d %H:%M:%S')
def ok(**kw):         return jsonify({'success': True, **kw})
def err(msg, s=400):  return jsonify({'error': msg}), s

def admin_required(f):
    @functools.wraps(f)
    def w(*a, **kw):
        if not session.get('is_admin'): return err('請先以管理者身份登入', 401)
        return f(*a, **kw)
    return w

def user_required(f):
    @functools.wraps(f)
    def w(*a, **kw):
        if not session.get('user_id'): return err('請先登入', 401)
        return f(*a, **kw)
    return w

# ─── Email ────────────────────────────────────────────────────────────────────
def _make_from(name, addr):
    from email.header import Header
    from email.utils import formataddr
    return formataddr((Header(name, "utf-8").encode(), addr))

# ─── Email sending ─────────────────────────────────────────────────────────────
def _send_via_api(settings, to_email, subject, html):
    """HTTP API 發信 — 支援 Resend / Brevo，不受 Render SMTP 封鎖。"""
    prov    = settings.get('provider','resend')
    api_key = settings.get('api_key','')
    from_em = settings.get('from_email','')
    if prov == 'brevo':
        resp = _requests.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={'api-key': api_key, 'Content-Type': 'application/json'},
            json={'sender':{'email': from_em},
                  'to':[{'email': to_email}],
                  'subject': subject, 'htmlContent': html},
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            raise Exception(f'Brevo API error {resp.status_code}: {resp.text}')
    else:  # resend (default)
        resp = _requests.post(
            'https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={'from': from_em, 'to': [to_email], 'subject': subject, 'html': html},
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            raise Exception(f'Resend API error {resp.status_code}: {resp.text}')

def _smtp(s):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    host, port = s['host'], int(s['port'])
    if port == 465:
        srv = smtplib.SMTP_SSL(host, port, context=ctx, timeout=10)
    else:
        srv = smtplib.SMTP(host, port, timeout=10); srv.ehlo()
        if s.get('use_ssl'): srv.starttls(context=ctx); srv.ehlo()
    srv.login(s['username'], s['password']); return srv

def test_smtp(s): _smtp(s).quit()

def _build_html_code(code, from_email, host):
    return f"""<!DOCTYPE html>
<html><body style="background:#f0f4f8;font-family:'Segoe UI',sans-serif">
<div style="max-width:460px;margin:36px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">
  <div style="background:#1d4ed8;padding:24px 32px"><h1 style="color:#fff;margin:0;font-size:17px;font-weight:700">排程預約系統</h1></div>
  <div style="padding:28px 32px">
    <p style="color:#374151;font-size:15px;margin:0 0 16px">您好，以下是您的登入驗證碼：</p>
    <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;padding:22px;text-align:center;margin:0 0 20px">
      <span style="font-size:36px;font-weight:800;letter-spacing:14px;color:#0f172a;font-family:'Courier New',monospace">{code}</span>
    </div>
    <p style="color:#6b7280;font-size:13px;margin:0">此驗證碼將於 <strong>10 分鐘</strong>後失效。若非本人操作請忽略此信。</p>
  </div>
  <div style="background:#f9fafb;padding:12px 32px;border-top:1px solid #e5e7eb">
    <p style="color:#9ca3af;font-size:11px;margin:0">© 排程預約系統 — 系統自動發送，請勿回覆</p>
  </div>
</div></body></html>"""

def _build_html_test(settings, to_email):
    host_info = settings.get('host','') or 'Resend API'
    return f"""<!DOCTYPE html>
<html><body style="background:#f0f4f8;font-family:'Segoe UI',sans-serif">
<div style="max-width:460px;margin:36px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">
  <div style="background:#059669;padding:24px 32px">
    <h1 style="color:#fff;margin:0;font-size:17px;font-weight:700">✅ 排程預約系統 — 發信測試成功</h1>
  </div>
  <div style="padding:28px 32px">
    <p style="color:#374151;font-size:15px;margin:0 0 14px">您好，這封信代表您的 Email 設定正確無誤。</p>
    <table style="border-collapse:collapse;width:100%;font-size:13px">
      <tr><td style="padding:5px 0;color:#6b7280;width:90px">寄件方式</td><td style="color:#111827;font-weight:600">{settings.get('provider','smtp').upper()}</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280">寄件人</td><td style="color:#111827;font-weight:600">{settings.get('from_email','')}</td></tr>
      <tr><td style="padding:5px 0;color:#6b7280">收件人</td><td style="color:#111827;font-weight:600">{to_email}</td></tr>
    </table>
  </div>
  <div style="background:#f9fafb;padding:12px 32px;border-top:1px solid #e5e7eb">
    <p style="color:#9ca3af;font-size:11px;margin:0">© 排程預約系統 — 此為測試信，請勿回覆</p>
  </div>
</div></body></html>"""

def send_code_email(s, to_email, code):
    from email.header import Header
    subj = Header('【排程預約系統】登入驗證碼', 'utf-8').encode()
    html = _build_html_code(code, s.get('from_email',''), s.get('host',''))
    if s.get('provider') in ('resend','brevo'):
        _send_via_api(s, to_email, '【排程預約系統】登入驗證碼', html)
    else:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subj
        msg['From']    = _make_from('排程預約系統', s['from_email'])
        msg['To']      = to_email
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        srv = _smtp(s); srv.sendmail(s['from_email'], to_email, msg.as_string()); srv.quit()

def send_test_email(s, to_email):
    from email.header import Header
    subj = Header('【排程預約系統】Email 發信測試', 'utf-8').encode()
    html = _build_html_test(s, to_email)
    if s.get('provider') in ('resend','brevo'):
        _send_via_api(s, to_email, '【排程預約系統】Email 發信測試', html)
    else:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subj
        msg['From']    = _make_from('排程預約系統', s['from_email'])
        msg['To']      = to_email
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        srv = _smtp(s); srv.sendmail(s['from_email'], to_email, msg.as_string()); srv.quit()


def _get_dow_cnt(conn, eid):
    """取得 dow->slot_count 對應表，同時支援新版(event_day_schedules)和舊版(event_allowed_days)。"""
    rows = conn.execute(
        'SELECT day_of_week,slot_start_time,slot_end_time,slot_duration FROM event_day_schedules WHERE event_id=?', (eid,)
    ).fetchall()
    if rows:
        return {r['day_of_week']: calc_slots_count(r['slot_start_time'], r['slot_end_time'], r['slot_duration']) for r in rows}
    # 舊版 fallback: event_allowed_days + events.slot_* 欄位
    ev = conn.execute('SELECT slot_start_time,slot_end_time,slot_duration FROM events WHERE id=?', (eid,)).fetchone()
    if not ev: return {}
    slot_cnt = calc_slots_count(ev['slot_start_time'] or '09:00', ev['slot_end_time'] or '17:00', ev['slot_duration'] or 30)
    allowed  = conn.execute('SELECT day_of_week FROM event_allowed_days WHERE event_id=?', (eid,)).fetchall()
    return {r['day_of_week']: slot_cnt for r in allowed}

def _get_day_schedules(conn, eid):
    """取得 day_schedules 清單，同時支援新版和舊版。"""
    rows = conn.execute(
        'SELECT day_of_week,slot_start_time,slot_end_time,slot_duration FROM event_day_schedules WHERE event_id=? ORDER BY day_of_week', (eid,)
    ).fetchall()
    if rows:
        return rows_to_list(rows)
    ev = conn.execute('SELECT slot_start_time,slot_end_time,slot_duration FROM events WHERE id=?', (eid,)).fetchone()
    if not ev: return []
    allowed = conn.execute('SELECT day_of_week FROM event_allowed_days WHERE event_id=? ORDER BY day_of_week', (eid,)).fetchall()
    return [{'day_of_week': r['day_of_week'],
             'slot_start_time': ev['slot_start_time'] or '09:00',
             'slot_end_time':   ev['slot_end_time']   or '17:00',
             'slot_duration':   ev['slot_duration']   or 30} for r in allowed]

# ─── Event helpers ────────────────────────────────────────────────────────────
def _load_event_full(conn, open_only=False):
    q = 'SELECT * FROM events'
    q += ' WHERE is_open=1' if open_only else ''
    q += ' ORDER BY id DESC LIMIT 1'
    ev = conn.execute(q).fetchone()
    if not ev: return None
    d = dict(ev)
    ds_list = _get_day_schedules(conn, d['id'])
    d['day_schedules'] = ds_list
    d['allowed_days']  = [r['day_of_week'] for r in ds_list]
    ex = conn.execute('SELECT excluded_date, note FROM event_excluded_dates WHERE event_id=? ORDER BY excluded_date', (d['id'],)).fetchall()
    d['excluded_dates'] = rows_to_list(ex)
    return d

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.get('/api/auth/status')
def auth_status():
    with get_db() as _c:
        uid = session.get('user_id')
        urow = _c.execute('SELECT chinese_name,display_name,picture_url FROM users WHERE id=?',(uid,)).fetchone() if uid else None
    return ok(is_admin=bool(session.get('is_admin')),
              user_id=uid,
              chinese_name=urow['chinese_name'] if urow else None,
              display_name=urow['display_name'] if urow else None,
              picture_url=urow['picture_url'] if urow else None)

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════════════════
@app.post('/api/admin/login')
def admin_login():
    if (request.json or {}).get('password') == get_admin_password():
        session['is_admin'] = True; session.permanent = True; return ok()
    return err('密碼錯誤', 401)

@app.post('/api/admin/logout')
def admin_logout():
    session.pop('is_admin', None); return ok()

@app.put('/api/admin/password')
@admin_required
def change_password():
    d = request.json or {}
    current = (d.get('current') or '').strip()
    new_pwd = (d.get('new')     or '').strip()
    confirm = (d.get('confirm') or '').strip()
    if current != get_admin_password():
        return err('目前密碼不正確')
    if len(new_pwd) < 6:
        return err('新密碼至少需要 6 個字元')
    if new_pwd != confirm:
        return err('新密碼與確認密碼不符')
    with get_db() as c:
        c.execute('INSERT OR REPLACE INTO admin_settings(id,password) VALUES(1,?)', (new_pwd,))
    return ok()

@app.get('/api/admin/email-settings')
@admin_required
def get_email():
    with get_db() as c:
        row = c.execute('SELECT * FROM email_settings LIMIT 1').fetchone()
    if not row:
        return jsonify(None)
    d = row_to_dict(row)
    d['has_password'] = bool(d.get('password'))
    d['has_api_key']  = bool(d.get('api_key'))
    d.pop('password', None)
    d.pop('api_key',  None)
    return jsonify(d)

@app.put('/api/admin/email-settings')
@admin_required
def save_email():
    d = request.json
    provider = (d.get('provider') or 'smtp').strip()
    with get_db() as c:
        ex = c.execute('SELECT id, password, api_key FROM email_settings LIMIT 1').fetchone()
        new_pwd = (d.get('password') or '').strip() or (ex['password'] if ex else '')
        new_key = (d.get('api_key')  or '').strip() or (ex['api_key']  if ex else '')
        vals = (provider, d.get('host',''), int(d.get('port',587)),
                d.get('username',''), new_pwd, 1 if d.get('ssl') else 0,
                d.get('from',''), new_key, now_str())
        if ex:
            c.execute('UPDATE email_settings SET provider=?,host=?,port=?,username=?,password=?,use_ssl=?,from_email=?,api_key=?,updated_at=? WHERE id='+str(ex['id']), vals)
        else:
            c.execute('INSERT INTO email_settings(provider,host,port,username,password,use_ssl,from_email,api_key,updated_at) VALUES(?,?,?,?,?,?,?,?,?)', vals)
    return ok()

@app.post('/api/admin/email-test')
@admin_required
def email_test():
    import smtplib as _smtp_mod
    d = request.json or {}
    provider = (d.get('provider') or 'smtp').strip()
    settings = {
        'provider':   provider,
        'host':       (d.get('host') or '').strip(),
        'port':       int(d.get('port') or 587),
        'username':   (d.get('username') or '').strip(),
        'password':   (d.get('password') or '').strip(),
        'use_ssl':    bool(d.get('ssl', True)),
        'from_email': (d.get('from') or '').strip(),
        'api_key':    (d.get('api_key') or '').strip(),
    }
    to_email = (d.get('to') or '').strip()
    if not settings['from_email']: return err('請填寫寄件人 Email')
    if not to_email:               return err('請填寫測試收件人 Email')
    if provider in ('resend','brevo'):
        if not settings['api_key']:
            with get_db() as c:
                row = c.execute('SELECT api_key FROM email_settings LIMIT 1').fetchone()
                if row and row['api_key']: settings['api_key'] = row['api_key']
        if not settings['api_key']: return err('請填寫 API Key')
    else:
        if not settings['host']:   return err('請填寫 SMTP 主機')
        if not settings['password']:
            with get_db() as c:
                row = c.execute('SELECT password FROM email_settings LIMIT 1').fetchone()
                if row and row['password']: settings['password'] = row['password']
    try:
        send_test_email(settings, to_email)
        return ok()
    except _smtp_mod.SMTPAuthenticationError:
        host = settings['host'].lower()
        if 'gmail' in host:
            hint = ('Gmail 帳號驗證失敗。Gmail 不允許直接使用帳號密碼，'
                    '請依以下步驟取得「應用程式密碼」：\n'
                    '① Google 帳戶 → 安全性 → 開啟兩步驟驗證\n'
                    '② 搜尋「應用程式密碼」→ 選擇「郵件」→ 產生\n'
                    '③ 將產生的 16 位密碼（不含空格）貼入密碼欄')
        elif 'outlook' in host or 'hotmail' in host or 'live' in host:
            hint = ('Outlook / Hotmail 帳號驗證失敗。\n'
                    '請確認：帳號為完整 Email 地址、密碼正確，'
                    '且帳號未開啟多因子驗證（若有，需改用應用程式密碼）。')
        else:
            hint = ('SMTP 帳號驗證失敗（535）。\n'
                    '請確認帳號與密碼正確，或洽 IT / 主機商取得正確的 SMTP 認證方式。')
        return err(hint)
    except _smtp_mod.SMTPConnectError as e:
        return err(f'無法連線至主機 {settings["host"]}:{settings["port"]}，請確認主機名稱與 Port 正確。（{e}）')
    except _smtp_mod.SMTPRecipientsRefused:
        return err(f'收件人 {to_email} 被伺服器拒絕，請確認收件地址格式正確。')
    except _smtp_mod.SMTPSenderRefused:
        return err(f'寄件地址 {settings["from_email"]} 被拒絕，請確認寄件人格式正確。')
    except _smtp_mod.SMTPException as e:
        return err(f'SMTP 錯誤：{e}')
    except OSError as e:
        return err(f'網路連線失敗（主機：{settings["host"]}:{settings["port"]}）：{e}')
    except Exception as e:
        return err(f'發送失敗：{e}')

@app.get('/api/admin/event')
@admin_required
def get_admin_event():
    with get_db() as c: return jsonify(_load_event_full(c))

@app.post('/api/admin/event')
@admin_required
def save_event():
    d   = request.json
    eid = d.get('id')
    mode= d.get('scheduleMode', 'uniform')

    with get_db() as c:
        # Build the uniform columns (for backward compat display)
        uni_start = d.get('slotStart', '09:00')
        uni_end   = d.get('slotEnd',   '17:00')
        uni_dur   = int(d.get('slotDuration', 30))

        if eid:
            c.execute("""UPDATE events SET name=?,start_date=?,end_date=?,schedule_mode=?,
                slot_start_time=?,slot_end_time=?,slot_duration=?,max_slots_per_user=?,updated_at=? WHERE id=?""",
                (d['name'],d['startDate'],d['endDate'],mode,uni_start,uni_end,uni_dur,
                 int(d['maxSlotsPerUser']),now_str(),eid))
            c.execute('DELETE FROM event_day_schedules WHERE event_id=?', (eid,))
        else:
            cur = c.execute("""INSERT INTO events(name,start_date,end_date,schedule_mode,
                slot_start_time,slot_end_time,slot_duration,max_slots_per_user)
                VALUES(?,?,?,?,?,?,?,?)""",
                (d['name'],d['startDate'],d['endDate'],mode,uni_start,uni_end,uni_dur,
                 int(d['maxSlotsPerUser'])))
            eid = cur.lastrowid

        # Save per-day schedules
        day_schedules = d.get('daySchedules', [])
        for ds in day_schedules:
            c.execute("""INSERT OR REPLACE INTO event_day_schedules
                (event_id,day_of_week,slot_start_time,slot_end_time,slot_duration)
                VALUES(?,?,?,?,?)""",
                (eid, int(ds['dayOfWeek']), ds['slotStart'], ds['slotEnd'], int(ds['slotDuration'])))
        # 排除日期
        c.execute('DELETE FROM event_excluded_dates WHERE event_id=?', (eid,))
        for ex in d.get('excludedDates', []):
            c.execute('INSERT OR IGNORE INTO event_excluded_dates(event_id,excluded_date,note) VALUES(?,?,?)',
                      (eid, ex['date'], ex.get('note', '')))

    return ok(id=eid)

@app.put('/api/admin/event/toggle')
@admin_required
def toggle_event():
    d = request.json
    with get_db() as c:
        c.execute('UPDATE events SET is_open=?,updated_at=? WHERE id=?',
                  (1 if d['isOpen'] else 0, now_str(), d['id']))
    return ok()

@app.get('/api/admin/bookings')
@admin_required
def admin_bookings():
    with get_db() as c:
        rows = c.execute(
            'SELECT b.id,b.event_id,u.email,u.chinese_name,u.display_name,'
            'b.booking_date,b.slot_start_time,b.slot_end_time,b.created_at '
            'FROM slot_bookings b JOIN users u ON b.user_id=u.id '
            'ORDER BY b.booking_date,b.slot_start_time').fetchall()
    return jsonify(rows_to_list(rows))

@app.delete('/api/admin/booking/<int:bid>')
@admin_required
def del_booking(bid):
    with get_db() as c: c.execute('DELETE FROM slot_bookings WHERE id=?', (bid,))
    return ok()

@app.get('/api/admin/export')
@admin_required
def export_bookings():
    import csv, io
    from flask import Response
    with get_db() as c:
        rows = c.execute(
            'SELECT u.chinese_name,u.display_name,u.email,u.line_user_id,'
            'b.booking_date,b.slot_start_time,b.slot_end_time,'
            'ev.name as event_name '
            'FROM slot_bookings b '
            'JOIN users u ON b.user_id=u.id '
            'JOIN events ev ON b.event_id=ev.id '
            'ORDER BY b.booking_date,b.slot_start_time').fetchall()
    buf = io.StringIO()
    buf.write('﻿')  # BOM for Excel UTF-8
    w = csv.writer(buf)
    w.writerow(['活動名稱','中文姓名','LINE顯示名稱','Email','LINE User ID','預約日期','開始時間','結束時間'])
    for r in rows:
        w.writerow([r['event_name'], r['chinese_name'] or '', r['display_name'] or '',
                    r['email'] or '', r['line_user_id'] or '',
                    r['booking_date'], str(r['slot_start_time'])[:5], str(r['slot_end_time'])[:5]])
    buf.seek(0)
    return Response(buf.getvalue(), mimetype='text/csv; charset=utf-8-sig',
                    headers={'Content-Disposition': 'attachment; filename="bookings.csv"'})

@app.post('/api/admin/import')
@admin_required
def import_bookings():
    import csv, io
    f = request.files.get('file')
    if not f: return err('請上傳 CSV 檔案')
    text = f.stream.read().decode('utf-8-sig').strip()
    reader = csv.DictReader(io.StringIO(text))
    skipped = 0; imported = 0; errors = []
    with get_db() as c:
        ev = c.execute('SELECT id FROM events ORDER BY id DESC LIMIT 1').fetchone()
        if not ev: return err('請先建立活動')
        eid = ev['id']
        for i, row in enumerate(reader, 2):
            try:
                name  = (row.get('中文姓名') or '').strip()
                email = (row.get('Email') or '').strip()
                line_uid = (row.get('LINE User ID') or '').strip()
                date  = (row.get('預約日期') or '').strip()
                ts    = (row.get('開始時間') or '').strip()
                te    = (row.get('結束時間') or '').strip()
                if not date or not ts: skipped += 1; continue
                # Find or create user
                user = None
                if line_uid:
                    user = c.execute('SELECT id FROM users WHERE line_user_id=?', (line_uid,)).fetchone()
                if not user and email:
                    user = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
                if not user:
                    uid = c.execute(
                        'INSERT INTO users(line_user_id,email,chinese_name,display_name) VALUES(?,?,?,?)',
                        (line_uid or None, email or None, name or None, name or None)).lastrowid
                else:
                    uid = user['id']
                    if name: c.execute('UPDATE users SET chinese_name=? WHERE id=? AND chinese_name IS NULL', (name, uid))
                # Check if slot already exists
                exists = c.execute(
                    'SELECT id FROM slot_bookings WHERE event_id=? AND user_id=? AND booking_date=? AND slot_start_time=?',
                    (eid, uid, date, ts)).fetchone()
                if exists: skipped += 1; continue
                # Check event slot conflict (same slot taken by someone else)
                conflict = c.execute(
                    'SELECT id FROM slot_bookings WHERE event_id=? AND booking_date=? AND slot_start_time=?',
                    (eid, date, ts)).fetchone()
                if conflict: skipped += 1; errors.append(f'第{i}行：{date} {ts} 時段已被他人預約'); continue
                c.execute(
                    'INSERT INTO slot_bookings(event_id,user_id,booking_date,slot_start_time,slot_end_time) VALUES(?,?,?,?,?)',
                    (eid, uid, date, ts, te))
                imported += 1
            except Exception as e:
                errors.append(f'第{i}行錯誤：{e}')
    return ok(imported=imported, skipped=skipped, errors=errors[:10])

@app.get('/api/admin/export-event')
@admin_required
def export_event():
    with get_db() as c:
        ev = _load_event_full(c)
        if not ev: return err('尚無活動設定')
        ex = c.execute('SELECT excluded_date,note FROM event_excluded_dates WHERE event_id=? ORDER BY excluded_date',(ev['id'],)).fetchall()
    import json
    from flask import Response
    data = {
        'name':               ev.get('name',''),
        'start_date':         ev.get('start_date',''),
        'end_date':           ev.get('end_date',''),
        'schedule_mode':      ev.get('schedule_mode','uniform'),
        'max_slots_per_user': ev.get('max_slots_per_user',3),
        'slot_start_time':    ev.get('slot_start_time','09:00'),
        'slot_end_time':      ev.get('slot_end_time','17:00'),
        'slot_duration':      ev.get('slot_duration',30),
        'day_schedules':      ev.get('day_schedules',[]),
        'excluded_dates':     rows_to_list(ex),
    }
    out = json.dumps(data, ensure_ascii=False, indent=2)
    return Response(out, mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename="event_settings.json"'})

@app.post('/api/admin/import-event')
@admin_required
def import_event():
    import json
    f = request.files.get('file')
    if not f: return err('請上傳 JSON 檔案')
    try:
        d = json.loads(f.stream.read().decode('utf-8'))
    except Exception as e:
        return err('JSON 格式錯誤：' + str(e))
    for k in ['name','start_date','end_date']:
        if not d.get(k): return err('缺少必要欄位：' + k)
    mode  = d.get('schedule_mode','uniform')
    ds_raw= d.get('day_schedules',[])
    ss    = d.get('slot_start_time','09:00')
    se    = d.get('slot_end_time','17:00')
    dur   = d.get('slot_duration',30)
    day_schedules = [{'dayOfWeek': r['day_of_week'],
                      'slotStart': r.get('slot_start_time',ss),
                      'slotEnd':   r.get('slot_end_time',se),
                      'slotDuration': r.get('slot_duration',dur)} for r in ds_raw]
    excluded = d.get('excluded_dates',[])
    with get_db() as c:
        ex = c.execute('SELECT id FROM events ORDER BY id DESC LIMIT 1').fetchone()
        if ex:
            eid = ex['id']
            c.execute('UPDATE events SET name=?,start_date=?,end_date=?,schedule_mode=?,slot_start_time=?,slot_end_time=?,slot_duration=?,max_slots_per_user=? WHERE id=?',
                      (d['name'],d['start_date'],d['end_date'],mode,ss,se,dur,int(d.get('max_slots_per_user',3)),eid))
        else:
            eid = c.execute('INSERT INTO events(name,start_date,end_date,schedule_mode,slot_start_time,slot_end_time,slot_duration,max_slots_per_user) VALUES(?,?,?,?,?,?,?,?)',
                            (d['name'],d['start_date'],d['end_date'],mode,ss,se,dur,int(d.get('max_slots_per_user',3)))).lastrowid
        c.execute('DELETE FROM event_day_schedules WHERE event_id=?',(eid,))
        for ds in day_schedules:
            c.execute('INSERT INTO event_day_schedules(event_id,day_of_week,slot_start_time,slot_end_time,slot_duration) VALUES(?,?,?,?,?)',
                      (eid,int(ds['dayOfWeek']),ds['slotStart'],ds['slotEnd'],int(ds['slotDuration'])))
        c.execute('DELETE FROM event_excluded_dates WHERE event_id=?',(eid,))
        for ex2 in excluded:
            c.execute('INSERT OR IGNORE INTO event_excluded_dates(event_id,excluded_date,note) VALUES(?,?,?)',
                      (eid,ex2.get('excluded_date',''),ex2.get('note','')))
    return ok()

@app.get('/api/admin/settings')
@admin_required
def get_admin_settings():
    with get_db() as c:
        row = c.execute('SELECT auto_logout FROM admin_settings WHERE id=1').fetchone()
    return ok(auto_logout=row['auto_logout'] if row else 30)

@app.put('/api/admin/settings')
@admin_required
def save_admin_settings():
    d = request.json or {}
    al = int(d.get('auto_logout', 30))
    if al < 1: al = 1
    with get_db() as c:
        c.execute('INSERT OR REPLACE INTO admin_settings(id,password,auto_logout) VALUES(1,(SELECT password FROM admin_settings WHERE id=1),?)', (al,))
    return ok()

# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC / USER
# ══════════════════════════════════════════════════════════════════════════════
@app.get('/api/public/config')
def public_config():
    return ok(allowed_domains=ALLOWED_DOMAINS, line_enabled=bool(LINE_CHANNEL_ID))

@app.get('/api/public/event')
def public_event():
    with get_db() as c:
        row = c.execute('SELECT id,name,start_date,end_date,is_open FROM events WHERE is_open=1 ORDER BY id DESC LIMIT 1').fetchone()
    return jsonify(row_to_dict(row))

def _line_error_page(msg):
    """Show a visible error page on LINE callback failure (not silent redirect)."""
    import html as _html
    safe_msg = _html.escape(str(msg))
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>body{{font-family:'Segoe UI',sans-serif;display:flex;align-items:center;
  justify-content:center;height:100vh;margin:0;background:#fef2f2}}
.box{{text-align:center;padding:40px;max-width:480px}}
.ico{{font-size:48px;margin-bottom:12px}}
.ttl{{font-size:18px;font-weight:700;color:#991b1b;margin-bottom:8px}}
.msg{{color:#7f1d1d;font-size:13px;background:#fee2e2;padding:12px;border-radius:8px;word-break:break-all}}
.btn{{margin-top:20px;display:inline-block;background:#1d4ed8;color:#fff;
  padding:10px 28px;border-radius:9px;text-decoration:none;font-weight:700}}</style>
</head><body><div class="box">
<div class="ico">&#10060;</div>
<div class="ttl">LINE 登入失敗</div>
<div class="msg">{safe_msg}</div>
<a href="/" class="btn">返回首頁</a>
</div></body></html>""", 400

# ── LINE Login OAuth2 ─────────────────────────────────────────────────────
import hashlib, hmac, base64, secrets as _secrets

@app.get('/api/auth/line/url')
def line_login_url():
    if not LINE_CHANNEL_ID or not LINE_REDIRECT_URI:
        return err('LINE Login 尚未設定（請確認 LINE_CHANNEL_ID 與 LINE_REDIRECT_URI）')
    import urllib.parse as _up
    state = _secrets.token_urlsafe(16)
    session['line_state'] = state
    # redirect_uri 必須 URL encode
    params = (f'response_type=code&client_id={LINE_CHANNEL_ID}'
              f'&redirect_uri={_up.quote(LINE_REDIRECT_URI, safe="")}'
              f'&state={state}&scope=profile%20openid&bot_prompt=normal')
    return ok(url='https://access.line.me/oauth2/v2.1/authorize?' + params)

# strict_slashes=False: 同時接受 /callback 和 /callback/
@app.get('/api/auth/line/callback', strict_slashes=False)
def line_callback():
    code  = request.args.get('code')
    error = request.args.get('error')
    if error or not code:
        desc = request.args.get('error_description', error or '授權失敗')
        return _line_error_page(desc)
    try:
        token_resp = _requests.post('https://api.line.me/oauth2/v2.1/token', data={
            'grant_type':    'authorization_code',
            'code':          code,
            'redirect_uri':  LINE_REDIRECT_URI,
            'client_id':     LINE_CHANNEL_ID,
            'client_secret': LINE_CHANNEL_SECRET,
        }, timeout=15)
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
        if not access_token:
            raise Exception(token_data.get('error_description') or
                            token_data.get('error') or '取得 token 失敗')
        profile_resp = _requests.get('https://api.line.me/v2/profile',
            headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        profile = profile_resp.json()
        line_uid = profile.get('userId')
        display  = profile.get('displayName', '')
        pic      = profile.get('pictureUrl', '')
        if not line_uid:
            raise Exception('無法取得 LINE userId')
    except Exception as e:
        return _line_error_page(str(e))

    with get_db() as c:
        user = c.execute('SELECT id, chinese_name FROM users WHERE line_user_id=?', (line_uid,)).fetchone()
        if user:
            uid = user['id']
            c.execute("UPDATE users SET display_name=?,picture_url=?,last_login_at=datetime('now') WHERE id=?",
                      (display, pic, uid))
            needs_name = not user['chinese_name']
        else:
            uid = c.execute(
                'INSERT INTO users(line_user_id,display_name,picture_url) VALUES(?,?,?)',
                (line_uid, display, pic)).lastrowid
            needs_name = True

    session['user_id']   = uid
    session['user_line'] = line_uid
    session.permanent    = True

    from flask import redirect as _redir
    return _redir('/')

# LINE callback directly uses Flask redirect — no sessionStorage needed

@app.post('/api/user/set-name')
def set_name():
    uid = session.get('user_id')
    if not uid: return err('請先登入', 401)
    import re
    name = (request.json or {}).get('name', '').strip()
    if not name: return err('請輸入姓名')
    if len(name) > 4: return err('姓名最多 4 個字')
    if re.search(r'[A-Za-z0-9]', name): return err('姓名不允許英文或數字')
    with get_db() as c:
        c.execute('UPDATE users SET chinese_name=? WHERE id=?', (name, uid))
    return ok()

@app.post('/api/user/logout')
def user_logout():
    session.pop('user_id',   None)
    session.pop('user_line', None)
    return ok()

@app.get('/api/user/event')
@user_required
def user_event():
    with get_db() as c:
        return jsonify(_load_event_full(c, open_only=True))

@app.get('/api/user/calendar')
@user_required
def calendar():
    eid = request.args.get('eventId', type=int)
    ws  = request.args.get('weekStart', '')
    if not eid or not ws: return err('缺少參數')
    try: we = (datetime.strptime(ws,'%Y-%m-%d')+timedelta(days=6)).strftime('%Y-%m-%d')
    except ValueError: return err('日期格式錯誤')
    uid = session['user_id']
    with get_db() as c:
        bks = c.execute(
            'SELECT b.booking_date,b.slot_start_time,b.slot_end_time,'
            'u.chinese_name,u.display_name,'
            'CASE WHEN b.user_id=? THEN 1 ELSE 0 END AS is_mine '
            'FROM slot_bookings b JOIN users u ON b.user_id=u.id '
            'WHERE b.event_id=? AND b.booking_date BETWEEN ? AND ?',
            (uid, eid, ws, we)).fetchall()
        cnt = c.execute(
            'SELECT COUNT(*) as cnt FROM slot_bookings WHERE event_id=? AND user_id=?',
            (eid, uid)).fetchone()['cnt']
    return jsonify(bookings=rows_to_list(bks), my_total=cnt)

@app.post('/api/user/book')
@user_required
def book():
    d = request.json or {}
    eid,date,ss,se = d.get('eventId'),d.get('date'),d.get('slotStart'),d.get('slotEnd')
    uid = session['user_id']
    with get_db() as c:
        ev = c.execute('SELECT max_slots_per_user,is_open FROM events WHERE id=?', (eid,)).fetchone()
        if not ev or not ev['is_open']: return err('活動不存在或已關閉')
        cnt = c.execute('SELECT COUNT(*) as cnt FROM slot_bookings WHERE event_id=? AND user_id=?',
            (eid, uid)).fetchone()['cnt']
        if cnt >= ev['max_slots_per_user']: return err(f"已達上限（最多 {ev['max_slots_per_user']} 個時段）")
        if c.execute('SELECT id FROM slot_bookings WHERE event_id=? AND booking_date=? AND slot_start_time=?',
                     (eid,date,ss)).fetchone(): return err('該時段已被他人預約')
        try:
            c.execute('INSERT INTO slot_bookings(event_id,user_id,booking_date,slot_start_time,slot_end_time) VALUES(?,?,?,?,?)',
                      (eid,uid,date,ss,se))
        except sqlite3.IntegrityError: return err('該時段已被搶先預約')
    return ok()

@app.delete('/api/user/book')
@user_required
def cancel():
    d = request.json or {}
    eid,date,ss = d.get('eventId'),d.get('date'),d.get('slotStart')
    uid = session['user_id']
    with get_db() as c:
        c.execute('DELETE FROM slot_bookings WHERE event_id=? AND user_id=? AND booking_date=? AND slot_start_time=?',
                  (eid,uid,date,ss))
    return ok()


# ── Month Availability ────────────────────────────────────────────────────────
def calc_slots_count(start, end, dur):
    """Count how many slots fit between start and end with given duration."""
    def to_min(t): h,m=t.split(':'); return int(h)*60+int(m)
    cur, fin, count = to_min(start), to_min(end), 0
    while cur + int(dur) <= fin: cur += int(dur); count += 1
    return count

@app.get('/api/user/month-availability')
@user_required
def month_availability():
    import calendar as cal_mod
    from datetime import date as date_cls
    eid   = request.args.get('eventId', type=int)
    year  = request.args.get('year',  type=int)
    month = request.args.get('month', type=int)
    if not all([eid, year, month]): return err('缺少參數')
    with get_db() as c:
        ev = c.execute('SELECT start_date,end_date FROM events WHERE id=?',(eid,)).fetchone()
        if not ev: return err('活動不存在')
        dow_cnt = _get_dow_cnt(c, eid)
        _, days_in = cal_mod.monthrange(year, month)
        ms=f'{year:04d}-{month:02d}-01'; me=f'{year:04d}-{month:02d}-{days_in:02d}'
        bk_rows=c.execute('SELECT booking_date,COUNT(*) as cnt FROM slot_bookings WHERE event_id=? AND booking_date BETWEEN ? AND ? GROUP BY booking_date',(eid,ms,me)).fetchall()
        bk_cnt={r['booking_date']:r['cnt'] for r in bk_rows}
    ev_s,ev_e=dict(ev)['start_date'],dict(ev)['end_date']
    result={}
    for day in range(1,days_in+1):
        ds2=f'{year:04d}-{month:02d}-{day:02d}'
        if ds2<ev_s or ds2>ev_e: continue
        py_dow=date_cls(year,month,day).weekday()   # Mon=0
        our_dow=(py_dow+1)%7                         # Sun=0,Mon=1,...
        if our_dow not in dow_cnt: continue
        total=dow_cnt[our_dow]; booked=bk_cnt.get(ds2,0)
        result[ds2]='full' if booked>=total else 'open'
    return jsonify(result)

@app.get('/api/user/day-slots')
@user_required
def day_slots():
    eid = request.args.get('eventId', type=int)
    date = request.args.get('date', '')
    uid = session['user_id']
    if not eid or not date: return err('缺少參數')
    with get_db() as c:
        bks = c.execute(
            'SELECT b.slot_start_time, b.slot_end_time, '
            'u.chinese_name, u.display_name, '
            'CASE WHEN b.user_id=? THEN 1 ELSE 0 END AS is_mine '
            'FROM slot_bookings b JOIN users u ON b.user_id=u.id '
            'WHERE b.event_id=? AND b.booking_date=?',
            (uid, eid, date)).fetchall()
        my_total = c.execute(
            'SELECT COUNT(*) as cnt FROM slot_bookings WHERE event_id=? AND user_id=?',
            (eid, uid)).fetchone()['cnt']
    return jsonify(bookings=rows_to_list(bks), my_total=my_total)


# ── All Availability (entire event range) ──────────────────────────────────────
@app.get('/api/user/all-availability')
@user_required
def all_availability():
    from datetime import date as _date, timedelta as _td
    from collections import defaultdict
    eid   = request.args.get('eventId', type=int)
    if not eid: return err('缺少參數')
    uid = session['user_id']
    with get_db() as c:
        ev = c.execute('SELECT start_date,end_date FROM events WHERE id=?',(eid,)).fetchone()
        if not ev: return err('活動不存在')
        dow_cnt = _get_dow_cnt(c, eid)
        bk_rows = c.execute(
            "SELECT b.booking_date, CASE WHEN b.user_id=? THEN 1 ELSE 0 END AS is_mine "
            "FROM slot_bookings b WHERE b.event_id=?",
            (uid, eid)).fetchall()
    day_booked = defaultdict(int)
    my_dates = set()
    for r in bk_rows:
        day_booked[r['booking_date']] += 1
        if r['is_mine']:
            my_dates.add(r['booking_date'])
    ev_s = dict(ev)['start_date']
    ev_e = dict(ev)['end_date']
    with get_db() as c2:
        ex_rows = c2.execute('SELECT excluded_date, note FROM event_excluded_dates WHERE event_id=? ORDER BY excluded_date',(eid,)).fetchall()
    excluded_set = {r['excluded_date'] for r in ex_rows}
    excluded_list = [{'date': r['excluded_date'], 'note': r['note'] or ''} for r in ex_rows]
    result = {}
    cur = _date.fromisoformat(ev_s)
    end = _date.fromisoformat(ev_e)
    while cur <= end:
        ds2 = cur.isoformat()
        if ds2 not in excluded_set:
            our_dow = (cur.weekday() + 1) % 7
            if our_dow in dow_cnt:
                total  = dow_cnt[our_dow]
                booked = day_booked.get(ds2, 0)
                result[ds2] = 'full' if booked >= total else 'open'
        cur += _td(days=1)
    return jsonify(availability=result, my_dates=list(my_dates), excluded_dates=excluded_list)

@app.get('/')
def index(): return send_from_directory('public', 'index.html')

@app.errorhandler(404)
def not_found(_): return send_from_directory('public', 'index.html')

# 無論用 gunicorn 或直接執行都會初始化 DB
init_db()

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    print(f"\n🚀  http://localhost:{port}  |  Dev={IS_DEV}\n")
    app.run(host='0.0.0.0', port=port, debug=IS_DEV)

