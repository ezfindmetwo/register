"""排程預約系統 — Flask + SQLite"""
import os, sqlite3, random, smtplib, ssl, functools
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from flask import Flask, request, jsonify, session, send_from_directory
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY', 'sched-secret-change-me')
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

DB_PATH        = os.getenv('DB_PATH',        'scheduling.db')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
IS_DEV         = os.getenv('FLASK_ENV',      'development') != 'production'
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
        CREATE TABLE IF NOT EXISTS email_settings (
            id INTEGER PRIMARY KEY,
            host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 587,
            username TEXT NOT NULL, password TEXT NOT NULL,
            use_ssl INTEGER NOT NULL DEFAULT 1, from_email TEXT NOT NULL,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            created_at TEXT DEFAULT (datetime('now')), last_login_at TEXT
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
    # Migration: add schedule_mode to existing events table (idempotent)
    with get_db() as c:
        try: c.execute("ALTER TABLE events ADD COLUMN schedule_mode TEXT NOT NULL DEFAULT 'uniform'")
        except: pass
    print(f"[DB] {os.path.abspath(DB_PATH)}")

# ─── Helpers ──────────────────────────────────────────────────────────────────
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
        if not session.get('user_email'): return err('請先登入', 401)
        return f(*a, **kw)
    return w

# ─── Email ────────────────────────────────────────────────────────────────────
def _make_from(name, addr):
    """Encode display name only; keep email address as plain ASCII."""
    from email.header import Header
    from email.utils import formataddr
    return formataddr((Header(name, "utf-8").encode(), addr))

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

def send_code_email(s, to, code):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header('【排程預約系統】登入驗證碼', 'utf-8').encode()
    msg['From']    = _make_from('排程預約系統', s['from_email'])
    msg['To']      = to
    html = f"""<html><body style="background:#f0f4f8;font-family:'Segoe UI',sans-serif">
<div style="max-width:460px;margin:36px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">
  <div style="background:#1d4ed8;padding:26px 32px"><h1 style="color:#fff;margin:0;font-size:18px;font-weight:700;letter-spacing:-.3px">排程預約系統</h1></div>
  <div style="padding:30px 32px">
    <p style="color:#374151;font-size:15px;margin:0 0 16px">您好，以下是您的登入驗證碼：</p>
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:22px;text-align:center;margin:0 0 20px">
      <span style="font-size:36px;font-weight:800;letter-spacing:14px;color:#0f172a;font-family:'Courier New',monospace">{code}</span>
    </div>
    <p style="color:#6b7280;font-size:13px;margin:0">此驗證碼將於 <strong>10 分鐘</strong>後失效。若非本人操作請忽略此信。</p>
  </div>
  <div style="background:#f9fafb;padding:12px 32px;border-top:1px solid #e5e7eb">
    <p style="color:#9ca3af;font-size:11px;margin:0">© 排程預約系統 — 系統自動發送，請勿回覆</p>
  </div>
</div></body></html>"""
    msg.attach(MIMEText(html, 'html', 'utf-8'))
    srv = _smtp(s); srv.sendmail(s['from_email'], to, msg.as_string()); srv.quit()

def send_test_email(s, to_email):
    """發送實際測試信，驗證完整的寄信流程。"""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header('【排程預約系統】Email 發信測試', 'utf-8').encode()
    msg['From']    = _make_from('排程預約系統', s['from_email'])
    msg['To']      = to_email
    html = f"""<!DOCTYPE html>
<html><body style="background:#f0f4f8;font-family:'Segoe UI',sans-serif">
<div style="max-width:460px;margin:36px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">
  <div style="background:#059669;padding:24px 32px">
    <h1 style="color:#fff;margin:0;font-size:17px;font-weight:700">✅ 排程預約系統 — 發信測試成功</h1>
  </div>
  <div style="padding:28px 32px">
    <p style="color:#374151;font-size:15px;margin:0 0 14px">您好，這封信代表您的 Email 設定正確無誤。</p>
    <table style="border-collapse:collapse;width:100%;font-size:13px">
      <tr><td style="padding:6px 0;color:#6b7280;width:110px">SMTP 主機</td><td style="color:#111827;font-weight:600">{s['host']}:{s['port']}</td></tr>
      <tr><td style="padding:6px 0;color:#6b7280">寄件人</td><td style="color:#111827;font-weight:600">{s['from_email']}</td></tr>
      <tr><td style="padding:6px 0;color:#6b7280">收件人</td><td style="color:#111827;font-weight:600">{to_email}</td></tr>
    </table>
  </div>
  <div style="background:#f9fafb;padding:12px 32px;border-top:1px solid #e5e7eb">
    <p style="color:#9ca3af;font-size:11px;margin:0">© 排程預約系統 — 此為測試信，請勿回覆</p>
  </div>
</div></body></html>"""
    msg.attach(MIMEText(html, 'html', 'utf-8'))
    srv = _smtp(s)
    srv.sendmail(s['from_email'], to_email, msg.as_string())
    srv.quit()

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
    return ok(is_admin=bool(session.get('is_admin')), user_email=session.get('user_email'))

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════════════════════════════════
@app.post('/api/admin/login')
def admin_login():
    if (request.json or {}).get('password') == ADMIN_PASSWORD:
        session['is_admin'] = True; session.permanent = True; return ok()
    return err('密碼錯誤', 401)

@app.post('/api/admin/logout')
def admin_logout():
    session.pop('is_admin', None); return ok()

@app.get('/api/admin/email-settings')
@admin_required
def get_email():
    with get_db() as c:
        row = c.execute('SELECT * FROM email_settings LIMIT 1').fetchone()
    if not row:
        return jsonify(None)
    d = row_to_dict(row)
    d['has_password'] = bool(d.get('password'))  # 告知前端是否已有儲存的密碼
    d.pop('password', None)                        # 不回傳明文密碼給前端
    return jsonify(d)

@app.put('/api/admin/email-settings')
@admin_required
def save_email():
    d = request.json
    with get_db() as c:
        ex = c.execute('SELECT id, password FROM email_settings LIMIT 1').fetchone()
        # 若密碼欄位空白，保留資料庫原有密碼（瀏覽器不會自動帶入 password 欄位）
        new_pwd = (d.get('password') or '').strip()
        if not new_pwd and ex:
            new_pwd = ex['password']  # 維持舊密碼
        if ex:
            c.execute("UPDATE email_settings SET host=?,port=?,username=?,password=?,use_ssl=?,from_email=?,updated_at=? WHERE id=?",
                      (d['host'],int(d['port']),d['username'],new_pwd,1 if d.get('ssl') else 0,d['from'],now_str(),ex['id']))
        else:
            c.execute("INSERT INTO email_settings(host,port,username,password,use_ssl,from_email) VALUES(?,?,?,?,?,?)",
                      (d['host'],int(d['port']),d['username'],new_pwd,1 if d.get('ssl') else 0,d['from']))
    return ok()

@app.post('/api/admin/email-test')
@admin_required
def email_test():
    import smtplib as _smtp_mod
    d = request.json or {}
    settings = {
        'host':       (d.get('host') or '').strip(),
        'port':       int(d.get('port') or 587),
        'username':   (d.get('username') or '').strip(),
        'password':   (d.get('password') or '').strip(),
        'use_ssl':    bool(d.get('ssl', True)),
        'from_email': (d.get('from') or '').strip(),
    }
    to_email = (d.get('to') or '').strip()
    if not settings['host']:       return err('請填寫 SMTP 主機')
    if not settings['from_email']: return err('請填寫寄件人 Email')
    if not to_email:               return err('請填寫測試收件人 Email')
    # 密碼欄位若為空（瀏覽器未帶入），從資料庫補回
    if not settings['password']:
        with get_db() as c:
            row = c.execute('SELECT password FROM email_settings LIMIT 1').fetchone()
            if row and row['password']:
                settings['password'] = row['password']
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
        rows = c.execute("""
            SELECT b.id,b.event_id,u.email,b.booking_date,b.slot_start_time,b.slot_end_time,b.created_at
            FROM slot_bookings b JOIN users u ON b.user_id=u.id
            ORDER BY b.booking_date,b.slot_start_time""").fetchall()
    return jsonify(rows_to_list(rows))

@app.delete('/api/admin/booking/<int:bid>')
@admin_required
def del_booking(bid):
    with get_db() as c: c.execute('DELETE FROM slot_bookings WHERE id=?', (bid,))
    return ok()

# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC / USER
# ══════════════════════════════════════════════════════════════════════════════
@app.get('/api/public/config')
def public_config():
    return ok(allowed_domains=ALLOWED_DOMAINS)

@app.get('/api/public/event')
def public_event():
    with get_db() as c:
        row = c.execute('SELECT id,name,start_date,end_date,is_open FROM events WHERE is_open=1 ORDER BY id DESC LIMIT 1').fetchone()
    return jsonify(row_to_dict(row))

@app.post('/api/user/request-code')
def request_code():
    email = ((request.json or {}).get('email') or '').strip().lower()
    if not email or '@' not in email: return err('請輸入有效的 Email 地址')
    if ALLOWED_DOMAINS:
        domain = email.split('@', 1)[1]
        if domain not in ALLOWED_DOMAINS:
            return err('此 Email 網域不被允許，請使用：' + '、'.join('@'+d for d in ALLOWED_DOMAINS))
    with get_db() as c:
        if not c.execute('SELECT id FROM events WHERE is_open=1 LIMIT 1').fetchone():
            return err('目前沒有開放報名的活動')
        user = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        uid  = user['id'] if user else c.execute('INSERT INTO users(email) VALUES(?)', (email,)).lastrowid
        c.execute('UPDATE verification_codes SET is_used=1 WHERE user_id=? AND is_used=0', (uid,))
        code = generate_code()
        c.execute('INSERT INTO verification_codes(user_id,code,expires_at) VALUES(?,?,?)', (uid,code,expires_at(10)))
    mail_sent = False
    try:
        with get_db() as c:
            cfg = c.execute('SELECT * FROM email_settings LIMIT 1').fetchone()
        if cfg: send_code_email(dict(cfg), email, code); mail_sent = True
    except Exception as e: print(f'[MAIL] {e}')
    payload = {'success': True, 'mail_sent': mail_sent}
    if IS_DEV: payload['dev_code'] = code
    return jsonify(payload)

@app.post('/api/user/verify')
def verify():
    d = request.json or {}
    email = (d.get('email') or '').strip().lower()
    code  = (d.get('code')  or '').strip().upper()
    with get_db() as c:
        row = c.execute("""
            SELECT vc.id FROM verification_codes vc JOIN users u ON vc.user_id=u.id
            WHERE u.email=? AND vc.code=? AND vc.is_used=0 AND vc.expires_at > datetime('now')
        """, (email, code)).fetchone()
        if not row: return err('驗證碼錯誤或已逾期（10 分鐘有效）', 401)
        c.execute('UPDATE verification_codes SET is_used=1 WHERE id=?', (row['id'],))
        c.execute("UPDATE users SET last_login_at=datetime('now') WHERE email=?", (email,))
    session['user_email'] = email; session.permanent = True; return ok()

@app.post('/api/user/logout')
def user_logout():
    session.pop('user_email', None); return ok()

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
    email = session['user_email']
    with get_db() as c:
        bks = c.execute("""
            SELECT b.booking_date,b.slot_start_time,b.slot_end_time,u.email,
                   CASE WHEN u.email=? THEN 1 ELSE 0 END AS is_mine
            FROM slot_bookings b JOIN users u ON b.user_id=u.id
            WHERE b.event_id=? AND b.booking_date BETWEEN ? AND ?
        """, (email, eid, ws, we)).fetchall()
        cnt = c.execute("""
            SELECT COUNT(*) as cnt FROM slot_bookings b JOIN users u ON b.user_id=u.id
            WHERE b.event_id=? AND u.email=?
        """, (eid, email)).fetchone()['cnt']
    return jsonify(bookings=rows_to_list(bks), my_total=cnt)

@app.post('/api/user/book')
@user_required
def book():
    d = request.json or {}
    eid,date,ss,se = d.get('eventId'),d.get('date'),d.get('slotStart'),d.get('slotEnd')
    email = session['user_email']
    with get_db() as c:
        ev = c.execute('SELECT max_slots_per_user,is_open FROM events WHERE id=?', (eid,)).fetchone()
        if not ev or not ev['is_open']: return err('活動不存在或已關閉')
        cnt = c.execute("""SELECT COUNT(*) as cnt FROM slot_bookings b JOIN users u ON b.user_id=u.id
            WHERE b.event_id=? AND u.email=?""", (eid, email)).fetchone()['cnt']
        if cnt >= ev['max_slots_per_user']: return err(f"已達上限（最多 {ev['max_slots_per_user']} 個時段）")
        if c.execute('SELECT id FROM slot_bookings WHERE event_id=? AND booking_date=? AND slot_start_time=?',
                     (eid,date,ss)).fetchone(): return err('該時段已被他人預約')
        uid = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()['id']
        try:
            c.execute('INSERT INTO slot_bookings(event_id,user_id,booking_date,slot_start_time,slot_end_time) VALUES(?,?,?,?,?)',
                      (eid,uid,date,ss,se))
        except sqlite3.IntegrityError: return err('該時段已被搶先預約')
    return ok()

@app.delete('/api/user/book')
@user_required
def cancel():
    d = request.json or {}
    eid,date,ss,email = d.get('eventId'),d.get('date'),d.get('slotStart'),session['user_email']
    with get_db() as c:
        u = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if u: c.execute('DELETE FROM slot_bookings WHERE event_id=? AND user_id=? AND booking_date=? AND slot_start_time=?',
                        (eid,u['id'],date,ss))
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
    eid=request.args.get('eventId',type=int); date=request.args.get('date','')
    email=session['user_email']
    if not eid or not date: return err('缺少參數')
    with get_db() as c:
        bks=c.execute("""
            SELECT b.slot_start_time,b.slot_end_time,u.email,
                   CASE WHEN u.email=? THEN 1 ELSE 0 END AS is_mine
            FROM slot_bookings b JOIN users u ON b.user_id=u.id
            WHERE b.event_id=? AND b.booking_date=?
        """,(email,eid,date)).fetchall()
        my_total=c.execute("""SELECT COUNT(*) as cnt FROM slot_bookings b JOIN users u ON b.user_id=u.id
            WHERE b.event_id=? AND u.email=?""",(eid,email)).fetchone()['cnt']
    return jsonify(bookings=rows_to_list(bks),my_total=my_total)


# ── All Availability (entire event range) ──────────────────────────────────────
@app.get('/api/user/all-availability')
@user_required
def all_availability():
    from datetime import date as _date, timedelta as _td
    from collections import defaultdict
    eid   = request.args.get('eventId', type=int)
    if not eid: return err('缺少參數')
    email = session['user_email']
    with get_db() as c:
        ev = c.execute('SELECT start_date,end_date FROM events WHERE id=?',(eid,)).fetchone()
        if not ev: return err('活動不存在')
        dow_cnt = _get_dow_cnt(c, eid)
        bk_rows = c.execute(
            "SELECT b.booking_date, CASE WHEN u.email=? THEN 1 ELSE 0 END AS is_mine "
            "FROM slot_bookings b JOIN users u ON b.user_id=u.id WHERE b.event_id=?",
            (email, eid)).fetchall()
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

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('FLASK_PORT', 5000))
    print(f"\n🚀  http://localhost:{port}  |  Dev={IS_DEV}\n")
    app.run(host='0.0.0.0', port=port, debug=IS_DEV)

