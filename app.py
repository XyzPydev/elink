import os
import sqlite3
import hashlib
import time
import datetime
import json
import shutil
from typing import Dict, List, Set, Optional
import secrets
import smtplib
from email.message import EmailMessage
from datetime import timedelta, datetime
import urllib.parse


import uvicorn
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketState

TEST_MODE = False
VERIFIED = ["sollamon.gg@gmail.com"]

# Optional: ngrok
try:
    from pyngrok import ngrok
except Exception:
    ngrok = None

# ---------------- CONFIG ----------------
NGROK_AUTHTOKEN = "2ybZlmGB05cL0RnQqknqqJdRDw3_31eakk3mYCv9n2JaHYGQF"
RESERVED_DOMAIN = "supreme-valid-sawfish.ngrok-free.app"
PORT = 8000

# додайте змінні середовища для SMTP та базового URL вашого сайту
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = int(587)
SMTP_USER = "elynk.project@gmail.com"
SMTP_PASS = "zdqf ewkk ozgv zhdn"
EMAIL_FROM = "Support <elynk.project@gmail.com>"
SITE_URL = os.environ.get("SITE_URL", f"http://127.0.0.1:{PORT}")
CODE_EXP_MINUTES = int(os.environ.get("CODE_EXP_MINUTES", 15))
RESEND_COOLDOWN_SECONDS = int(os.environ.get("RESEND_COOLDOWN_SECONDS", 60))

SITE_URL_WITH_END = f"http://127.0.0.1:{PORT}"

DATABASE = 'users.db'
SECRET_KEY = 'pass11221'  # змініть на свій секрет
ALLOWED_EXT = {'png','jpg','jpeg','gif','webp','bmp','pdf','txt','zip','mp3','wav','ogg','m4a'}
ALLOWED_AVATAR_EXT = {'png','jpg','jpeg','gif','webp'}

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------- DB helpers ----------------
def init_db():
    """
    Ініціалізація БД і міграції:
    - створює таблиці users/chats/messages, якщо їх немає
    - додає відсутні колонки: avatar_url, last_seen, is_verified,
      verification_code, verification_expiry, last_verification_sent
    - автоматично виставляє is_verified = 1 для існуючих записів,
      email яких присутні в константі VERIFIED
    """
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    cursor = conn.cursor()

    # Базова users table (якщо її ще немає)
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, password TEXT)''')
    conn.commit()

    # Дізнаємось існуючі колонки
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [r[1] for r in cursor.fetchall()]

    # Додаємо avatar_url
    if 'avatar_url' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT ''")
            conn.commit()
            print("DB migration: added avatar_url to users")
        except Exception as e:
            print("Could not add avatar_url:", e)

    # Додаємо last_seen
    if 'last_seen' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_seen DATETIME")
            conn.commit()
            print("DB migration: added last_seen to users")
        except Exception as e:
            print("Could not add last_seen:", e)

    # Додаємо is_verified
    if 'is_verified' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")
            conn.commit()
            print("DB migration: added is_verified to users")
        except Exception as e:
            print("Could not add is_verified:", e)

    # Додаємо verification_code
    if 'verification_code' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN verification_code TEXT")
            conn.commit()
            print("DB migration: added verification_code to users")
        except Exception as e:
            print("Could not add verification_code:", e)

    # Додаємо verification_expiry
    if 'verification_expiry' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN verification_expiry DATETIME")
            conn.commit()
            print("DB migration: added verification_expiry to users")
        except Exception as e:
            print("Could not add verification_expiry:", e)

    # Додаємо last_verification_sent
    if 'last_verification_sent' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_verification_sent DATETIME")
            conn.commit()
            print("DB migration: added last_verification_sent to users")
        except Exception as e:
            print("Could not add last_verification_sent:", e)

    # Створюємо chats та messages (якщо ще немає)
    cursor.execute('''CREATE TABLE IF NOT EXISTS chats
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, user1_id INTEGER, user2_id INTEGER,
                       UNIQUE(user1_id, user2_id))''')
    conn.commit()

    cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       chat_id INTEGER,
                       sender_id INTEGER,
                       message TEXT,
                       file_url TEXT,
                       file_type TEXT,
                       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()

    # Авто-верифікація існуючих користувачів, email яких містяться в VERIFIED
    try:
        verified_emails = [e.strip().lower() for e in VERIFIED if e and isinstance(e, str)]
        if verified_emails:
            for em in verified_emails:
                cursor.execute("UPDATE users SET is_verified = 1 WHERE lower(trim(email)) = ?", (em,))
            conn.commit()
            print("DB migration: set is_verified=1 for emails in VERIFIED list")
    except Exception as e:
        print("Could not auto-verify VERIFIED emails:", e)

    conn.close()

# --- NEW: helper to send email ---
def send_verification_email(to_email: str, code: str):
    subject = f"Your Elink code is {code}"
    link = f"{SITE_URL}/verify?email={urllib.parse.quote_plus(to_email)}"
    plain = f"""Hi,

Your code: {code}
Valid for {CODE_EXP_MINUTES} minutes.
{link}
"""
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #0f1720;">
        <div style="max-width:600px; margin:0 auto; padding:18px; background:#fff; border-radius:8px;">
          <div style="text-align:center; margin-bottom:12px;">
            <img src="cid:elink_logo" alt="Elink" style="width:120px; height:auto;" />
          </div>
          <h2 style="margin:0 0 8px 0">Привіт</h2>
          <p>Ваш код підтвердження:</p>
          <p style="font-size:26px; font-weight:700; letter-spacing:2px; margin:6px 0; color:#1f6feb;">{code}</p>
          <p>Дійсний <strong>{CODE_EXP_MINUTES} хвилин</strong>.</p>
          <p><a href="{link}">Підтвердити email</a></p>
          <hr/>
          <p style="font-size:12px; color:#666">Якщо ви не реєструвались — ігноруйте цей лист.</p>
        </div>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(plain)
    msg.add_alternative(html, subtype="html")

    # path до картинки в проєкті (перевірте, що файл існує)
    logo_path = os.path.join(os.getcwd(), "static", "icons", "logo.png")
    try:
        with open(logo_path, "rb") as f:
            img_data = f.read()
        # вставляємо як "related" до html-альтернативи (payload index 1)
        # Content-ID = <elink_logo> -> в HTML використовуємо cid:elink_logo
        msg.get_payload()[1].add_related(img_data, maintype="image", subtype="png", cid="elink_logo")
    except FileNotFoundError:
        # якщо файла немає — просто пропускаємо вставку картинки
        pass

    # відправка (як у вас)
    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
        return True
    except Exception as e:
        print("SMTP send error:", e)
        return False

def get_db_conn():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_id(db, user_id):
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

def get_user_by_email(db, email):
    cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    return dict(row) if row else None

def get_user_by_username(db, username):
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def _to_int_flag(val):
    """
    Нормалізує різні варіанти значень в 0/1.
    Підтримує: None, 0, 1, '0', '1', 'true', 'false', True, False.
    """
    try:
        if val is None:
            return 0
        if isinstance(val, bool):
            return 1 if val else 0
        # якщо це bytes
        if isinstance(val, (bytes, bytearray)):
            val = val.decode('utf-8', errors='ignore')
        s = str(val).strip().lower()
        if s in ('1', 'true', 'yes', 'on'):
            return 1
        return 0
    except Exception:
        return 0

def _row_to_dict_with_defaults(row, defaults=None):
    """
    Перетворює sqlite3.Row в звичайний dict і додає дефолтні ключі (якщо відсутні).
    """
    d = {}
    try:
        # sqlite3.Row підтримує ітерацію по ключам
        for k in row.keys():
            d[k] = row[k]
    except Exception:
        # якщо row вже dict або інше
        try:
            d = dict(row)
        except Exception:
            d = {}

    if defaults:
        for k, v in defaults.items():
            if k not in d:
                d[k] = v
    return d

def ensure_chat_between(db, a_id: int, b_id: int):
    if a_id == b_id:
        return None
    user1, user2 = (a_id, b_id) if a_id < b_id else (b_id, a_id)
    cur = db.execute("SELECT id FROM chats WHERE user1_id = ? AND user2_id = ?", (user1, user2))
    row = cur.fetchone()
    if row:
        return row['id']
    cur = db.execute("INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)", (user1, user2))
    db.commit()
    return cur.lastrowid

def get_messages(db, chat_id: int):
    cur = db.execute("""
        SELECT m.id, m.chat_id, m.sender_id, m.message, m.file_url, m.file_type, m.timestamp,
               u.username, u.is_verified
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.chat_id = ?
        ORDER BY m.id
    """, (chat_id,))
    return cur.fetchall()

def list_user_chats(db, user_id: int):
    cur = db.execute("""
        SELECT
          c.id AS chat_id,
          c.user1_id,
          c.user2_id,
          (SELECT message FROM messages m2 WHERE m2.chat_id = c.id ORDER BY m2.id DESC LIMIT 1) AS last_message,
          (SELECT timestamp FROM messages m2 WHERE m2.chat_id = c.id ORDER BY m2.id DESC LIMIT 1) AS last_ts
        FROM chats c
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY last_ts DESC
    """, (user_id, user_id))
    chats = []
    for row in cur.fetchall():
        other_id = row['user1_id'] if row['user1_id'] != user_id else row['user2_id']
        other = get_user_by_id(db, other_id)
        # 안전ная нормалізація полей (avatar, is_verified)
        other_avatar = ''
        other_is_verified = 0
        if other:
            try:
                other_avatar = other['avatar_url'] if other['avatar_url'] else ''
            except Exception:
                other_avatar = ''
            try:
                other_is_verified = _to_int_flag(other['is_verified'])
            except Exception:
                other_is_verified = 0

        chats.append({
            'chat_id': row['chat_id'],
            'other_id': other_id,
            'other_username': other['username'] if other else "Unknown",
            'other_email': other['email'] if other else "",
            'other_avatar': other_avatar,
            'other_is_verified': other_is_verified,
            'last_message': row['last_message'] or '',
            'last_ts': row['last_ts']
        })
    return chats

def detect_file_type(filename: str):
    ext = filename.rsplit('.',1)[-1].lower()
    if ext in {'png','jpg','jpeg','gif','webp','bmp'}:
        return 'image'
    if ext in {'mp3','wav','ogg','m4a'}:
        return 'audio'
    return 'file'

# ---------------- WebSocket manager ----------------
class ConnectionManager:
    def __init__(self):
        # chat_id -> set of websockets
        self.active: Dict[int, Set[WebSocket]] = {}
        # websocket -> user_id
        self.ws_user: Dict[WebSocket, int] = {}

    async def connect(self, chat_id: int, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active.setdefault(chat_id, set()).add(websocket)
        self.ws_user[websocket] = user_id

    def disconnect(self, chat_id: int, websocket: WebSocket):
        if chat_id in self.active:
            self.active[chat_id].discard(websocket)
            if not self.active[chat_id]:
                del self.active[chat_id]
        self.ws_user.pop(websocket, None)

    async def broadcast(self, chat_id: int, message: dict):
        conns = list(self.active.get(chat_id, []))
        for ws in conns:
            try:
                if ws.application_state == WebSocketState.CONNECTED:
                    await ws.send_json(message)
            except Exception:
                # ignore broken sockets; disconnect later
                pass

manager = ConnectionManager()

# typing status: key (chat_id, user_id) -> timestamp
typing_status: Dict[tuple, float] = {}

# ---------------- Utility ----------------
def save_message(db, chat_id: int, sender_id: int, text: Optional[str], file_url: Optional[str], file_type: Optional[str]):
    cur = db.execute("INSERT INTO messages (chat_id, sender_id, message, file_url, file_type) VALUES (?, ?, ?, ?, ?)",
                     (chat_id, sender_id, text, file_url, file_type))
    db.commit()
    last_id = cur.lastrowid
    # повертаємо повідомлення разом з юзерським is_verified
    return db.execute("""
        SELECT m.id, m.chat_id, m.sender_id, m.message, m.file_url, m.file_type, m.timestamp,
               u.username, u.is_verified
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.id = ?
    """, (last_id,)).fetchone()


# ---------------- Routes ----------------
@app.get("/", response_class=HTMLResponse, name="/")
def index(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse(url="/login")
    db = get_db_conn()
    me = get_user_by_id(db, user_id)
    if not me:
        request.session.pop('user_id', None)
        db.close()
        return RedirectResponse(url="/login")
    chats = list_user_chats(db, me['id'])
    cur = db.execute("SELECT id, username, email, avatar_url, is_verified FROM users WHERE id != ? ORDER BY username COLLATE NOCASE", (me['id'],))
    users = cur.fetchall()
    db.close()
    return templates.TemplateResponse("index.html", {"request": request, "me": me, "chats": chats, "users": users})


@app.get("/register", response_class=HTMLResponse, name="register")
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# --- NEW: verify page GET + POST handlers ---
@app.get("/verify", response_class=HTMLResponse)
def verify_get(request: Request, email: Optional[str] = None, sent: Optional[int] = None):
    # Render a simple template to input code; template will display email and whether mail was sent.
    return templates.TemplateResponse("verify.html", {"request": request, "email": email or "", "sent": sent})

@app.post("/verify")
def verify_post(request: Request, email: str = Form(...), code: str = Form(...)):
    email = email.strip().lower()
    db = get_db_conn()
    user_row = get_user_by_email(db, email)
    if not user_row:
        db.close()
        return HTMLResponse("Користувача не знайдено", status_code=404)

    # convert sqlite3.Row to dict so we can use .get safely
    user = dict(user_row)

    if user.get("is_verified"):
        db.close()
        return RedirectResponse(url="/login?verified=1", status_code=303)

    stored_hash = user.get("verification_code")
    expiry = user.get("verification_expiry")
    now = datetime.utcnow()

    # check expiry if present
    if expiry:
        try:
            exp_dt = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
            if now > exp_dt:
                db.close()
                return HTMLResponse("Код прострочено. Замовте повторну відправку.", status_code=400)
        except Exception:
            # якщо формат інший — продовжуємо, але можна логувати
            pass

    code_hash = hashlib.sha256(code.strip().encode()).hexdigest()
    if stored_hash and code_hash == stored_hash:
        db.execute("UPDATE users SET is_verified = 1, verification_code = NULL, verification_expiry = NULL WHERE id = ?", (user["id"],))
        db.commit()
        db.close()
        return RedirectResponse(url="/login?verified=1", status_code=303)
    else:
        db.close()
        return HTMLResponse("Невірний код. Спробуйте ще раз.", status_code=400)

# --- NEW: resend verification endpoint ---
@app.post("/resend_verification")
def resend_verification(request: Request, email: str = Form(...)):
    email = email.strip().lower()
    db = get_db_conn()
    user_row = get_user_by_email(db, email)
    if not user_row:
        db.close()
        return JSONResponse({"error":"not_found"}, status_code=404)

    user = dict(user_row)

    # rate-limit based on last_verification_sent
    last = user.get("last_verification_sent")
    if last:
        try:
            last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
            if (datetime.utcnow() - last_dt).total_seconds() < RESEND_COOLDOWN_SECONDS:
                db.close()
                return JSONResponse({"error":"too_many_requests"}, status_code=429)
        except Exception:
            pass

    # generate new code
    code = f"{secrets.randbelow(900000) + 100000}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expiry = (datetime.utcnow() + timedelta(minutes=CODE_EXP_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    try:
        db.execute(
            "UPDATE users SET verification_code = ?, verification_expiry = ?, last_verification_sent = ? WHERE id = ?",
            (code_hash, expiry, now_ts, user["id"])
        )
        db.commit()
    except Exception as e:
        print("DB update error on resend:", e)
        db.close()
        return JSONResponse({"error":"db_error"}, status_code=500)

    db.close()

    sent = send_verification_email(email, code)
    if not sent:
        return JSONResponse({"error":"smtp_failed"}, status_code=500)
    return JSONResponse({"ok": True})

@app.post("/register")
def register_post(request: Request, email: str = Form(...), username: str = Form(...), password: str = Form(...)):
    """
    Реєстрація:
    - автоматично виставляє is_verified=1 якщо email в VERIFIED
    - якщо користувач в VERIFIED, не надсилаємо verification email
    - для інших генеруємо код і надсилаємо лист
    """
    email = email.strip().lower()
    username = username.strip()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db = get_db_conn()

    # Перевірка чи email в списку VERIFIED (case-insensitive)
    try:
        verified_set = {v.strip().lower() for v in VERIFIED if v and isinstance(v, str)}
        is_verified_flag = 1 if email in verified_set else 0
    except Exception:
        is_verified_flag = 0

    try:
        cur = db.execute(
            "INSERT INTO users (email, username, password, is_verified) VALUES (?, ?, ?, ?)",
            (email, username, hashed, is_verified_flag)
        )
        db.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        db.close()
        return HTMLResponse(content="Користувач з таким email або username вже існує", status_code=400)
    except Exception as e:
        db.close()
        print("DB insert error in register:", e)
        return HTMLResponse(content="Помилка при створенні користувача", status_code=500)

    # Якщо користувач автоматично верифікований — не генеруємо/не надсилаємо код
    if is_verified_flag:
        try:
            db.execute("UPDATE users SET verification_code = NULL, verification_expiry = NULL, last_verification_sent = NULL WHERE id = ?", (user_id,))
            db.commit()
        except Exception as e:
            print("Could not clear verification fields for auto-verified user:", e)
        db.close()
        return RedirectResponse(url="/login", status_code=303)

    # Для звичайних користувачів генеруємо код і надсилаємо листа
    code = f"{secrets.randbelow(900000) + 100000}"  # 100000-999999
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expiry = (datetime.utcnow() + timedelta(minutes=CODE_EXP_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    now_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    try:
        db.execute("UPDATE users SET verification_code = ?, verification_expiry = ?, last_verification_sent = ? WHERE id = ?",
                   (code_hash, expiry, now_ts, user_id))
        db.commit()
    except Exception as e:
        print("DB update verification fields error:", e)
    db.close()

    sent = send_verification_email(email, code)
    if not sent:
        return RedirectResponse(url=f"/verify?email={urllib.parse.quote_plus(email)}&sent=0", status_code=303)

    return RedirectResponse(url=f"/verify?email={urllib.parse.quote_plus(email)}&sent=1", status_code=303)

@app.get("/api/verified_users")
def api_verified_users():
    """
    Повертає список користувачів, у яких is_verified = 1
    (використовувати для фронту або діагностики)
    """
    db = get_db_conn()
    try:
        rows = db.execute("SELECT id, username, email, avatar_url FROM users WHERE is_verified = 1 ORDER BY username COLLATE NOCASE").fetchall()
        users = [{"id": r["id"], "username": r["username"], "email": r["email"], "avatar_url": r["avatar_url"]} for r in rows]
    finally:
        db.close()
    return JSONResponse(users)


@app.post("/admin/mark_verified")
def admin_mark_verified():
    """
    Оновлює поле is_verified в users відповідно до списку VERIFIED (case-insensitive).
    Повертає підсумок оновлення.
    !!! Рекомендується захистити цей ендпоінт (токен/авторизація) на проді.
    """
    db = get_db_conn()
    updated = 0
    errors = []
    try:
        verified_emails = [e.strip().lower() for e in VERIFIED if e and isinstance(e, str)]
        for em in verified_emails:
            try:
                cur = db.execute("UPDATE users SET is_verified = 1 WHERE lower(trim(email)) = ?", (em,))
                updated += cur.rowcount if cur is not None else 0
            except Exception as e:
                errors.append(f"{em}: {e}")
        db.commit()
    except Exception as e:
        errors.append(str(e))
    finally:
        db.close()

    return JSONResponse({"ok": True, "updated_rows_estimate": updated, "errors": errors})


@app.get("/login", response_class=HTMLResponse, name="login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    """
    Авторизація: не дозволяє зайти, якщо акаунт не підтверджено через email.
    Якщо пароль вірний, але is_verified False/NULL/0 — редірект на /verify.
    """
    email = email.strip().lower()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db = get_db_conn()
    user = get_user_by_email(db, email)
    if user and user['password'] == hashed:
        # безпечна перевірка поля is_verified (може бути 0/1 або NULL)
        try:
            is_verified = bool(user['is_verified'])
        except Exception:
            # якщо колонки немає або значення незвичне — вважати не підтвердженим
            is_verified = False

        if is_verified:
            request.session['user_id'] = user['id']
            db.close()
            return RedirectResponse(url="/", status_code=303)
        else:
            # Не дозволяємо логін — редіректим на сторінку підтвердження
            db.close()
            # опціонально: можна додати ?sent=1 якщо лист щойно висилався
            return RedirectResponse(url=f"/verify?email={urllib.parse.quote_plus(email)}&sent=0", status_code=303)

    db.close()
    return HTMLResponse(content="Невірний email або пароль", status_code=400)

@app.get("/logout", name="logout")
def logout(request: Request):
    request.session.pop('user_id', None)
    return RedirectResponse(url="/login")

@app.post("/start_chat_by_username")
def start_chat_by_username(request: Request, username: str = Form(...)):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse(url="/login")
    username = username.strip()
    db = get_db_conn()
    other = get_user_by_username(db, username)
    if not other:
        db.close()
        return HTMLResponse(content=f"Користувача з username '{username}' не знайдено", status_code=404)
    if other['id'] == user_id:
        db.close()
        return HTMLResponse(content="Ви не можете почати чат з самим собою", status_code=400)
    chat_id = ensure_chat_between(db, user_id, other['id'])
    db.close()
    if not chat_id:
        return HTMLResponse(content="Не вдалося створити чат — спробуйте ще раз", status_code=500)
    return RedirectResponse(url=f"/chat/{chat_id}")

@app.get("/start_chat/{receiver_id}", name="start_chat")
def start_chat(request: Request, receiver_id: int):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse(url="/login")
    if receiver_id == user_id:
        return HTMLResponse(content="Ви не можете почати чат з самим собою", status_code=400)
    db = get_db_conn()
    other = get_user_by_id(db, receiver_id)
    if not other:
        db.close()
        return HTMLResponse(content="Користувача не знайдено", status_code=404)
    chat_id = ensure_chat_between(db, user_id, other['id'])
    db.close()
    if not chat_id:
        return HTMLResponse(content="Не вдалося створити чат", status_code=500)
    return RedirectResponse(url=f"/chat/{chat_id}")

@app.get("/chat/{chat_id}", response_class=HTMLResponse, name="chat")
def chat_page(request: Request, chat_id: int):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse(url="/login")
    db = get_db_conn()
    me_row = get_user_by_id(db, user_id)
    if not me_row:
        request.session.pop('user_id', None)
        db.close()
        return RedirectResponse(url="/login")

    # перетворимо me в dict і нормалізуємо поля
    me = _row_to_dict_with_defaults(me_row, defaults={"avatar_url": "", "is_verified": 0})
    me['is_verified'] = _to_int_flag(me.get('is_verified', 0))

    cur = db.execute("SELECT user1_id, user2_id FROM chats WHERE id = ?", (chat_id,))
    chat_row = cur.fetchone()
    if not chat_row:
        db.close()
        return HTMLResponse(content="Чат не знайдено", status_code=404)

    other_id = chat_row['user1_id'] if chat_row['user1_id'] != me['id'] else chat_row['user2_id']
    other_row = get_user_by_id(db, other_id)
    other = _row_to_dict_with_defaults(other_row or {}, defaults={"avatar_url": "", "is_verified": 0, "username": "Unknown", "email": ""})
    other['is_verified'] = _to_int_flag(other.get('is_verified', 0))

    # messages: беремо з get_messages (яка вже робить JOIN на users), і нормалізуємо
    raw_messages = get_messages(db, chat_id)
    messages = []
    for r in raw_messages:
        m = _row_to_dict_with_defaults(r, defaults={"file_url": "", "file_type": "", "message": ""})
        # is_verified в результаті SELECT може бути в полі 'is_verified' з join
        m['is_verified'] = _to_int_flag(m.get('is_verified', 0))
        messages.append(m)

    # chats: використаємо list_user_chats (яка має повертати dict з other_is_verified),
    # але на всякий випадок нормалізуємо кожен елемент
    chats_raw = list_user_chats(db, me['id'])
    chats = []
    for c in chats_raw:
        cc = dict(c)
        cc['other_avatar'] = cc.get('other_avatar') or ''
        cc['other_is_verified'] = _to_int_flag(cc.get('other_is_verified', 0))
        chats.append(cc)

    # users (sidebar): вибираємо і нормалізуємо в список dict
    rows = db.execute("SELECT id, username, email, avatar_url, is_verified FROM users WHERE id != ? ORDER BY username COLLATE NOCASE", (me['id'],)).fetchall()
    users = []
    for r in rows:
        u = _row_to_dict_with_defaults(r, defaults={"avatar_url": "", "is_verified": 0})
        u['is_verified'] = _to_int_flag(u.get('is_verified', 0))
        users.append(u)

    db.close()
    return templates.TemplateResponse("chat.html", {
        "request": request, "me": me, "other": other, "messages": messages,
        "chat_id": chat_id, "chats": chats, "users": users
    })

@app.post("/send_message_ajax")
async def send_message_ajax(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return JSONResponse({"error": "not_logged_in"}, status_code=401)
    data = await request.json()
    chat_id = data.get('chat_id')
    text = (data.get('message') or '').strip()
    if not chat_id or not text:
        return JSONResponse({"error": "bad_request"}, status_code=400)
    db = get_db_conn()
    row = save_message(db, chat_id, user_id, text, None, None)
    db.close()
    if not row:
        return JSONResponse({"error": "not_found"}, status_code=500)
    payload = {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "sender_id": row["sender_id"],
        "message": row["message"],
        "file_url": row["file_url"],
        "file_type": row["file_type"],
        "timestamp": row["timestamp"],
        "username": row["username"],
        "is_verified": _to_int_flag(row["is_verified"])
    }
    # push via websocket
    await manager.broadcast(chat_id, {"type": "message", "data": payload})
    return JSONResponse(payload)


@app.post("/send_message/{chat_id}")
def send_message_route(request: Request, chat_id: int, message: str = Form(...)):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse(url="/login")
    text = message.strip()
    if text:
        db = get_db_conn()
        db.execute("INSERT INTO messages (chat_id, sender_id, message) VALUES (?, ?, ?)", (chat_id, user_id, text))
        db.commit()
        db.close()
        # broadcast omitted in sync route; client should fetch or use WS
    return RedirectResponse(url=f"/chat/{chat_id}")

@app.get("/chat_messages/{chat_id}", name="chat_messages")
def chat_messages(request: Request, chat_id: int, last_id: int = 0):
    user_id = request.session.get('user_id')
    if not user_id:
        return JSONResponse([], status_code=401)
    db = get_db_conn()
    cur = db.execute("""
        SELECT m.id, m.chat_id, m.sender_id, m.message, m.file_url, m.file_type, m.timestamp, u.username
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.chat_id = ? AND m.id > ?
        ORDER BY m.id ASC
    """, (chat_id, last_id))
    rows = cur.fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "chat_id": r["chat_id"],
            "sender_id": r["sender_id"],
            "message": r["message"],
            "file_url": r["file_url"],
            "file_type": r["file_type"],
            "timestamp": r["timestamp"],
            "username": r["username"]
        })
    db.close()
    return JSONResponse(items)

@app.get("/search_users", name="search_users")
def search_users(request: Request, q: str = ""):
    user_id = request.session.get('user_id')
    if not user_id:
        return ""
    db = get_db_conn()
    me_id = user_id
    if not q:
        cur = db.execute("SELECT id, username, email FROM users WHERE id != ? ORDER BY username COLLATE NOCASE", (me_id,))
    else:
        cur = db.execute("SELECT id, username, email FROM users WHERE id != ? AND username LIKE ? ORDER BY username COLLATE NOCASE", (me_id, f"%{q}%"))
    rows = cur.fetchall()
    items = [{"id": r["id"], "username": r["username"], "email": r["email"]} for r in rows]
    db.close()
    return JSONResponse(items)

# file uploads
@app.post("/upload_file_ajax")
async def upload_file_ajax(request: Request, file: UploadFile = File(...), chat_id: int = Form(...)):
    user_id = request.session.get('user_id')
    if not user_id:
        return JSONResponse({"error":"not_logged_in"}, status_code=401)
    try:
        chat_id = int(chat_id)
    except:
        return JSONResponse({"error":"bad_chat"}, status_code=400)
    if not file.filename:
        return JSONResponse({"error":"no_file"}, status_code=400)
    ext = file.filename.rsplit('.',1)[-1].lower()
    if ext not in ALLOWED_EXT:
        return JSONResponse({"error":"forbidden_ext"}, status_code=400)
    uploads_dir = os.path.join(os.getcwd(), 'static', 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    safe_name = f"{int(time.time())}_{os.path.basename(file.filename)}"
    fpath = os.path.join(uploads_dir, safe_name)
    # write file
    with open(fpath, "wb") as out_file:
        content = await file.read()
        out_file.write(content)
    file_url = f"/static/uploads/{safe_name}"
    file_type = detect_file_type(safe_name)
    db = get_db_conn()
    row = save_message(db, chat_id, user_id, f"[file] {safe_name}", file_url, file_type)
    db.close()
    if not row:
        return JSONResponse({"error":"not_found"}, status_code=500)
    payload = {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "sender_id": row["sender_id"],
        "message": row["message"],
        "file_url": row["file_url"],
        "file_type": row["file_type"],
        "timestamp": row["timestamp"],
        "username": row["username"],
        "is_verified": _to_int_flag(row["is_verified"])
    }
    await manager.broadcast(chat_id, {"type": "message", "data": payload})
    return JSONResponse(payload)


@app.get("/settings", response_class=HTMLResponse, name="settings")
def settings(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse("/login")
    db = get_db_conn()
    me = get_user_by_id(db, user_id)
    db.close()
    return templates.TemplateResponse("settings.html", {"request": request, "me": me})

@app.post("/update_profile", name="update_profile")
async def update_profile(request: Request, username: str = Form(None), avatar: Optional[UploadFile] = File(None)):
    user_id = request.session.get('user_id')
    if not user_id:
        return RedirectResponse("/login")
    db = get_db_conn()
    me_id = user_id
    if username:
        username = username.strip()
        cur = db.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, me_id))
        if cur.fetchone():
            db.close()
            return HTMLResponse("Username already taken", status_code=400)
        db.execute("UPDATE users SET username = ? WHERE id = ?", (username, me_id))
        db.commit()
    if avatar and avatar.filename:
        ext = avatar.filename.rsplit('.',1)[-1].lower()
        if ext not in ALLOWED_AVATAR_EXT:
            db.close()
            return HTMLResponse("Invalid avatar file type", status_code=400)
        avatars_dir = os.path.join(os.getcwd(), 'static', 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)
        filename = f"{int(time.time())}_{os.path.basename(avatar.filename)}"
        path = os.path.join(avatars_dir, filename)
        with open(path, "wb") as out_file:
            content = await avatar.read()
            out_file.write(content)
        avatar_url = f"/static/avatars/{filename}"
        db.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, me_id))
        db.commit()
    db.close()
    return RedirectResponse(request.url_for("settings"), status_code=302)

@app.post("/heartbeat")
def heartbeat(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return JSONResponse({"error":"not_logged_in"}, status_code=401)
    db = get_db_conn()
    db.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return JSONResponse({"ok": True})

@app.post("/set_typing")
async def set_typing(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        return JSONResponse({"error":"not_logged_in"}, status_code=401)
    data = await request.json()
    chat_id = int(data.get('chat_id', 0))
    typing = bool(data.get('typing', False))
    key = (chat_id, user_id)
    if typing:
        typing_status[key] = time.time()
    else:
        typing_status.pop(key, None)
    # broadcast typing state to others in chat via websocket
    await manager.broadcast(chat_id, {"type": "typing", "data": {"user_id": user_id, "typing": typing}})
    return JSONResponse({"ok": True})

@app.get("/user_status/{user_id}", name="user_status")
def user_status(request: Request, user_id: int, chat_id: Optional[int] = None):
    db = get_db_conn()
    row = db.execute("SELECT last_seen FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    last_seen = row['last_seen'] if row else None
    online = False
    if last_seen:
        try:
            last = datetime.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            online = (datetime.datetime.utcnow() - last).total_seconds() < 30
        except Exception:
            online = False
    typing = False
    if chat_id:
        key = (chat_id, user_id)
        ts = typing_status.get(key)
        if ts and (time.time() - ts) < 3:
            typing = True
    return JSONResponse({"online": online, "typing": typing, "last_seen": last_seen})

# ---------------- WebSocket endpoint ----------------
@app.websocket("/ws/chat/{chat_id}")
async def websocket_chat(websocket: WebSocket, chat_id: int):
    """
    WebSocket expects session cookie to be present so that SessionMiddleware provides websocket.session
    On client: new WebSocket("ws://.../ws/chat/123", {credentials: "include"}) to send cookies.
    """
    # Access session from websocket
    session = websocket.session if hasattr(websocket, "session") else {}
    user_id = session.get('user_id')
    if not user_id:
        await websocket.close(code=1008)
        return
    # connect
    await manager.connect(chat_id, websocket, user_id)
    try:
        while True:
            data = await websocket.receive_json()
            # expected payload like {"type":"message","message":"hi"} or {"type":"typing","typing":true}
            typ = data.get("type")
            if typ == "message":
                text = (data.get("message") or "").strip()
                if not text:
                    continue
                db = get_db_conn()
                row = save_message(db, chat_id, user_id, text, None, None)
                db.close()
                if not row:
                    # optionally notify sender about failure
                    continue
                payload = {
                    "id": row["id"],
                    "chat_id": row["chat_id"],
                    "sender_id": row["sender_id"],
                    "message": row["message"],
                    "file_url": row["file_url"],
                    "file_type": row["file_type"],
                    "timestamp": row["timestamp"],
                    "username": row["username"],
                    "is_verified": _to_int_flag(row["is_verified"])
                }
                await manager.broadcast(chat_id, {"type":"message", "data": payload})
            elif typ == "typing":
                typing = bool(data.get("typing", False))
                key = (chat_id, user_id)
                if typing:
                    typing_status[key] = time.time()
                else:
                    typing_status.pop(key, None)
                await manager.broadcast(chat_id, {"type":"typing", "data": {"user_id": user_id, "typing": typing}})
            else:
                # unknown type; ignore or handle custom events
                pass
    except WebSocketDisconnect:
        manager.disconnect(chat_id, websocket)
    except Exception:
        manager.disconnect(chat_id, websocket)

# ---------------- NGROK runner ----------------
def run_ngrok(port=PORT):
    if ngrok is None:
        print("pyngrok not installed")
        return
    ngrok.set_auth_token(NGROK_AUTHTOKEN)
    try:
        tunnel = ngrok.connect(port, proto="http", hostname=RESERVED_DOMAIN)
        print("NGROK:", tunnel.public_url)
    except Exception as e:
        print("ngrok error:", e)

# ---------------- Main ----------------
if __name__ == "__main__":
    init_db()
    # optional ngrok
    try:
        if not TEST_MODE:
            run_ngrok()
    except Exception as e:
        print("ngrok не запустився:", e)
    uvicorn.run("app:app", host="127.0.0.1", port=PORT, reload=True)
