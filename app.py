import os
import sqlite3
import hashlib
import time
import datetime
import json
import shutil
from typing import Dict, List, Set, Optional

import uvicorn
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.websockets import WebSocketState

# Optional: ngrok
try:
    from pyngrok import ngrok
except Exception:
    ngrok = None

# ---------------- CONFIG ----------------
NGROK_AUTHTOKEN = "2ybZlmGB05cL0RnQqknqqJdRDw3_31eakk3mYCv9n2JaHYGQF"
RESERVED_DOMAIN = "supreme-valid-sawfish.ngrok-free.app"
PORT = 8000

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
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY, email TEXT UNIQUE, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    # migrations: add avatar_url, last_seen
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [r[1] for r in cursor.fetchall()]
    if 'avatar_url' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
            conn.commit()
            print("DB migration: added avatar_url to users")
        except Exception as e:
            print("Could not add avatar_url:", e)
    if 'last_seen' not in user_cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_seen DATETIME")
            conn.commit()
        except Exception as e:
            print("Could not add last_seen:", e)

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
    conn.close()

def get_db_conn():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_id(db, user_id):
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

def get_user_by_email(db, email):
    cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_username(db, username):
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

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
        SELECT m.id, m.chat_id, m.sender_id, m.message, m.file_url, m.file_type, m.timestamp, u.username
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
        chats.append({
            'chat_id': row['chat_id'],
            'other_id': other_id,
            'other_username': other['username'] if other else "Unknown",
            'other_email': other['email'] if other else "",
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
    return db.execute("""
        SELECT m.id, m.chat_id, m.sender_id, m.message, m.file_url, m.file_type, m.timestamp, u.username
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
    cur = db.execute("SELECT id, username, email FROM users WHERE id != ? ORDER BY username COLLATE NOCASE", (me['id'],))
    users = cur.fetchall()
    db.close()
    return templates.TemplateResponse("index.html", {"request": request, "me": me, "chats": chats, "users": users})

@app.get("/register", response_class=HTMLResponse, name="register")
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(request: Request, email: str = Form(...), username: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    username = username.strip()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db = get_db_conn()
    try:
        db.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed))
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return HTMLResponse(content="Користувач з таким email або username вже існує", status_code=400)
    db.close()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse, name="login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db = get_db_conn()
    user = get_user_by_email(db, email)
    if user and user['password'] == hashed:
        request.session['user_id'] = user['id']
        db.close()
        return RedirectResponse(url="/", status_code=303)
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
    me = get_user_by_id(db, user_id)
    cur = db.execute("SELECT user1_id, user2_id FROM chats WHERE id = ?", (chat_id,))
    chat_row = cur.fetchone()
    if not chat_row:
        db.close()
        return HTMLResponse(content="Чат не знайдено", status_code=404)
    other_id = chat_row['user1_id'] if chat_row['user1_id'] != me['id'] else chat_row['user2_id']
    other = get_user_by_id(db, other_id)
    messages = get_messages(db, chat_id)
    chats = list_user_chats(db, me['id'])
    users = db.execute("SELECT id, username, email FROM users WHERE id != ? ORDER BY username COLLATE NOCASE", (me['id'],)).fetchall()
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
        "username": row["username"]
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
    payload = {
        "id": row["id"],
        "chat_id": row["chat_id"],
        "sender_id": row["sender_id"],
        "message": row["message"],
        "file_url": row["file_url"],
        "file_type": row["file_type"],
        "timestamp": row["timestamp"],
        "username": row["username"]
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

@app.post("/update_profile")
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
    return RedirectResponse("/settings")

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
                payload = {
                    "id": row["id"],
                    "chat_id": row["chat_id"],
                    "sender_id": row["sender_id"],
                    "message": row["message"],
                    "file_url": row["file_url"],
                    "file_type": row["file_type"],
                    "timestamp": row["timestamp"],
                    "username": row["username"]
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
        run_ngrok()
    except Exception as e:
        print("ngrok не запустився:", e)
    uvicorn.run("app:app", host="127.0.0.1", port=PORT, reload=True)