import os
import re
import sqlite3
import random
import smtplib
import uuid
import json
import base64
import datetime
import time
import urllib.request
import urllib.error

from flask import Flask, render_template_string, request, redirect, session, url_for, send_from_directory, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
        base64url_to_bytes,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        AuthenticatorAttachment,
        ResidentKeyRequirement,
        UserVerificationRequirement,
        PublicKeyCredentialDescriptor,
    )
    WEBAUTHN_AVAILABLE = True
except Exception:
    WEBAUTHN_AVAILABLE = False


app = Flask(__name__)
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=30)
app.secret_key = os.environ.get("SECRET_KEY", "adam_secret_key_2026")






def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}



def b64url_encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode_to_bytes(value: str) -> bytes:
    value = (value or "").encode("utf-8")
    padding = b"=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def get_rp_id():
    return (request.host or "").split(":")[0]


def get_origin():
    return request.host_url.rstrip("/")


def passkeys_supported():
    return WEBAUTHN_AVAILABLE

SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
SENDER_APP_PASSWORD = os.environ.get("SENDER_APP_PASSWORD", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", SENDER_EMAIL or "")
MAIL_PROVIDER = os.environ.get("MAIL_PROVIDER", "resend").strip().lower()
MAIL_REQUIRED_FOR_REGISTER = False
DEV_CONSOLE_OTP_FALLBACK = False
MAIL_ENABLED = env_flag("MAIL_ENABLED", True)
OTP_EXPIRY_SECONDS = 10 * 60

CONTACT_PHONE = "+9647864145165"
CONTACT_EMAIL = "hishamalhansh@gmail.com"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = None  # unlimited upload size
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 30

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = None
MAX_SINGLE_FILE_SIZE = 3 * 1024 * 1024
MAX_WORK_IMAGES = 10

IRAQ_GOVERNORATES = [
    "بغداد", "البصرة", "نينوى", "أربيل", "النجف", "كربلاء", "الأنبار",
    "بابل", "ذي قار", "ديالى", "دهوك", "السليمانية", "صلاح الدين",
    "كركوك", "واسط", "ميسان", "المثنى", "القادسية", "حلبجة", "الناصرية"
]

SPECIALTY_GROUPS = {
    "مهندسون": [
        "مهندس كهربائيات",
        "مهندس معماري",
        "مهندس انشاء",
        "مهندس ديكور وتصميم"
    ],
    "خلفه بناء": [
        "خلفه اشتايكر",
        "خلفه طابوك",
        "خلفه سيراميك والرضيه",
        "خلفه جص (ابياض)",
        "خلفه قالب نجار"
    ],
    "عمال بناء": [
        "عمال بناء"
    ],
    "مواد بناء": [
        "مواد بناء"
    ],
    "فنيين": [
        "فني كهرباء",
        "فني تبريد",
        "فني صحيات"
    ]
}

SPECIALTY_ICONS = {
    "مهندس كهربائيات": "⚡",
    "مهندس معماري": "🏛️",
    "مهندس انشاء": "🏗️",
    "مهندس ديكور وتصميم": "🎨",
    "خلفه اشتايكر": "🧱",
    "خلفه طابوك": "🧱",
    "خلفه سيراميك والرضيه": "🟫",
    "خلفه جص (ابياض)": "🪣",
    "خلفه قالب نجار": "🪚",
    "عمال بناء": "👷",
    "مواد بناء": "🏬",
    "فني كهرباء": "💡",
    "فني تبريد": "❄️",
    "فني صحيات": "🚿"
}

SPECIALTIES = [item for group in SPECIALTY_GROUPS.values() for item in group]

LOGIN_ATTEMPTS = {}
MESSAGE_RATE_LIMIT = {}
COMMENT_RATE_LIMIT = {}

LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5

MESSAGE_WINDOW_SECONDS = 20
MESSAGE_MAX_COUNT = 5

COMMENT_WINDOW_SECONDS = 120
COMMENT_MAX_COUNT = 3



def auto_login_from_cookie():
    if "user" not in session:
        email_cookie = request.cookies.get("remember_email")
        if email_cookie:
            with get_db() as con:
                u = con.execute("SELECT * FROM users WHERE email=?", (email_cookie,)).fetchone()
            if u:
                session["user"] = u["name"]
                session["user_id"] = u["id"]
                session["role"] = u["role"] or "worker"



def get_current_session_user():
    user_id = session.get("user_id")
    user_name = session.get("user")
    with get_db() as con:
        if user_id:
            user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if user:
                return user
        if user_name:
            user = con.execute("SELECT * FROM users WHERE name=?", (user_name,)).fetchone()
            if user:
                session["user_id"] = user["id"]
                return user
    return None

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def clean_old_attempts(storage, window_seconds):
    now = time.time()
    expired_keys = []
    for key, timestamps in list(storage.items()):
        filtered = [t for t in timestamps if now - t <= window_seconds]
        if filtered:
            storage[key] = filtered
        else:
            expired_keys.append(key)
    for key in expired_keys:
        storage.pop(key, None)


def too_many_attempts(storage, key, window_seconds, max_count):
    clean_old_attempts(storage, window_seconds)
    now = time.time()
    arr = storage.get(key, [])
    arr = [t for t in arr if now - t <= window_seconds]
    if len(arr) >= max_count:
        storage[key] = arr
        return True
    arr.append(now)
    storage[key] = arr
    return False


def normalize_spaces(text):
    text = (text or "").strip()
    return re.sub(r"\s+", " ", text)


def sanitize_input(text, max_length=300):
    text = normalize_spaces(text)
    text = text.replace("<", "").replace(">", "")
    if len(text) > max_length:
        text = text[:max_length]
    return text


def valid_email(email):
    email = (email or "").strip()
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None and len(email) <= 120


def normalize_iraq_phone(phone):
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())

    if digits.startswith("964"):
        return "+" + digits

    if digits.startswith("0"):
        digits = digits[1:]

    if not digits.startswith("964"):
        digits = "964" + digits

    return "+" + digits


def valid_phone(phone):
    normalized = normalize_iraq_phone(phone)
    digits = "".join(ch for ch in normalized if ch.isdigit())
    return digits.startswith("964") and 12 <= len(digits) <= 15


def valid_password(password):
    return password is not None and len(password.strip()) >= 4


def file_size_ok(file_obj):
    try:
        current_pos = file_obj.stream.tell()
        file_obj.stream.seek(0, os.SEEK_END)
        size = file_obj.stream.tell()
        file_obj.stream.seek(current_pos)
        return size <= MAX_SINGLE_FILE_SIZE
    except Exception:
        return True


def detect_real_image_type(file_obj):
    return None


def validate_uploaded_image(file_obj):
    if not file_obj or file_obj.filename == "":
        return False, "لا يوجد ملف"
    return True, ""



def get_main_group_by_specialty(specialty):
    for group_name, items in SPECIALTY_GROUPS.items():
        if specialty in items:
            return group_name
    return ""


def get_specialty_icon(specialty):
    return SPECIALTY_ICONS.get(specialty, "🛠️")


def build_specialties_cards(active_section=""):
    html = '<div class="specialties-grid">'
    for group_name, items in SPECIALTY_GROUPS.items():
        html += f'''
        <div class="specialty-group-card">
            <h3>{group_name}</h3>
            <div class="specialty-items">
        '''
        for item in items:
            icon = get_specialty_icon(item)
            active_class = " active-specialty-item" if item == active_section else ""
            html += f'''
            <a class="specialty-item{active_class}" href="/workers-specialty/{item}">
                <div class="specialty-icon">{icon}</div>
                <div class="specialty-name">{item}</div>
            </a>
            '''
        html += '</div></div>'
    html += '</div>'
    return html


def build_main_groups_cards():
    html = '<div class="specialties-grid">'
    for group_name, items in SPECIALTY_GROUPS.items():
        first_icon = get_specialty_icon(items[0]) if items else "🛠️"
        html += f'''
        <a class="specialty-group-card" href="/workers-group/{group_name}" style="display:block;">
            <div class="specialty-icon" style="font-size:34px;margin-bottom:10px;">{first_icon}</div>
            <h3>{group_name}</h3>
            <div class="section-subtitle">عرض اختصاصات {group_name}</div>
        </a>
        '''
    html += '</div>'
    return html


def build_group_specialties_cards(group_name):
    items = SPECIALTY_GROUPS.get(group_name, [])
    html = '<div class="specialties-grid">'
    for item in items:
        icon = get_specialty_icon(item)
        html += f'''
        <a class="specialty-group-card" href="/workers-specialty/{item}" style="display:block;">
            <div class="specialty-icon" style="font-size:34px;margin-bottom:10px;">{icon}</div>
            <h3>{item}</h3>
            <div class="section-subtitle">فتح قائمة المستخدمين المسجلين بهذا الاختصاص</div>
        </a>
        '''
    html += '</div>'
    return html


def build_main_groups_options(selected_value=""):
    html = ""
    for group_name in SPECIALTY_GROUPS.keys():
        selected = "selected" if group_name == selected_value else ""
        html += f'<option value="{group_name}" {selected}>{group_name}</option>'
    return html


def build_specialties_options(selected_value="", group_name=""):
    html = ""
    items = SPECIALTY_GROUPS.get(group_name, []) if group_name else SPECIALTIES
    for item in items:
        selected = "selected" if item == selected_value else ""
        html += f'<option value="{item}" {selected}>{item}</option>'
    return html


def build_governorates_options(selected_value=""):
    html = ""
    for gov in IRAQ_GOVERNORATES:
        selected = "selected" if gov == selected_value else ""
        html += f'<option value="{gov}" {selected}>{gov}</option>'
    return html


def specialty_script(selected_value=""):
    groups_json = json.dumps(SPECIALTY_GROUPS, ensure_ascii=False)
    return f"""
    <script>
    const specialtyGroups = {groups_json};

    function updateSpecialties(selectedValue = "") {{
        const mainGroup = document.getElementById("main_group");
        const sectionSelect = document.getElementById("section");
        if (!mainGroup || !sectionSelect) return;

        const chosen = mainGroup.value;
        sectionSelect.innerHTML = '<option value="">اختر الاختصاص</option>';

        if (specialtyGroups[chosen]) {{
            specialtyGroups[chosen].forEach(function(item) {{
                const option = document.createElement("option");
                option.value = item;
                option.textContent = item;
                if (item === selectedValue) {{
                    option.selected = true;
                }}
                sectionSelect.appendChild(option);
            }});
        }}
    }}

    document.addEventListener("DOMContentLoaded", function() {{
        updateSpecialties({json.dumps(selected_value, ensure_ascii=False)});
    }});
    </script>
    """


def build_whatsapp_link(phone):
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if not digits:
        return "#"
    if digits.startswith("00"):
        digits = digits[2:]
    return f"https://api.whatsapp.com/send?phone={digits}"


GOVERNORATE_COORDS = {
    "بغداد": (33.3152, 44.3661),
    "البصرة": (30.5085, 47.7804),
    "نينوى": (36.3350, 43.1189),
    "أربيل": (36.1911, 44.0092),
    "النجف": (31.9996, 44.3267),
    "كربلاء": (32.6160, 44.0249),
    "الأنبار": (33.4258, 43.2993),
    "بابل": (32.5367, 44.4200),
    "ذي قار": (31.0429, 46.2573),
    "ديالى": (33.7436, 44.6436),
    "دهوك": (36.8671, 42.9885),
    "السليمانية": (35.5613, 45.4300),
    "صلاح الدين": (34.1966, 43.8739),
    "كركوك": (35.4681, 44.3922),
    "واسط": (32.5000, 45.8333),
    "ميسان": (31.8356, 47.1442),
    "المثنى": (31.3140, 45.2806),
    "القادسية": (31.9870, 44.9250),
    "حلبجة": (35.1778, 45.9861),
    "الناصرية": (31.0577, 46.2576)
}


def get_worker_rating_summary(user_id):
    with get_db() as con:
        row = con.execute(
            "SELECT COUNT(*) AS total, AVG(rating) AS avg_rating FROM comments WHERE user_id=?",
            (user_id,)
        ).fetchone()
    total = int(row["total"] or 0)
    avg_rating = float(row["avg_rating"] or 0)
    return round(avg_rating, 1), total


def render_stars(avg_rating):
    full = int(round(avg_rating))
    full = max(0, min(5, full))
    return "★" * full + "☆" * (5 - full)


def trusted_badge_html(worker):
    return '<span class="badge verified-badge">موثوق ✔️</span>' if worker["verified_worker"] else ""


def pinned_badge_html(worker):
    return '<span class="badge pinned-badge">مميز 📌</span>' if worker["is_pinned"] else ""


def worker_map_query(worker):
    place = normalize_spaces(f'{worker["city"] or ""} {worker["governorate"] or ""} العراق')
    return place or "العراق"


def worker_map_link(worker):
    query = worker_map_query(worker)
    return "https://www.google.com/maps/search/" + query.replace(" ", "+")


def governorate_coords(governorate):
    return GOVERNORATE_COORDS.get(governorate or "", (33.3152, 44.3661))


def allowed_file(filename):
    return True


def save_uploaded_file(file_obj):
    if not file_obj or file_obj.filename == "":
        return ""

    is_valid, _ = validate_uploaded_image(file_obj)
    if not is_valid:
        return ""

    original = secure_filename(file_obj.filename)
    if "." in original:
        ext = original.rsplit(".", 1)[1].lower()
        if ext == "jpeg":
            ext = "jpg"
        unique_name = f"{uuid.uuid4().hex}.{ext}"
    else:
        unique_name = f"{uuid.uuid4().hex}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

    try:
        file_obj.stream.seek(0)
    except Exception:
        pass

    file_obj.save(save_path)
    return unique_name


def delete_file_if_exists(filename):
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass

def insert_user_record(con, values_dict):
    payload = {
        "name": values_dict.get("name", ""),
        "phone": values_dict.get("phone", ""),
        "email": values_dict.get("email", ""),
        "password": values_dict.get("password", ""),
        "role": values_dict.get("role", ""),
        "birthdate": values_dict.get("birthdate", ""),
        "section": values_dict.get("section", ""),
        "governorate": values_dict.get("governorate", ""),
        "city": values_dict.get("city", ""),
        "exp": values_dict.get("exp", ""),
        "bio": values_dict.get("bio", ""),
        "profile_pic": values_dict.get("profile_pic", ""),
        "work_images": values_dict.get("work_images", ""),
    }

    try:
        con.execute("""
        INSERT INTO users
        (name, phone, email, password, role, birthdate, section, governorate, city, exp, bio, profile_pic, work_images, is_verified)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)
        """, (
            payload["name"], payload["phone"], payload["email"], payload["password"], payload["role"], payload["birthdate"],
            payload["section"], payload["governorate"], payload["city"], payload["exp"], payload["bio"], payload["profile_pic"], payload["work_images"]
        ))
    except sqlite3.OperationalError:
        con.execute("""
        INSERT INTO users
        (name, phone, email, password, role, birthdate, section, governorate, city, exp, bio, profile_pic, work_images)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            payload["name"], payload["phone"], payload["email"], payload["password"], payload["role"], payload["birthdate"],
            payload["section"], payload["governorate"], payload["city"], payload["exp"], payload["bio"], payload["profile_pic"], payload["work_images"]
        ))



@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


def get_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def table_columns(cur, table_name):
    cur.execute(f"PRAGMA table_info({table_name})")
    return [col[1] for col in cur.fetchall()]


def column_exists(cur, table_name, column_name):
    return column_name in table_columns(cur, table_name)


def init_db():
    with get_db() as con:
        cur = con.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            birthdate TEXT,
            section TEXT,
            city TEXT,
            exp TEXT,
            bio TEXT
        )
        """)

        if not column_exists(cur, "users", "is_verified"):
            cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "birthdate"):
            cur.execute("ALTER TABLE users ADD COLUMN birthdate TEXT DEFAULT ''")

        if not column_exists(cur, "users", "profile_pic"):
            cur.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT DEFAULT ''")

        if not column_exists(cur, "users", "work_images"):
            cur.execute("ALTER TABLE users ADD COLUMN work_images TEXT DEFAULT ''")

        if not column_exists(cur, "users", "governorate"):
            cur.execute("ALTER TABLE users ADD COLUMN governorate TEXT DEFAULT ''")

        if not column_exists(cur, "users", "show_phone"):
            cur.execute("ALTER TABLE users ADD COLUMN show_phone INTEGER DEFAULT 1")

        if not column_exists(cur, "users", "show_whatsapp"):
            cur.execute("ALTER TABLE users ADD COLUMN show_whatsapp INTEGER DEFAULT 1")

        if not column_exists(cur, "users", "allow_messages"):
            cur.execute("ALTER TABLE users ADD COLUMN allow_messages INTEGER DEFAULT 1")

        if not column_exists(cur, "users", "views"):
            cur.execute("ALTER TABLE users ADD COLUMN views INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "verified_worker"):
            cur.execute("ALTER TABLE users ADD COLUMN verified_worker INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "is_pinned"):
            cur.execute("ALTER TABLE users ADD COLUMN is_pinned INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "is_blocked"):
            cur.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0")

        if not column_exists(cur, "users", "hidden_by_admin"):
            cur.execute("ALTER TABLE users ADD COLUMN hidden_by_admin INTEGER DEFAULT 0")


        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_passkeys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT UNIQUE,
            public_key TEXT,
            sign_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_name TEXT,
            receiver_name TEXT,
            msg TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        if not column_exists(cur, "messages", "is_read"):
            cur.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_settings(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT,
            action TEXT,
            target_name TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            commenter_name TEXT,
            rating INTEGER,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)


        cur.execute("""
        CREATE TABLE IF NOT EXISTS support_messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender_type TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read_admin INTEGER DEFAULT 0,
            is_read_user INTEGER DEFAULT 0
        )
        """)

        if not column_exists(cur, "support_messages", "user_id"):
            cur.execute("ALTER TABLE support_messages ADD COLUMN user_id INTEGER DEFAULT 0")

        if not column_exists(cur, "support_messages", "sender_type"):
            cur.execute("ALTER TABLE support_messages ADD COLUMN sender_type TEXT DEFAULT 'user'")

        if not column_exists(cur, "support_messages", "message"):
            cur.execute("ALTER TABLE support_messages ADD COLUMN message TEXT DEFAULT ''")

        if not column_exists(cur, "support_messages", "is_read_admin"):
            cur.execute("ALTER TABLE support_messages ADD COLUMN is_read_admin INTEGER DEFAULT 0")

        if not column_exists(cur, "support_messages", "is_read_user"):
            cur.execute("ALTER TABLE support_messages ADD COLUMN is_read_user INTEGER DEFAULT 0")

        admin_row = cur.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
        if not admin_row:
            cur.execute(
                "INSERT INTO admin_settings (id, username, password) VALUES (1, ?, ?)",
                ("admin", generate_password_hash("1234"))
            )

        con.commit()

    print("تم تجهيز قاعدة البيانات بنجاح")


init_db()



def build_pretty_email_html(title, code, intro_text, note_text):
    return f"""
    <div dir="rtl" style="margin:0;padding:0;background:#eef4fb;font-family:Arial,Tahoma,sans-serif;">
        <div style="max-width:680px;margin:0 auto;padding:34px 16px;">
            <div style="background:linear-gradient(180deg,#0a1f3b 0%,#0f2d55 55%,#113766 100%);border-radius:28px;overflow:hidden;border:1px solid rgba(37,99,235,.16);box-shadow:0 22px 60px rgba(15,39,71,.20);">

                <div style="padding:30px 24px 14px 24px;text-align:center;color:#ffffff;">
                    <div style="display:inline-block;background:rgba(255,255,255,.10);padding:10px 18px;border-radius:999px;font-size:14px;margin-bottom:18px;border:1px solid rgba(255,255,255,.12);">
                        منصة المسطر
                    </div>

                    <h1 style="margin:0;font-size:31px;font-weight:800;letter-spacing:.2px;">{title}</h1>

                    <p style="margin:14px 0 0 0;font-size:17px;line-height:2;color:#dbeafe;">
                        {intro_text}
                    </p>
                </div>

                <div style="padding:24px;">
                    <div style="background:#ffffff;border-radius:24px;padding:30px 22px;text-align:center;border:1px solid #dbeafe;">
                        <div style="font-size:14px;color:#64748b;margin-bottom:10px;">رمز التحقق الخاص بك</div>

                        <div style="display:inline-block;background:linear-gradient(180deg,#2563eb 0%,#1d4ed8 100%);color:#ffffff;font-size:42px;font-weight:800;letter-spacing:8px;padding:18px 28px;border-radius:20px;box-shadow:0 14px 28px rgba(37,99,235,.24);">
                            {code}
                        </div>

                        <p style="margin:18px 0 0 0;font-size:15px;line-height:1.9;color:#475569;">
                            {note_text}
                        </p>
                    </div>

                    <div style="margin-top:16px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.08);padding:16px 18px;border-radius:18px;color:#dbeafe;font-size:14px;line-height:1.95;">
                        تم إرسال هذه الرسالة من <strong>المسطر</strong>. إذا لم تطلب هذا الإجراء، تجاهل الرسالة ولا تشارك الرمز مع أي شخص.
                    </div>
                </div>

                <div style="padding:0 24px 28px 24px;text-align:center;color:#bfdbfe;font-size:14px;line-height:1.9;">
                    مع التحية<br>
                    <strong>فريق المسطر</strong>
                </div>
            </div>
        </div>
    </div>
    """

def send_mail(to_email, subject, body, html_body=None):
    if not MAIL_ENABLED:
        print("MAIL DISABLED")
        return False

    provider = (MAIL_PROVIDER or "resend").lower().strip()

    if provider == "resend":
        if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
            print("RESEND ERROR: missing RESEND_API_KEY or RESEND_FROM_EMAIL")
            return False

        payload = {
            "from": RESEND_FROM_EMAIL,
            "to": [to_email],
            "subject": subject,
            "html": html_body or f"<div dir='rtl' style='font-family:Arial,sans-serif'><p>{body}</p></div>",
            "text": body,
        }

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "musattar-app/1.0",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                print("RESEND STATUS:", getattr(resp, "status", "unknown"), raw)
                return 200 <= getattr(resp, "status", 0) < 300
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(e)
            print("RESEND HTTP ERROR:", e.code, detail)
            return False
        except Exception as e:
            print("RESEND SEND ERROR:", e)
            return False

    # Optional SMTP fallback for non-Render/paid environments
    if not SENDER_EMAIL or not SENDER_APP_PASSWORD:
        print("MAIL ERROR: missing SENDER_EMAIL or SENDER_APP_PASSWORD")
        return False

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        return True
    except Exception as ssl_error:
        print("MAIL SSL ERROR:", ssl_error)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        return True
    except Exception as tls_error:
        print("MAIL TLS ERROR:", tls_error)
        return False


def otp_is_expired(session_key="otp_created_at"):
    created_at = session.get(session_key)
    if not created_at:
        return True
    return (time.time() - float(created_at)) > OTP_EXPIRY_SECONDS


def cleanup_saved_files(user_data):
    if not user_data:
        return
    if user_data.get("profile_pic"):
        delete_file_if_exists(user_data.get("profile_pic"))
    for img in [x.strip() for x in (user_data.get("work_images") or "").split(",") if x.strip()]:
        delete_file_if_exists(img)


STYLE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>المسطر</title>
<style>
:root{
    --primary:#2563eb;
    --primary-2:#60a5fa;
    --accent:#0ea5e9;
    --bg:#061426;
    --panel:rgba(10,25,47,.92);
    --card:rgba(255,255,255,.05);
    --text:#ecf5ff;
    --muted:#9db2ce;
    --border:rgba(96,165,250,.22);
    --shadow:0 18px 40px rgba(2,8,23,.35);
    --soft-shadow:0 10px 24px rgba(2,8,23,.24);
    
    
    
    
    
    
    
    
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;padding:0;font-family:Tahoma,Arial,sans-serif;background:radial-gradient(circle at top right, rgba(96,165,250,.18), transparent 22%),radial-gradient(circle at top left, rgba(14,165,233,.14), transparent 20%),linear-gradient(180deg,#06101d 0%, #0a1d35 48%, #0d2744 100%);color:var(--text)}
a{text-decoration:none;color:inherit}
.container{width:min(94%,1120px);margin:24px auto;background:linear-gradient(180deg, rgba(10,25,47,.96), rgba(7,18,35,.96));backdrop-filter:blur(12px);border:1px solid rgba(96,165,250,.18);border-radius:30px;padding:22px;box-shadow:var(--shadow)}
.narrow-container{width:min(94%,620px)}
h1,h2,h3,h4{margin:0 0 14px} h1{font-size:36px} h2{font-size:28px} h3{font-size:20px}
.small{font-size:13px;color:var(--muted)} .center{text-align:center}
.section-subtitle{font-size:14px;color:var(--muted);margin-bottom:14px}
input,select,textarea,button{width:100%;margin:8px 0;padding:13px 14px;border-radius:16px;border:1px solid var(--border);font-size:16px;background:rgba(255,255,255,.06);color:var(--text)}
input:focus,select:focus,textarea:focus{outline:none;border-color:rgba(96,165,250,.55);box-shadow:0 0 0 4px rgba(37,99,235,.16)}
textarea{min-height:120px;resize:vertical}
button{background:linear-gradient(180deg,#3b82f6 0%, #1d4ed8 100%);color:#f8fbff;border:none;cursor:pointer;font-weight:700;box-shadow:0 10px 18px rgba(37,99,235,.25)} button:hover{transform:translateY(-1px);opacity:.97}
button.light-btn{background:rgba(37,99,235,.18);color:var(--text);border:1px solid rgba(96,165,250,.32)}
label{display:block;font-weight:bold;margin-top:10px}
.msg,.notice-box{background:rgba(37,99,235,.14);border:1px solid rgba(96,165,250,.28);padding:14px;border-radius:18px;text-align:center;margin:12px 0;color:#dbeafe}
.notice{font-size:13px;text-align:center;color:var(--muted);margin-top:8px}
hr{border:none;border-top:1px solid var(--border);margin:18px 0}
.row,.inline,.topbar,.worker-hero-top,.admin-panel-top{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.row>*{flex:1;min-width:220px}
.hero-panel,.card,.specialty-group-card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box{background:rgba(255,255,255,.05);border:1px solid rgba(96,165,250,.18);border-radius:24px;box-shadow:var(--soft-shadow)}
.hero-panel,.card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box,.comment-card{padding:18px}
.hero-badge,.badge,.worker-specialty-badge{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:34px;padding:7px 12px;border-radius:999px;font-size:12px;font-weight:700}
.hero-badge,.badge{background:rgba(59,130,246,.16);color:#dbeafe;border:1px solid rgba(96,165,250,.28)}
.worker-specialty-badge{background:linear-gradient(180deg,#1e40af 0%, #1d4ed8 100%);color:#eff6ff}
.home-grid,.home-features-grid,.home-stats-grid,.specialties-grid,.work-grid,.admin-stats-grid,.admin-users-grid{display:grid;gap:14px}
.home-grid{grid-template-columns:1.4fr .9fr}.home-features-grid,.home-stats-grid{grid-template-columns:repeat(3,1fr)}
.home-feature-icon{width:54px;height:54px;border-radius:18px;background:rgba(59,130,246,.16);display:flex;align-items:center;justify-content:center;font-size:26px;margin-bottom:10px}
.profile-img,.profile-img-large{object-fit:cover;border-radius:50%;border:4px solid rgba(96,165,250,.7);background:rgba(255,255,255,.08)}
.profile-img{width:88px;height:88px}.profile-img-large{width:128px;height:128px;display:block}
.profile-placeholder,.profile-placeholder-large{display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,.08);border-radius:50%;color:#bfd4ee;border:3px solid rgba(96,165,250,.32)}
.profile-placeholder{width:88px;height:88px;font-size:32px}.profile-placeholder-large{width:128px;height:128px;font-size:42px;margin:0 auto}
.worker-card{display:grid;grid-template-columns:96px 1fr;gap:16px;align-items:start}
.worker-info-grid,.detail-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:12px}
.info-chip,.detail-box{background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:16px;padding:10px 12px;font-size:14px}
.work-grid{grid-template-columns:repeat(3,1fr);margin-top:12px}
.work-grid img{width:100%;aspect-ratio:1/1;object-fit:cover;border-radius:18px;border:2px solid rgba(96,165,250,.5);background:rgba(255,255,255,.08)}
.specialties-grid{grid-template-columns:repeat(2,1fr);margin-top:18px}
.specialty-group-card h3{margin:0 0 12px;color:var(--text);font-size:18px}.specialty-items{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.specialty-item{display:block;background:rgba(255,255,255,.05);border:1px solid rgba(96,165,250,.18);border-radius:16px;padding:14px 8px;text-align:center;transition:.2s;color:var(--text)}
.specialty-item:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.08)}
.active-specialty-item{background:var(--text);color:#eff6ff;border-color:var(--text)}.active-specialty-item .specialty-name,.active-specialty-item .specialty-icon{color:#eff6ff}
.specialty-icon{font-size:28px;margin-bottom:6px}.specialty-name{font-size:14px;font-weight:700;color:var(--text);line-height:1.6}
.link-btn,.bottom-corner-link,.settings-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px}
.link-btn{background:linear-gradient(180deg,#2563eb 0%, #1d4ed8 100%);color:#eff6ff;padding:10px 14px;border-radius:14px;margin:4px 0;font-size:14px;font-weight:700;border:1px solid rgba(147,197,253,.28);box-shadow:0 6px 18px rgba(0,0,0,.22)}.link-red{background:linear-gradient(180deg,#dc2626 0%, #b91c1c 100%);color:#fff}
.search-panel{display:none;margin-bottom:16px}.search-panel.show{display:block}.search-inline-grid{display:grid;grid-template-columns:1.3fr 1fr 1fr auto;gap:10px;align-items:end}
.settings-floating{position:fixed;top:14px;left:14px;z-index:9999}.settings-btn{width:auto;min-width:46px;height:46px;padding:0 14px;background:linear-gradient(180deg,#1d4ed8 0%, #1e40af 100%);color:#eff6ff;border-radius:999px;font-size:14px;font-weight:700;box-shadow:0 6px 18px rgba(0,0,0,.22);border:1px solid rgba(147,197,253,.28)}
.bottom-corner-link{position:fixed;bottom:18px;z-index:9999;min-width:86px;height:46px;padding:0 16px;background:linear-gradient(180deg,#1d4ed8 0%, #1e40af 100%);color:#eff6ff;border-radius:999px;box-shadow:0 6px 18px rgba(0,0,0,.22);font-size:14px;font-weight:700;border:1px solid rgba(147,197,253,.28)}.bottom-left-link{left:16px}.bottom-right-link{right:16px}
.global-back-wrap{position:fixed;top:14px;right:14px;z-index:9999}.global-back-btn{display:inline-flex;align-items:center;justify-content:center;min-width:112px;height:46px;padding:0 16px;background:linear-gradient(180deg,#2563eb 0%, #1d4ed8 100%);color:#eff6ff;border-radius:999px;box-shadow:0 6px 18px rgba(0,0,0,.22);font-size:14px;font-weight:800;border:1px solid rgba(147,197,253,.28)}
.settings-profile-wrap{display:flex;align-items:center;gap:14px}.settings-profile-info{flex:1}.settings-section-title{font-size:18px;font-weight:700;margin:0 0 10px;text-align:right}
.worker-hero-grid{display:grid;grid-template-columns:140px 1fr;gap:18px;align-items:start}
.star{font-size:20px;color:#60a5fa;margin:6px 0}.comment-card{margin:10px 0}
.admin-stats-grid{grid-template-columns:repeat(4,1fr);margin-bottom:16px}.admin-stat .label{font-size:13px;color:var(--muted);margin-bottom:8px}.admin-stat .value{font-size:28px;font-weight:700}
.admin-users-grid{grid-template-columns:repeat(2,1fr)}
.empty-state{padding:24px;text-align:center;border-radius:22px;background:rgba(255,255,255,.06);border:1px dashed rgba(96,165,250,.18);color:#615200}
.footer-note{text-align:center;color:var(--muted);font-size:13px;margin-top:16px}
@media (max-width:960px){.home-grid,.home-features-grid,.home-stats-grid,.admin-stats-grid,.admin-users-grid,.specialties-grid{grid-template-columns:1fr}.search-inline-grid{grid-template-columns:1fr}}
@media (max-width:720px){h1{font-size:28px}h2{font-size:24px}.container{padding:16px;border-radius:24px}.worker-card,.worker-hero-grid,.settings-profile-wrap{grid-template-columns:1fr;display:grid}.worker-info-grid,.detail-grid,.work-grid,.specialty-items{grid-template-columns:1fr 1fr}}
@media (max-width:520px){.work-grid,.worker-info-grid,.detail-grid,.specialty-items{grid-template-columns:1fr}.bottom-corner-link{font-size:13px;min-width:74px;padding:0 12px}}

.worker-rating-line{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
.rating-stars{font-size:16px;color:#fbbf24;letter-spacing:2px}
.rating-text{font-size:13px;color:#dbeafe}
.verified-badge{background:rgba(16,185,129,.18);border-color:rgba(16,185,129,.45);color:#d1fae5}
.pinned-badge{background:rgba(245,158,11,.16);border-color:rgba(245,158,11,.45);color:#fde68a}
.filter-grid-pro{display:grid;grid-template-columns:1.2fr 1fr 1fr 1fr 1fr auto;gap:10px;align-items:end}
.map-link-btn{background:rgba(255,255,255,.08);border:1px solid rgba(96,165,250,.28);color:var(--text)}
.mini-stat{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:16px;padding:10px 12px}
.map-page-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:14px}
#workersMap{width:100%;height:620px;border-radius:22px;border:1px solid rgba(96,165,250,.22);overflow:hidden}
.map-list-card{max-height:620px;overflow:auto}
@media (max-width:960px){.filter-grid-pro,.map-page-grid{grid-template-columns:1fr}}


/* Soft elegant typography tuning */
:root{
    --text:#eaf2ff;
    --muted:#b7c7dd;
}
body{
    font-family:"Tahoma","Arial",sans-serif;
    font-size:15px;
    line-height:1.75;
    -webkit-font-smoothing:antialiased;
    -moz-osx-font-smoothing:grayscale;
}
.container{
    width:min(92%,1060px);
    margin:18px auto;
    padding:18px;
    border-radius:24px;
}
h1,h2,h3,h4{
    letter-spacing:0;
    line-height:1.5;
    font-weight:700;
}
h1{font-size:30px}
h2{font-size:24px}
h3{font-size:18px}
.small,.section-subtitle,.notice,.footer-note{font-size:13px;line-height:1.8}
input,select,textarea,button{
    font-size:14px;
    padding:11px 13px;
    border-radius:14px;
}
button{font-weight:700}
.hero-panel,.card,.specialty-group-card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box{
    border-radius:20px;
    padding:16px;
}
.home-feature-icon{
    width:48px;
    height:48px;
    border-radius:15px;
    font-size:22px;
}
.home-grid{grid-template-columns:1.2fr .85fr;gap:14px}
.home-features-grid,.home-stats-grid,.specialties-grid,.work-grid,.admin-stats-grid,.admin-users-grid{gap:12px}
.profile-img{width:78px;height:78px}
.profile-img-large{width:112px;height:112px}
.profile-placeholder{width:78px;height:78px;font-size:28px}
.profile-placeholder-large{width:112px;height:112px;font-size:38px}
.worker-card{grid-template-columns:86px 1fr;gap:14px}
.worker-info-grid,.detail-grid{gap:8px;margin-top:10px}
.info-chip,.detail-box{
    border-radius:14px;
    padding:9px 11px;
    font-size:13px;
    line-height:1.7;
}
.work-grid img{
    border-radius:14px;
}
.specialty-group-card h3{font-size:17px}
.specialty-item{
    border-radius:14px;
    padding:12px 8px;
}
.specialty-icon{font-size:24px}
.specialty-name{font-size:13px;line-height:1.6}
.link-btn{
    padding:9px 13px;
    border-radius:12px;
    font-size:13px;
}
.settings-btn{
    width:42px;
    height:42px;
    font-size:18px;
}
.bottom-corner-link,.global-back-btn{
    min-width:78px;
    height:42px;
    padding:0 14px;
    font-size:13px;
}
.worker-hero-grid{grid-template-columns:120px 1fr;gap:16px}
.star{font-size:18px}
.admin-stat .value{font-size:24px}
.empty-state{
    padding:20px;
    border-radius:18px;
}
.topbar,.row,.inline,.worker-hero-top,.admin-panel-top{gap:10px}
.filter-grid-pro,.map-page-grid{gap:12px}
.map-box,.map-list-box,.stats-soft-card{
    border-radius:20px !important;
}
.worker-rating-line{
    gap:6px;
    flex-wrap:wrap;
}
.rating-stars{
    font-size:15px;
    letter-spacing:1px;
}
@media (max-width:960px){
    .home-grid,.home-features-grid,.home-stats-grid,.admin-stats-grid,.admin-users-grid,.specialties-grid,.filter-grid-pro,.map-page-grid{grid-template-columns:1fr}
}
@media (max-width:720px){
    h1{font-size:24px}
    h2{font-size:20px}
    h3{font-size:16px}
    .container{padding:14px;border-radius:20px}
    .worker-card,.worker-hero-grid,.settings-profile-wrap{grid-template-columns:1fr;display:grid}
    .worker-info-grid,.detail-grid,.work-grid,.specialty-items{grid-template-columns:1fr 1fr}
}
@media (max-width:520px){
    body{font-size:14px}
    .work-grid,.worker-info-grid,.detail-grid,.specialty-items{grid-template-columns:1fr}
    input,select,textarea,button{font-size:13px;padding:10px 12px}
    .container{width:min(94%,1000px)}
    .hero-panel,.card,.settings-group,.worker-hero,.home-feature-card,.home-stat,.home-cta-box,.comment-card{padding:14px}
    .profile-img{width:70px;height:70px}
    .profile-img-large{width:98px;height:98px}
}


/* Back/settings floating buttons clarity fix */
#globalBackWrap,.settings-floating{filter:none}
.global-back-btn:hover,.settings-btn:hover,.bottom-corner-link:hover{transform:translateY(-1px);opacity:.98}
.global-back-btn:before{content:"↩ ";font-size:15px}
@media (max-width:520px){
  .global-back-btn,.settings-btn{height:40px;min-width:94px;font-size:13px;padding:0 12px}
  .bottom-corner-link{height:40px;min-width:70px}
}


/* Fix pale white action buttons */
.link-btn:hover,.link-red:hover{filter:brightness(1.04);transform:translateY(-1px)}


/* Dark readable selects and small controls */
select{
    background:linear-gradient(180deg, rgba(37,54,82,.96), rgba(26,40,63,.96)) !important;
    color:#eef6ff !important;
    border:1px solid rgba(96,165,250,.30) !important;
    appearance:auto;
}
select option{
    background:#13253f !important;
    color:#eef6ff !important;
}
select optgroup{
    background:#13253f !important;
    color:#93c5fd !important;
    font-weight:700;
}
input[type="checkbox"]{
    width:18px !important;
    height:18px !important;
    accent-color:#2563eb;
    vertical-align:middle;
}
label input[type="checkbox"]{
    margin-left:8px;
}

</style>
</head>
<body>
"""

def settings_corner():
    hidden_paths = {"/login", "/register", "/forgot", "/reset"}
    if "user" in session and request.path not in hidden_paths:
        return '''
        <div class="settings-floating">
            <a class="settings-btn" href="/settings" title="الإعدادات">الإعدادات</a>
        </div>
        '''
    return ""


HOME_HTML = STYLE + """
<div class="container narrow-container" style="margin-top:90px;text-align:center;">
    <h1 style="font-size:42px;margin-bottom:20px;">المسطر</h1>
    <div class="section-subtitle" style="margin-bottom:18px;">دخول الاختصاصي من هنا، أما الزائر فله صفحة دخول مستقلة من الزر الموجود بالأسفل.</div>

    <form action="/login" method="post">
        <input type="email" name="email" value="{{ last_email }}" placeholder="البريد الإلكتروني" required>
        <input type="password" name="password" placeholder="كلمة السر" required>
        <button type="submit">تسجيل دخول الاختصاصي</button>
    </form>

    <div class="inline" style="justify-content:space-between;margin-top:12px;">
        <a href="/register" style="color:#60a5fa;font-weight:700;">إنشاء حساب اختصاصي</a>
        <a href="/forgot" style="color:#cbd5e1;">نسيت كلمة السر</a>
    </div>
</div>
<a class="bottom-corner-link bottom-left-link" href="/admin">🛠️</a>
<a class="bottom-corner-link bottom-right-link" href="/visitor/login">👤 زائر</a>
</body></html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_HTML, last_email=(session.get("last_email") or request.cookies.get("remember_email", "")))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        password = request.form.get("password", "")
        ip = get_client_ip()

        if too_many_attempts(LOGIN_ATTEMPTS, ip, LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
            return render_template_string(STYLE + '<div class="container"><div class="msg">تم تجاوز عدد محاولات الدخول، حاول لاحقاً</div><a href="/login"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            user = con.execute("SELECT * FROM users WHERE email=? AND role!='visitor'", (email,)).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return render_template_string(STYLE + '<div class="container"><div class="msg">البريد الإلكتروني أو كلمة المرور غير صحيحة</div><a href="/login"><button>رجوع</button></a></div></body></html>')

        if user["is_blocked"]:
            return render_template_string(STYLE + '<div class="container"><div class="msg">هذا الحساب محظور من قبل الإدارة</div><a href="/login"><button>رجوع</button></a></div></body></html>')

        session.permanent = True
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        session["role"] = user["role"] or "worker"
        session["last_email"] = user["email"] or email
        LOGIN_ATTEMPTS.pop(ip, None)
        resp = redirect(url_for("workers"))
        resp.set_cookie("remember_email", email, max_age=60*60*24*30)
        return resp

    return redirect(url_for("home"))


def visitor_account_required():
    return "user" in session and session.get("role") == "visitor"


@app.route("/visitor/login", methods=["GET", "POST"])
def visitor_login():
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        password = request.form.get("password", "")
        ip = get_client_ip()

        if too_many_attempts(LOGIN_ATTEMPTS, f"visitor:{ip}", LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
            return render_template_string(STYLE + '<div class="container"><div class="msg">تم تجاوز عدد محاولات الدخول، حاول لاحقاً</div><a href="/visitor/login"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            user = con.execute("SELECT * FROM users WHERE email=? AND role='visitor'", (email,)).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return render_template_string(STYLE + '<div class="container"><div class="msg">البريد الإلكتروني أو كلمة المرور غير صحيحة</div><a href="/visitor/login"><button>رجوع</button></a></div></body></html>')

        if user["is_blocked"]:
            return render_template_string(STYLE + '<div class="container"><div class="msg">هذا الحساب محظور من قبل الإدارة</div><a href="/visitor/login"><button>رجوع</button></a></div></body></html>')

        session.permanent = True
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        session["role"] = "visitor"
        session["last_email"] = user["email"] or email
        LOGIN_ATTEMPTS.pop(f"visitor:{ip}", None)
        resp = redirect(url_for("workers"))
        resp.set_cookie("remember_email", email, max_age=60*60*24*30)
        return resp

    return render_template_string(
        STYLE + """
        <div class="container narrow-container" style="margin-top:70px;">
            <a href="/"><button class="light-btn">رجوع للرئيسية</button></a>
            <h2>دخول الزائر</h2>
            <div class="section-subtitle">إذا كان عندك حساب زائر، سجّل دخولك من هنا.</div>
            <form method="post">
                <input type="email" name="email" placeholder="البريد الإلكتروني" required>
                <input type="password" name="password" placeholder="كلمة السر" required>
                <button>دخول الزائر</button>
            </form>
            <div class="notice">ما عندك حساب؟ <a href="/visitor/register" style="color:#93c5fd;font-weight:700;">أنشئ حساب جديد</a></div>
        </div>
        </body></html>
        """
    )


@app.route("/visitor/register", methods=["GET", "POST"])
def visitor_register():
    if request.method == "POST":
        d = {
            "name": sanitize_input(request.form.get("name", ""), 80),
            "email": sanitize_input(request.form.get("email", ""), 120).lower(),
            "password": request.form.get("password", "").strip(),
            "role": "visitor",
        }

        if not d["name"] or not d["email"] or not d["password"]:
            return render_template_string(STYLE + '<div class="container"><div class="msg">اكمل الحقول المطلوبة</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        if not valid_email(d["email"]):
            return render_template_string(STYLE + '<div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        if not valid_password(d["password"]):
            return render_template_string(STYLE + '<div class="container"><div class="msg">كلمة المرور قصيرة</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            old = con.execute("SELECT id FROM users WHERE email=?", (d["email"],)).fetchone()
            if old:
                return render_template_string(STYLE + '<div class="container"><div class="msg">هذا البريد مستخدم مسبقاً</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        d["password"] = generate_password_hash(d["password"])

        try:
            with get_db() as con:
                old = con.execute("SELECT id FROM users WHERE email=?", (d["email"],)).fetchone()
                if old:
                    return render_template_string(STYLE + '<div class="container"><div class="msg">هذا البريد مستخدم مسبقاً</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

                insert_user_record(con, {
                    "name": d["name"],
                    "phone": "",
                    "email": d["email"],
                    "password": d["password"],
                    "role": "visitor",
                    "birthdate": "",
                    "section": "",
                    "governorate": "",
                    "city": "",
                    "exp": "",
                    "bio": "",
                    "profile_pic": "",
                    "work_images": "",
                })
                con.commit()
        except sqlite3.IntegrityError:
            return render_template_string(STYLE + '<div class="container"><div class="msg">تعذر حفظ الحساب: البريد مستخدم مسبقاً</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')
        except Exception as e:
            return render_template_string(STYLE + f'<div class="container"><div class="msg">تعذر إنشاء حساب الزائر: {str(e)}</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        return redirect(url_for("visitor_login"))

    return render_template_string(
        STYLE + """
        <div class="container narrow-container" style="margin-top:70px;">
            <a href="/visitor/login"><button class="light-btn">رجوع</button></a>
            <h2>إنشاء حساب زائر</h2>
            <div class="section-subtitle">أنشئ حساب زائر بسيط بالاسم والبريد الإلكتروني وكلمة السر فقط.</div>
            <form method="post">
                <input name="name" placeholder="الاسم" required>
                <input type="email" name="email" placeholder="البريد الإلكتروني" required>
                <input type="password" name="password" placeholder="كلمة السر" required>
                <button>إنشاء حساب الزائر</button>
            </form>
            <div class="notice">بعد إنشاء الحساب تگدر تسجل دخولك مباشرة.</div>
        </div>
        </body></html>
        """
    )


@app.route("/visitor/verify", methods=["GET", "POST"])
def visitor_verify():
    return redirect(url_for("visitor_register"))


@app.route("/visitor/account")
def visitor_account():
    if "user" not in session:
        return redirect(url_for("visitor_login"))
    if session.get("role") != "visitor":
        return redirect(url_for("profile"))

    user = get_current_session_user()
    if not user:
        session.clear()
        return redirect(url_for("visitor_login"))

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container">
            <a href="/settings"><button class="light-btn">رجوع</button></a>
            <h2>حساب الزائر</h2>
            <div class="card">
                <div class="detail-grid">
                    <div class="detail-box"><strong>الاسم</strong>{user["name"] or "-"}</div>
                    <div class="detail-box"><strong>البريد الإلكتروني</strong>{user["email"] or "-"}</div>
                    <div class="detail-box"><strong>نوع الحساب</strong>زائر</div>
                </div>
            </div>
        </div>
        </body></html>
        """
    )


@app.route("/visitor/edit-profile", methods=["GET", "POST"])
def visitor_edit_profile():
    if "user" not in session:
        return redirect(url_for("visitor_login"))
    if session.get("role") != "visitor":
        return redirect(url_for("edit_profile"))

    user = get_current_session_user()
    if not user:
        session.clear()
        return redirect(url_for("visitor_login"))

    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""), 80)
        email = sanitize_input(request.form.get("email", ""), 120).lower()

        if not name or not email:
            return render_template_string(STYLE + '<div class="container"><div class="msg">الاسم والبريد الإلكتروني مطلوبان</div><a href="/visitor/edit-profile"><button>رجوع</button></a></div></body></html>')

        if not valid_email(email):
            return render_template_string(STYLE + '<div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/visitor/edit-profile"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            exists = con.execute("SELECT id FROM users WHERE email=? AND id != ?", (email, user["id"])).fetchone()
            if exists:
                return render_template_string(STYLE + '<div class="container"><div class="msg">هذا البريد مستخدم من حساب آخر</div><a href="/visitor/edit-profile"><button>رجوع</button></a></div></body></html>')

            con.execute("UPDATE users SET name=?, email=? WHERE id=?", (name, email, user["id"]))
            con.commit()

        session["user"] = name
        session["last_email"] = email
        return render_template_string(STYLE + '<div class="container"><div class="msg">تم تحديث حساب الزائر بنجاح</div><a href="/settings"><button>الرجوع للإعدادات</button></a></div></body></html>')

    return render_template_string(
        STYLE + f"""
        <div class="container narrow-container">
            <a href="/settings"><button class="light-btn">رجوع</button></a>
            <h2>تعديل حساب الزائر</h2>
            <form method="post">
                <input name="name" value="{user['name'] or ''}" placeholder="الاسم" required>
                <input type="email" name="email" value="{user['email'] or ''}" placeholder="البريد الإلكتروني" required>
                <button>حفظ التعديلات</button>
            </form>
        </div>
        </body></html>
        """
    )


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))

    user = get_current_session_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not check_password_hash(user["password"], current_password):
            return render_template_string(STYLE + '<div class="container"><div class="msg">كلمة المرور الحالية غير صحيحة</div><a href="/change-password"><button>رجوع</button></a></div></body></html>')

        if not valid_password(new_password):
            return render_template_string(STYLE + '<div class="container"><div class="msg">كلمة المرور الجديدة قصيرة</div><a href="/change-password"><button>رجوع</button></a></div></body></html>')

        if new_password != confirm_password:
            return render_template_string(STYLE + '<div class="container"><div class="msg">تأكيد كلمة المرور غير مطابق</div><a href="/change-password"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            con.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), user["id"]))
            con.commit()

        return render_template_string(STYLE + '<div class="container"><div class="msg">تم تغيير كلمة المرور بنجاح</div><a href="/settings"><button>الرجوع للإعدادات</button></a></div></body></html>')

    return render_template_string(
        STYLE + """
        <div class="container narrow-container">
            <a href="/settings"><button class="light-btn">رجوع</button></a>
            <h2>تغيير كلمة المرور</h2>
            <form method="post">
                <input type="password" name="current_password" placeholder="كلمة المرور الحالية" required>
                <input type="password" name="new_password" placeholder="كلمة المرور الجديدة" required>
                <input type="password" name="confirm_password" placeholder="تأكيد كلمة المرور الجديدة" required>
                <button>حفظ كلمة المرور الجديدة</button>
            </form>
        </div>
        </body></html>
        """
    )


@app.route("/manage-work-images/<int:user_id>", methods=["GET", "POST"])
def manage_work_images(user_id):
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "worker":
        return redirect(url_for("settings"))

    user = get_current_session_user()
    if not user or int(user["id"]) != int(user_id):
        return redirect(url_for("profile"))

    existing_images = [x.strip() for x in (user["work_images"] or "").split(",") if x.strip()]

    if request.method == "POST":
        remove_images = request.form.getlist("remove_images")
        kept_images = [img for img in existing_images if img not in remove_images]

        for img in remove_images:
            delete_file_if_exists(img)

        added = []
        if "work_images" in request.files:
            files = request.files.getlist("work_images")
            remaining = max(0, MAX_WORK_IMAGES - len(kept_images))
            for file_obj in files[:remaining]:
                if file_obj and file_obj.filename:
                    valid_img, msg = validate_uploaded_image(file_obj)
                    if not valid_img:
                        return render_template_string(STYLE + f'<div class="container"><div class="msg">{msg}</div><a href="/manage-work-images/{user_id}"><button>رجوع</button></a></div></body></html>')
                    saved = save_uploaded_file(file_obj)
                    if saved:
                        added.append(saved)

        final_images = kept_images + added

        with get_db() as con:
            con.execute("UPDATE users SET work_images=? WHERE id=?", (",".join(final_images), user["id"]))
            con.commit()

        return render_template_string(STYLE + '<div class="container"><div class="msg">تم تحديث الأعمال بنجاح</div><a href="/edit-profile"><button>رجوع</button></a></div></body></html>')

    previews = ""
    if existing_images:
        previews = "<div class='work-grid'>" + "".join(
            f"<label style='display:block;text-align:center;'><img src='{url_for('uploaded_file', filename=img)}' alt='work'><div class='small'><input type='checkbox' name='remove_images' value='{img}'> حذف هذه الصورة</div></label>"
            for img in existing_images
        ) + "</div>"
    else:
        previews = '<div class="empty-state">لا توجد أعمال مرفوعة حالياً</div>'

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <a href="/edit-profile"><button class="light-btn">رجوع</button></a>
            <h2>إدارة أعمالي</h2>
            <div class="section-subtitle">يمكنك حذف صور قديمة وإضافة صور جديدة، والحد الأعلى {MAX_WORK_IMAGES} صور.</div>
            <form method="post" enctype="multipart/form-data">
                {previews}
                <label>إضافة صور جديدة</label>
                <input type="file" name="work_images" accept=".png,.jpg,.jpeg,.gif,.webp" multiple>
                <button>حفظ التعديلات</button>
            </form>
        </div>
        </body></html>
        """
    )



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        d = {
            "name": sanitize_input(request.form.get("name", ""), 80),
            "phone": sanitize_input(request.form.get("phone", ""), 25),
            "email": sanitize_input(request.form.get("email", ""), 120).lower(),
            "password": request.form.get("password", "").strip(),
            "role": "worker",
            "section": sanitize_input(request.form.get("section", ""), 80),
            "governorate": sanitize_input(request.form.get("governorate", ""), 80),
            "city": sanitize_input(request.form.get("city", ""), 80),
            "exp": sanitize_input(request.form.get("exp", ""), 30),
            "bio": sanitize_input(request.form.get("bio", ""), 500)
        }

        if not d["name"] or not d["phone"] or not d["email"] or not d["password"]:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اكمل الحقول الأساسية</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if d["role"]=="worker" and (not d["section"] or not d["governorate"] or not d["city"] or not d["exp"]):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اكمل الحقول الأساسية</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if not valid_email(d["email"]):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        d["phone"] = normalize_iraq_phone(d["phone"])

        if not valid_phone(d["phone"]):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">رقم الهاتف غير صحيح</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if not valid_password(d["password"]):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">كلمة المرور قصيرة</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if d["governorate"] not in IRAQ_GOVERNORATES:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اختر محافظة صحيحة</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if d["section"] not in SPECIALTIES:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اختر اختصاص صحيح</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        profile_pic = ""
        profile_file = request.files.get("profile_pic")
        if not profile_file or not profile_file.filename:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">الصورة الشخصية إجبارية</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        valid_img, msg = validate_uploaded_image(profile_file)
        if not valid_img:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">{msg}</div><a href="/register"><button>رجوع</button></a></div></body></html>')
        profile_pic = save_uploaded_file(profile_file)

        work_images_list = []
        if "work_images" in request.files:
            files = request.files.getlist("work_images")
            if len(files) > MAX_WORK_IMAGES:
                cleanup_saved_files({"profile_pic": profile_pic, "work_images": ",".join(work_images_list)})
                return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">الحد الأقصى لأعمالي هو {MAX_WORK_IMAGES}</div><a href="/register"><button>رجوع</button></a></div></body></html>')

            for file_obj in files[:MAX_WORK_IMAGES]:
                if file_obj and file_obj.filename:
                    valid_img, msg = validate_uploaded_image(file_obj)
                    if not valid_img:
                        cleanup_saved_files({"profile_pic": profile_pic, "work_images": ",".join(work_images_list)})
                        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">{msg}</div><a href="/register"><button>رجوع</button></a></div></body></html>')
                    saved = save_uploaded_file(file_obj)
                    if saved:
                        work_images_list.append(saved)

        d["profile_pic"] = profile_pic
        d["work_images"] = ",".join(work_images_list)
        d["password"] = generate_password_hash(d["password"])

        try:
            with get_db() as con:
                old = con.execute("SELECT id FROM users WHERE phone=? OR email=?", (d["phone"], d["email"])).fetchone()
                if old:
                    cleanup_saved_files(d)
                    return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">رقم الهاتف أو البريد مستخدم مسبقاً</div><a href="/register"><button>رجوع</button></a></div></body></html>')

                insert_user_record(con, {
                    "name": d["name"],
                    "phone": d["phone"],
                    "email": d["email"],
                    "password": d["password"],
                    "role": d["role"],
                    "birthdate": "",
                    "section": d["section"],
                    "governorate": d["governorate"],
                    "city": d["city"],
                    "exp": d["exp"],
                    "bio": d["bio"],
                    "profile_pic": d["profile_pic"],
                    "work_images": d["work_images"],
                })
                con.commit()
        except sqlite3.IntegrityError:
            cleanup_saved_files(d)
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تعذر حفظ الحساب: رقم الهاتف أو البريد مستخدم مسبقاً</div><a href="/register"><button>رجوع</button></a></div></body></html>')
        except Exception as e:
            cleanup_saved_files(d)
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">تعذر إنشاء الحساب: {str(e)}</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        return redirect(url_for("login"))

    group_options = build_main_groups_options("")
    gov_options = build_governorates_options("")
    specialty_options = build_specialties_options("", "")

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/"><button>رجوع للرئيسية</button></a>
            <h2>إنشاء حساب</h2>
            <form method="post" enctype="multipart/form-data">
                <input name="name" placeholder="الاسم الكامل" required>
                <input name="phone" placeholder="07XXXXXXXXX" required>
                <input name="email" type="email" placeholder="البريد الإلكتروني" required>
                <input name="password" type="password" placeholder="كلمة المرور" required>

                

                <label>القسم الرئيسي</label>
                <select name="main_group" id="main_group" onchange="updateSpecialties()" required>
                    <option value="">اختر القسم الرئيسي</option>
                    {group_options}
                </select>

                <label>الاختصاص</label>
                <select name="section" id="section" required>
                    <option value="">اختر الاختصاص</option>
                    {specialty_options}
                </select>

                <label>المحافظة</label>
                <select name="governorate" required>
                    <option value="">اختر المحافظة</option>
                    {gov_options}
                </select>

                <input name="city" placeholder="المدينة / المنطقة" required>
                <input name="exp" placeholder="سنوات الخبرة" required>
                <textarea name="bio" placeholder="نبذة مختصرة عنك"></textarea>

                <label>الصورة الشخصية</label>
                <input type="file" name="profile_pic" accept=".png,.jpg,.jpeg,.gif,.webp">

                <label>أعمالي</label>
                <input type="file" name="work_images" accept=".png,.jpg,.jpeg,.gif,.webp" multiple>

                <button>إنشاء الحساب</button>
            </form>

        </div>
        {specialty_script("")}
        </body></html>
        """
    )


@app.route("/verify", methods=["GET", "POST"])
def verify():
    return redirect(url_for("register"))


@app.route("/forgot", methods=["GET", "POST"] )
def forgot():
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        if not valid_email(email):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">البريد الإلكتروني غير صحيح</div><a href="/forgot"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            user = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()

        if not user:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا البريد غير مسجل</div><a href="/forgot"><button>رجوع</button></a></div></body></html>')

        otp = str(random.randint(100000, 999999))
        session["reset_email"] = email
        session["reset_otp"] = otp
        session["reset_otp_created_at"] = time.time()

        reset_html = build_pretty_email_html(
            "استعادة كلمة السر",
            otp,
            "وصلنا طلب استعادة كلمة السر لحسابك في المسطر. استخدم رمز التحقق التالي للمتابعة بأمان.",
            "أدخل هذا الرمز داخل تطبيق المسطر ثم اختر كلمة سر جديدة."
        )
        sent = send_mail(
            email,
            "استعادة كلمة السر",
            f"كود استعادة كلمة السر هو: {otp}",
            html_body=reset_html
        )
        if not sent:
            session.pop("reset_email", None)
            session.pop("reset_otp", None)
            session.pop("reset_otp_created_at", None)
            session.pop("reset_console_notice", None)
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + '''
                <div class="container">
                    <div class="msg">فشل إرسال كود الاستعادة إلى البريد الإلكتروني. تأكد من إعدادات Gmail.</div>
                    <a href="/forgot"><button>رجوع</button></a>
                </div>
                </body></html>
                '''
            )

        return redirect(url_for("reset_password"))

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + """
        <div class="container">
            <a href="/login"><button>رجوع</button></a>
            <h2>استعادة الحساب</h2>
            <form method="post">
                <input type="email" name="email" placeholder="البريد الإلكتروني" required>
                <button>إرسال الكود</button>
            </form>

        </div>
        </body></html>
        """
    )


@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    reset_email = session.get("reset_email")
    reset_otp = session.get("reset_otp")
    console_notice = ""

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        new_pass = request.form.get("new_pass", "").strip()

        if not reset_email or not reset_otp:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">انتهت جلسة الاستعادة</div><a href="/forgot"><button>رجوع</button></a></div></body></html>')

        if otp_is_expired("reset_otp_created_at"):
            session.pop("reset_email", None)
            session.pop("reset_otp", None)
            session.pop("reset_otp_created_at", None)
            session.pop("reset_console_notice", None)
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">انتهت صلاحية كود الاستعادة</div><a href="/forgot"><button>رجوع</button></a></div></body></html>')

        if otp != reset_otp:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">كود الاستعادة غير صحيح</div><a href="/reset"><button>رجوع</button></a></div></body></html>')

        if not valid_password(new_pass):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">كلمة المرور الجديدة قصيرة</div><a href="/reset"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            con.execute(
                "UPDATE users SET password=? WHERE email=?",
                (generate_password_hash(new_pass), reset_email)
            )
            con.commit()

        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_created_at", None)
        session.pop("reset_console_notice", None)
        return redirect(url_for("login"))

    note_html = f'<div class="msg">{console_notice}</div>' if console_notice else ""

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/forgot"><button>رجوع</button></a>
            <h2>إعادة تعيين كلمة المرور</h2>
            {note_html}
            <form method="post">
                <input name="otp" placeholder="كود الاستعادة" required>
                <input type="password" name="new_pass" placeholder="كلمة المرور الجديدة" required>
                <button>حفظ كلمة المرور</button>
            </form>
        </div>
        </body></html>
        """
    )


def worker_card(worker):
    profile_html = (
        f'<img src="{url_for("uploaded_file", filename=worker["profile_pic"])}" class="profile-img" alt="profile">'
        if worker["profile_pic"]
        else '<div class="profile-placeholder">👤</div>'
    )

    work_images_html = ""
    imgs = [x.strip() for x in (worker["work_images"] or "").split(",") if x.strip()]
    if imgs:
        blocks = []
        for img in imgs[:6]:
            blocks.append(f'<img src="{url_for("uploaded_file", filename=img)}" alt="work">')
        work_images_html = f'<div class="work-grid">{"".join(blocks)}</div>'

    phone_html = f'<div class="info-chip"><strong>الهاتف</strong><div>{worker["phone"]}</div></div>' if worker["show_phone"] else ""
    wa_html = f'<a class="link-btn" target="_blank" href="{build_whatsapp_link(worker["phone"])}">واتساب</a>' if worker["show_whatsapp"] else ""
    map_html = f'<a class="link-btn map-link-btn" target="_blank" href="{worker_map_link(worker)}">الخريطة</a>'
    avg_rating, rating_count = get_worker_rating_summary(worker["id"])
    stars = render_stars(avg_rating)
    verified_badge = trusted_badge_html(worker)
    pinned_badge = pinned_badge_html(worker)

    return f"""
    <div class="card">
        <div class="worker-card">
            <div>{profile_html}</div>
            <div>
                <div class="inline" style="margin-bottom:8px;">
                    <span class="worker-specialty-badge">{get_specialty_icon(worker["section"])} {worker["section"] or "بدون اختصاص"}</span>
                    <span class="badge">{worker["governorate"] or "بدون محافظة"}</span>
                    {verified_badge}
                    {pinned_badge}
                </div>
                <h3>{worker["name"]}</h3>
                <div class="small">ملف مهني يعرض المعلومات الأساسية وأعمالي وطرق التواصل.</div>
                <div class="worker-rating-line">
                    <span class="rating-stars">{stars}</span>
                    <span class="rating-text">⭐ {avg_rating} / 5</span>
                    <span class="badge">({rating_count} تقييم)</span>
                    <span class="badge">👁 {worker["views"] or 0} مشاهدة</span>
                </div>
                <div style="margin-top:10px;">{worker["bio"] or "لا توجد نبذة حالياً"}</div>
                <div class="worker-info-grid">
                    <div class="info-chip"><strong>المدينة</strong><div>{worker["city"] or "-"}</div></div>
                    <div class="info-chip"><strong>الخبرة</strong><div>{worker["exp"] or "-"}</div></div>
                    {phone_html}
                </div>
                <div class="inline" style="margin-top:8px;">
                    <a class="link-btn" href="/worker/{worker['id']}">فتح الملف</a>
                    {wa_html}
                    {map_html}
                </div>
            </div>
        </div>
        {work_images_html}
    </div>
    """




@app.route("/workers")
def workers():
    auto_login_from_cookie()

    if "user" in session:
        user_buttons = '''
        <a href="/profile"><button>ملفي الشخصي</button></a>
        <a href="/inbox"><button>الرسائل</button></a>
        
        <a href="/logout"><button>تسجيل الخروج</button></a>
        '''
    else:
        user_buttons = '''
        
        '''

    groups_cards = build_main_groups_cards()

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f'''
        <div class="container">
            <div class="topbar">
                <div><a href="/"><button class="light-btn">الرئيسية</button></a></div>
                <div class="inline"><span class="badge">اختَر القسم الرئيسي</span></div>
            </div>

            <div class="hero-panel" style="margin-bottom:16px;">
                <div class="inline" style="margin-bottom:10px;">
                    <span class="hero-badge">تصفح منظم</span>
                    <span class="hero-badge">قسم ← اختصاص ← مستخدمون</span>
                </div>
                <h2>الأقسام الرئيسية</h2>
                <div class="section-subtitle">اختر القسم الرئيسي أولاً، وبعدها تفتح لك صفحة الاختصاصات الخاصة به، ثم تظهر لك قائمة المستخدمين المسجلين.</div>
            </div>

            {user_buttons}

            <h3 style="margin-top:22px;">الاختصاصات الرئيسية</h3>
            {groups_cards}
        </div>
        </body></html>
        '''
    )


@app.route("/workers-group/<path:group_name>")
def workers_group(group_name):
    auto_login_from_cookie()
    group_name = sanitize_input(group_name, 80)

    if group_name not in SPECIALTY_GROUPS:
        return render_template_string(
            STYLE + (settings_corner() if 'user' in session else '') + '''
            <div class="container">
                <div class="msg">القسم المطلوب غير موجود</div>
                <a href="/workers"><button>رجوع</button></a>
            </div>
            </body></html>
            '''
        )

    specialties_cards = build_group_specialties_cards(group_name)

    if "user" in session:
        user_buttons = '''
        <a href="/profile"><button>ملفي الشخصي</button></a>
        <a href="/inbox"><button>الرسائل</button></a>
        
        '''
    else:
        user_buttons = '''
        
        '''

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f'''
        <div class="container">
            <div class="topbar">
                <div><a href="/workers"><button class="light-btn">رجوع للأقسام</button></a></div>
                <div class="inline"><span class="badge">{group_name}</span></div>
            </div>

            <div class="hero-panel" style="margin-bottom:16px;">
                <h2>اختصاصات {group_name}</h2>
                <div class="section-subtitle">اختر الاختصاص الذي تريده من هذا القسم حتى تظهر لك قائمة المستخدمين المسجلين.</div>
            </div>

            {user_buttons}
            {specialties_cards}
        </div>
        </body></html>
        '''
    )


@app.route("/workers-specialty/<path:specialty_name>")
def workers_specialty(specialty_name):
    auto_login_from_cookie()
    specialty_name = sanitize_input(specialty_name, 80)

    if specialty_name not in SPECIALTIES:
        return render_template_string(
            STYLE + (settings_corner() if 'user' in session else '') + '''
            <div class="container">
                <div class="msg">الاختصاص المطلوب غير موجود</div>
                <a href="/workers"><button>رجوع</button></a>
            </div>
            </body></html>
            '''
        )

    group_name = get_main_group_by_specialty(specialty_name)

    with get_db() as con:
        rows = con.execute(
            '''
            SELECT users.*
            FROM users
            WHERE users.is_verified=1
              AND COALESCE(users.is_blocked,0)=0
              AND COALESCE(users.hidden_by_admin,0)=0
              AND (users.role='worker' OR users.role IS NULL)
              AND users.section=?
            ORDER BY users.is_pinned DESC, users.id DESC
            ''',
            (specialty_name,)
        ).fetchall()

    cards = "".join(worker_card(row) for row in rows) if rows else '<div class="msg">لا يوجد مستخدمون مسجلون حالياً بهذا الاختصاص</div>'

    if "user" in session:
        user_buttons = '''
        <a href="/profile"><button>ملفي الشخصي</button></a>
        <a href="/inbox"><button>الرسائل</button></a>
        
        '''
    else:
        user_buttons = '''
        
        '''

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f'''
        <div class="container">
            <div class="topbar">
                <div class="inline">
                    <a href="/workers"><button class="light-btn">الأقسام</button></a>
                    <a href="/workers-group/{group_name}"><button class="light-btn">اختصاصات {group_name}</button></a>
                </div>
                <div class="inline"><span class="badge">{specialty_name}</span></div>
            </div>

            <div class="hero-panel" style="margin-bottom:16px;">
                <div class="inline" style="margin-bottom:10px;">
                    <span class="hero-badge">{group_name}</span>
                    <span class="hero-badge">{specialty_name}</span>
                </div>
                <h2>المستخدمون المسجلون ضمن اختصاص {specialty_name}</h2>
                <div class="section-subtitle">هذه الصفحة تعرض فقط المستخدمين المسجلين داخل هذا الاختصاص.</div>
            </div>

            {user_buttons}

            <div id="results" style="margin-top:18px;">
                {cards}
            </div>
        </div>
        </body></html>
        '''
    )


@app.route("/worker/<int:user_id>", methods=["GET", "POST"])
def worker_profile(user_id):
    with get_db() as con:
        worker = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        comments = con.execute(
            "SELECT * FROM comments WHERE user_id=? ORDER BY id DESC",
            (user_id,)
        ).fetchall()

    if not worker or worker["is_blocked"] or worker["hidden_by_admin"]:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا الملف غير متاح حالياً</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

    with get_db() as con:
        con.execute("UPDATE users SET views = COALESCE(views, 0) + 1 WHERE id=?", (user_id,))
        con.commit()
        worker = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if request.method == "POST":
        ip = get_client_ip()
        if too_many_attempts(COMMENT_RATE_LIMIT, f"{ip}:{user_id}", COMMENT_WINDOW_SECONDS, COMMENT_MAX_COUNT):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تم تجاوز عدد التعليقات المسموح مؤقتاً</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

        commenter_name = session["user"] if "user" in session else "زائر"
        rating_raw = request.form.get("rating", "5").strip()
        comment = sanitize_input(request.form.get("comment", ""), 400)

        try:
            rating = int(rating_raw)
        except Exception:
            rating = 5

        if rating < 1 or rating > 5:
            rating = 5

        if not comment:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اكتب تعليقاً أولاً</div><a href="/worker/%d"><button>رجوع</button></a></div></body></html>' % user_id)

        with get_db() as con:
            con.execute(
                "INSERT INTO comments (user_id, commenter_name, rating, comment) VALUES (?, ?, ?, ?)",
                (user_id, commenter_name, rating, comment)
            )
            con.commit()

        return redirect(url_for("worker_profile", user_id=user_id))

    avg_rating, rating_count = get_worker_rating_summary(user_id)
    stars = render_stars(avg_rating)
    profile_html = (
        f'<img src="{url_for("uploaded_file", filename=worker["profile_pic"])}" class="profile-img-large" alt="profile">'
        if worker["profile_pic"]
        else '<div class="profile-placeholder-large">👤</div>'
    )

    imgs = [x.strip() for x in (worker["work_images"] or "").split(",") if x.strip()]
    work_images_html = ""
    if imgs:
        work_images_html = '<div class="work-grid">' + "".join(
            f'<img src="{url_for("uploaded_file", filename=img)}" alt="work">' for img in imgs
        ) + '</div>'

    phone_html = f'<div class="detail-box"><strong>الهاتف</strong>{worker["phone"]}</div>' if worker["show_phone"] else ""
    wa_html = f'<a class="link-btn" target="_blank" href="{build_whatsapp_link(worker["phone"])}">مراسلة واتساب</a>' if worker["show_whatsapp"] else ""
    map_html = f'<a class="link-btn map-link-btn" target="_blank" href="{worker_map_link(worker)}">فتح الموقع على الخريطة</a>'

    comments_html = ""
    if comments:
        blocks = []
        for c in comments:
            cstars = "★" * int(c["rating"] or 0) + "☆" * (5 - int(c["rating"] or 0))
            blocks.append(f"""
            <div class="comment-card">
                <div><strong>{c["commenter_name"]}</strong></div>
                <div class="star">{cstars}</div>
                <div>{c["comment"]}</div>
                <div class="small">{c["created_at"]}</div>
            </div>
            """)
        comments_html = "".join(blocks)
    else:
        comments_html = '<div class="msg">لا توجد تعليقات بعد</div>'

    message_button = ""
    if "user" in session and worker["allow_messages"]:
        message_button = f'<a class="link-btn" href="/message/{worker["id"]}">إرسال رسالة</a>'

    verified_badge = trusted_badge_html(worker)
    pinned_badge = pinned_badge_html(worker)

    comment_form = f"""
        <div class="card">
            <h3>إضافة تعليق وتقييم</h3><div class="section-subtitle">يمكن للمستخدم أو الزائر إضافة رأيه وتقييمه هنا.</div>
            <form method="post">
                <select name="rating" required>
                    <option value="5">5 نجوم</option>
                    <option value="4">4 نجوم</option>
                    <option value="3">3 نجوم</option>
                    <option value="2">2 نجوم</option>
                    <option value="1">1 نجمة</option>
                </select>
                <textarea name="comment" placeholder="اكتب تقييمك وتعليقك" required></textarea>
                <button>نشر التعليق</button>
            </form>
        </div>
        """

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/workers"><button class="light-btn">رجوع</button></a>

            <div class="worker-hero">
                <div class="worker-hero-grid">
                    <div class="center">{profile_html}</div>
                    <div>
                        <div class="inline" style="margin-bottom:10px;">
                            <span class="worker-specialty-badge">{get_specialty_icon(worker["section"])} {worker["section"] or "-"}</span>
                            <span class="badge">{worker["governorate"] or "-"}</span>
                            {verified_badge}
                            {pinned_badge}
                            <span class="badge">👁 {worker["views"] or 0} مشاهدة</span>
                        </div>
                        <h2>{worker["name"]}</h2>
                        <div class="worker-rating-line">
                            <span class="rating-stars">{stars}</span>
                            <span class="badge">⭐ {avg_rating} / 5</span>
                            <span class="badge">{rating_count} تقييم</span>
                        </div>
                        <div class="section-subtitle">صفحة شخصية تعرض المعلومات الأساسية والأعمال وطرق التواصل بشكل أوضح.</div>
                        <div style="margin-top:10px;">{worker["bio"] or "لا توجد نبذة حالياً"}</div>

                        <div class="detail-grid">
                            <div class="detail-box"><strong>المدينة</strong>{worker["city"] or "-"}</div>
                            <div class="detail-box"><strong>الخبرة</strong>{worker["exp"] or "-"}</div>
                            {phone_html}
                            <div class="detail-box"><strong>استقبال الرسائل</strong>{'مفعل' if worker['allow_messages'] else 'معطل'}</div>
                        </div>

                        <div class="inline" style="margin-top:12px;">
                            {wa_html}
                            {message_button}
                            {map_html}
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>أعمالي</h3>
                <div class="section-subtitle">معرض مرتب لأعمال العامل داخل الملف الشخصي.</div>
                {work_images_html if work_images_html else '<div class="empty-state">لا توجد أعمال حتى الآن</div>'}
            </div>

            <div class="card">
                <h3>التقييمات والتعليقات</h3>
                {comments_html}
            </div>
            {comment_form}
        </div>
        </body></html>
        """
    )



@app.route("/message/<int:user_id>", methods=["GET", "POST"])
def message_user(user_id):
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        receiver = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not receiver:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">المستخدم غير موجود</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

    if not receiver["allow_messages"]:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا المستخدم عطّل استقبال الرسائل</div><a href="/worker/%d"><button>رجوع</button></a></div></body></html>' % user_id)

    if request.method == "POST":
        msg = sanitize_input(request.form.get("msg", ""), 1000)
        if not msg:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اكتب الرسالة أولاً</div><a href="/message/%d"><button>رجوع</button></a></div></body></html>' % user_id)

        ip = get_client_ip()
        key = f"{ip}:{session['user']}:{receiver['name']}"
        if too_many_attempts(MESSAGE_RATE_LIMIT, key, MESSAGE_WINDOW_SECONDS, MESSAGE_MAX_COUNT):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تم تجاوز عدد الرسائل المسموح مؤقتاً</div><a href="/worker/%d"><button>رجوع</button></a></div></body></html>' % user_id)

        with get_db() as con:
            con.execute(
                "INSERT INTO messages (sender_name, receiver_name, msg) VALUES (?, ?, ?)",
                (session["user"], receiver["name"], msg)
            )
            con.commit()

        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تم إرسال الرسالة</div><a href="/inbox"><button>فتح الرسائل</button></a></div></body></html>')

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/worker/{user_id}"><button>رجوع</button></a>
            <h2>إرسال رسالة إلى {receiver["name"]}</h2>
            <form method="post">
                <textarea name="msg" placeholder="اكتب رسالتك" required></textarea>
                <button>إرسال</button>
            </form>
        </div>
        </body></html>
        """
    )


@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        rows = con.execute(
            "SELECT * FROM messages WHERE receiver_name=? OR sender_name=? ORDER BY id DESC",
            (session["user"], session["user"])
        ).fetchall()

        con.execute("UPDATE messages SET is_read=1 WHERE receiver_name=?", (session["user"],))
        con.commit()

    if not rows:
        messages_html = '<div class="msg">لا توجد رسائل</div>'
    else:
        blocks = []
        for row in rows:
            direction = "واردة" if row["receiver_name"] == session["user"] else "صادرة"
            other_name = row["sender_name"] if direction == "واردة" else row["receiver_name"]
            blocks.append(f"""
            <div class="card">
                <div><strong>{direction}</strong> - مع {other_name}</div>
                <div style="margin-top:8px;">{row["msg"]}</div>
                <div class="small">{row["created_at"]}</div>
            </div>
            """)
        messages_html = "".join(blocks)

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/workers"><button>رجوع</button></a>
            <h2>الرسائل</h2>
            {messages_html}
        </div>
        </body></html>
        """
    )


@app.route("/support", methods=["GET", "POST"])
def support():
    if "user" not in session:
        return redirect(url_for("login"))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        msg = sanitize_input(request.form.get("msg", ""), 1500)
        if not msg:
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container narrow-container">
                    <div class="msg">اكتب رسالتك أولاً</div>
                    <a href="/support"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        with get_db() as con:
            con.execute(
                "INSERT INTO support_messages (user_id, sender_type, message, is_read_admin, is_read_user) VALUES (?, 'user', ?, 0, 1)",
                (current_user["id"], msg)
            )
            con.commit()

        return redirect(url_for("support"))

    with get_db() as con:
        messages = con.execute(
            "SELECT * FROM support_messages WHERE user_id=? ORDER BY id ASC",
            (current_user["id"],)
        ).fetchall()
        con.execute(
            "UPDATE support_messages SET is_read_user=1 WHERE user_id=? AND sender_type='admin'",
            (current_user["id"],)
        )
        con.commit()

    chat_html = ""
    for m in messages:
        mine = m["sender_type"] == "user"
        align = "justify-content:flex-end;" if mine else "justify-content:flex-start;"
        bg = "linear-gradient(180deg,#2563eb 0%, #1d4ed8 100%)" if mine else "rgba(255,255,255,.08)"
        color = "#ffffff" if mine else "var(--text)"
        label = "أنت" if mine else "الدعم الفني"
        small_color = "#dbeafe" if mine else "var(--muted)"
        chat_html += f"""
        <div style="display:flex;{align}margin:10px 0;">
            <div style="max-width:78%;background:{bg};color:{color};padding:12px 14px;border-radius:18px;border:1px solid rgba(96,165,250,.18);">
                <div style="font-size:12px;opacity:.85;margin-bottom:5px;">{label}</div>
                <div style="white-space:pre-wrap;word-break:break-word;">{m["message"]}</div>
                <div class="small" style="margin-top:6px;color:{small_color};">{m["created_at"]}</div>
            </div>
        </div>
        """

    if not chat_html:
        chat_html = '<div class="empty-state">ماكو رسائل دعم بعد. اكتب مشكلتك وسيتم الرد عليك من داخل التطبيق.</div>'

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container">
            <a href="/settings"><button class="light-btn">رجوع</button></a>
            <h2>الدعم الفني</h2>
            <div class="section-subtitle">اكتب مشكلتك هنا، وسيصلك الرد من الإدارة داخل نفس المحادثة.</div>

            <div class="card" style="padding:14px;max-height:420px;overflow:auto;">
                {chat_html}
            </div>

            <form method="post" style="margin-top:14px;">
                <textarea name="msg" placeholder="اكتب رسالتك للدعم الفني" required></textarea>
                <button>إرسال الرسالة</button>
            </form>
        </div>
        </body></html>
        """
    )


@app.route("/admin/support", methods=["GET", "POST"])
def admin_support():
    if not admin_required():
        return redirect(url_for("admin_login"))

    selected_user_id = request.args.get("user_id", "").strip()

    if request.method == "POST":
        selected_user_id = request.form.get("user_id", "").strip()
        msg = sanitize_input(request.form.get("msg", ""), 1500)

        if selected_user_id and msg:
            try:
                uid = int(selected_user_id)
            except Exception:
                uid = 0

            if uid:
                with get_db() as con:
                    user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                    if user:
                        con.execute(
                            "INSERT INTO support_messages (user_id, sender_type, message, is_read_admin, is_read_user) VALUES (?, 'admin', ?, 1, 0)",
                            (uid, msg)
                        )
                        con.commit()
                        log_admin_action("رد دعم فني", user["name"], "تم إرسال رد من الأدمن داخل الدعم الفني")
            return redirect(url_for("admin_support", user_id=selected_user_id))

    with get_db() as con:
        conversations = con.execute(
            """
            SELECT u.id, u.name, u.email,
                   MAX(sm.id) AS last_id,
                   MAX(sm.created_at) AS last_time,
                   SUM(CASE WHEN sm.sender_type='user' AND COALESCE(sm.is_read_admin,0)=0 THEN 1 ELSE 0 END) AS unread_count
            FROM support_messages sm
            JOIN users u ON u.id = sm.user_id
            GROUP BY u.id, u.name, u.email
            ORDER BY last_id DESC
            """
        ).fetchall()

    conversation_list = ""
    for c in conversations:
        active = " style='background:rgba(37,99,235,.16);border-color:rgba(96,165,250,.34);'" if selected_user_id and str(c["id"]) == str(selected_user_id) else ""
        unread = int(c["unread_count"] or 0)
        unread_badge = f"<span class='badge'>{unread} جديد</span>" if unread > 0 else ""
        conversation_list += f"""
        <a href="/admin/support?user_id={c['id']}" style="display:block;">
            <div class="card"{active}>
                <div class="inline" style="justify-content:space-between;">
                    <strong>{c["name"]}</strong>
                    {unread_badge}
                </div>
                <div class="small">{c["email"] or ""}</div>
                <div class="small">آخر رسالة: {c["last_time"] or ""}</div>
            </div>
        </a>
        """

    if not conversation_list:
        conversation_list = '<div class="empty-state">لا توجد رسائل دعم حتى الآن</div>'

    chat_html = '<div class="empty-state">اختر محادثة من القائمة</div>'
    reply_form = ""

    if selected_user_id:
        try:
            uid = int(selected_user_id)
        except Exception:
            uid = 0

        if uid:
            with get_db() as con:
                target_user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                messages = con.execute(
                    "SELECT * FROM support_messages WHERE user_id=? ORDER BY id ASC",
                    (uid,)
                ).fetchall()
                con.execute(
                    "UPDATE support_messages SET is_read_admin=1 WHERE user_id=? AND sender_type='user'",
                    (uid,)
                )
                con.commit()

            if target_user:
                blocks = ""
                for m in messages:
                    is_admin = m["sender_type"] == "admin"
                    align = "justify-content:flex-end;" if is_admin else "justify-content:flex-start;"
                    bg = "linear-gradient(180deg,#1d4ed8 0%, #1e40af 100%)" if is_admin else "rgba(255,255,255,.08)"
                    color = "#ffffff" if is_admin else "var(--text)"
                    sender = "الأدمن" if is_admin else target_user["name"]
                    small_color = "#dbeafe" if is_admin else "var(--muted)"
                    blocks += f"""
                    <div style="display:flex;{align}margin:10px 0;">
                        <div style="max-width:78%;background:{bg};color:{color};padding:12px 14px;border-radius:18px;border:1px solid rgba(96,165,250,.18);">
                            <div style="font-size:12px;opacity:.85;margin-bottom:5px;">{sender}</div>
                            <div style="white-space:pre-wrap;word-break:break-word;">{m["message"]}</div>
                            <div class="small" style="margin-top:6px;color:{small_color};">{m["created_at"]}</div>
                        </div>
                    </div>
                    """
                chat_html = blocks or '<div class="empty-state">لا توجد رسائل</div>'
                reply_form = f"""
                <form method="post" style="margin-top:14px;">
                    <input type="hidden" name="user_id" value="{uid}">
                    <textarea name="msg" placeholder="اكتب ردك هنا" required></textarea>
                    <button>إرسال الرد</button>
                </form>
                """

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <a href="/admin/panel"><button class="light-btn">رجوع للوحة الأدمن</button></a>
            <h2>الدعم الفني</h2>
            <div class="section-subtitle">اختر المستخدم من القائمة ثم رد عليه من داخل المحادثة.</div>

            <div class="map-page-grid">
                <div class="card map-list-card" style="padding:14px;">
                    <h3 style="margin-bottom:10px;">المحادثات</h3>
                    {conversation_list}
                </div>

                <div class="card" style="padding:14px;max-height:650px;overflow:auto;">
                    {chat_html}
                    {reply_form}
                </div>
            </div>
        </div>
        </body></html>
        """
    )


@app.route("/logout")
def logout():
    remembered_email = session.get("last_email") or request.cookies.get("remember_email", "")
    session.clear()
    if remembered_email:
        session["last_email"] = remembered_email
    resp = redirect(url_for("home"))
    if remembered_email:
        resp.set_cookie("remember_email", remembered_email, max_age=60*60*24*30)
    return resp


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""), 50)
        password = request.form.get("password", "")

        with get_db() as con:
            admin = con.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()

        if not admin or admin["username"] != username or not check_password_hash(admin["password"], password):
            return render_template_string(STYLE + '<div class="container"><div class="msg">بيانات الأدمن غير صحيحة</div><a href="/admin"><button>رجوع</button></a></div></body></html>')

        session["admin"] = username
        return redirect(url_for("admin_panel"))

    return render_template_string(
        STYLE + """
        <div class="container">
            <a href="/"><button>رجوع للرئيسية</button></a>
            <h2>دخول الأدمن</h2>
            <form method="post">
                <input name="username" placeholder="اسم المستخدم" required>
                <input type="password" name="password" placeholder="كلمة المرور" required>
                <button>دخول</button>
            </form>
        </div>
        </body></html>
        """
    )


def admin_required():
    return "admin" in session


def log_admin_action(action, target_name="", details=""):
    if "admin" not in session:
        return
    with get_db() as con:
        con.execute(
            "INSERT INTO admin_logs (admin_username, action, target_name, details) VALUES (?, ?, ?, ?)",
            (session["admin"], action, target_name, details)
        )
        con.commit()


@app.route("/admin/panel")
def admin_panel():
    if not admin_required():
        return redirect(url_for("admin_login"))

    admin_q = sanitize_input(request.args.get("q", ""), 80)

    with get_db() as con:
        users_count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        verified_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE is_verified=1").fetchone()["c"]
        messages_count = con.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
        comments_count = con.execute("SELECT COUNT(*) AS c FROM comments").fetchone()["c"]
        trusted_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE verified_worker=1").fetchone()["c"]
        pinned_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE is_pinned=1").fetchone()["c"]
        blocked_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE COALESCE(is_blocked,0)=1").fetchone()["c"]
        hidden_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE COALESCE(hidden_by_admin,0)=1").fetchone()["c"]

        if admin_q:
            like_q = f"%{admin_q}%"
            users = con.execute(
                "SELECT * FROM users WHERE name LIKE ? OR phone LIKE ? OR email LIKE ? ORDER BY is_pinned DESC, id DESC",
                (like_q, like_q, like_q)
            ).fetchall()
        else:
            users = con.execute("SELECT * FROM users ORDER BY is_pinned DESC, id DESC").fetchall()

        logs = con.execute("SELECT * FROM admin_logs ORDER BY id DESC LIMIT 20").fetchall()

    users_html = ""
    for u in users:
        avg_rating, rating_count = get_worker_rating_summary(u["id"])
        verified_badge = trusted_badge_html(u)
        pinned_badge = pinned_badge_html(u)
        trust_toggle = f'/admin/unverify-worker/{u["id"]}' if u["verified_worker"] else f'/admin/verify-worker/{u["id"]}'
        trust_text = 'إلغاء التوثيق' if u["verified_worker"] else 'توثيق العامل'
        pin_toggle = f'/admin/unpin-worker/{u["id"]}' if u["is_pinned"] else f'/admin/pin-worker/{u["id"]}'
        pin_text = 'إلغاء التثبيت' if u["is_pinned"] else 'تثبيت بالأعلى'
        block_toggle = f'/admin/unblock-user/{u["id"]}' if u["is_blocked"] else f'/admin/block-user/{u["id"]}'
        block_text = 'فك الحظر' if u["is_blocked"] else 'حظر المستخدم'
        hide_toggle = f'/admin/unhide-user/{u["id"]}' if u["hidden_by_admin"] else f'/admin/hide-user/{u["id"]}'
        hide_text = 'إظهار الملف' if u["hidden_by_admin"] else 'إخفاء الملف'
        blocked_badge = '<span class="badge" style="background:rgba(220,38,38,.18);border:1px solid rgba(248,113,113,.35);">🚫 محظور</span>' if u["is_blocked"] else ''
        hidden_badge = '<span class="badge" style="background:rgba(245,158,11,.16);border:1px solid rgba(251,191,36,.28);">🙈 مخفي</span>' if u["hidden_by_admin"] else ''
        users_html += f"""
        <div class="admin-user-card">
            <div><strong>{u["name"]}</strong></div>
            <div class="small">{u["email"]}</div>
            <div class="inline" style="margin:10px 0;">
                <span class="worker-specialty-badge">{get_specialty_icon(u['section'])} {u["section"] or "-"}</span>
                <span class="badge">{u["governorate"] or "-"}</span>
                {verified_badge}
                {pinned_badge}
                {blocked_badge}
                {hidden_badge}
            </div>
            <div class="small">الهاتف: {u["phone"] or "-"}</div>
            <div class="small">المدينة: {u["city"] or "-"}</div>
            <div class="small">التقييم: ⭐ {avg_rating} / 5 ({rating_count})</div>
            <div class="small">المشاهدات: 👁 {u["views"] or 0}</div>
            <div class="inline" style="margin-top:12px;">
                <a class="link-btn" href="/worker/{u['id']}">فتح الملف</a>
                <a class="link-btn" href="/admin/edit-user/{u['id']}">تعديل البيانات</a>
                <a class="link-btn" href="{trust_toggle}">{trust_text}</a>
                <a class="link-btn" href="{pin_toggle}">{pin_text}</a>
                <a class="link-btn" href="{block_toggle}">{block_text}</a>
                <a class="link-btn" href="{hide_toggle}">{hide_text}</a>
                <a class="link-btn link-red" href="/admin/delete-user/{u['id']}">حذف المستخدم</a>
            </div>
        </div>
        """

    logs_html = ""
    if logs:
        logs_html = "".join(
            f'<div class="admin-log-card"><div><strong>{l["action"]}</strong> - {l["target_name"] or "-"}</div><div>{l["details"] or ""}</div><div class="small">{l["created_at"]}</div></div>'
            for l in logs
        )
    else:
        logs_html = '<div class="msg">لا توجد سجلات</div>'

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <div class="admin-panel-top">
                <div class="inline">
                    <a href="/"><button class="light-btn">الرئيسية</button></a>
                    <a href="/admin/settings"><button class="light-btn">إعدادات الأدمن</button></a>
                    <a href="/admin/messages"><button class="light-btn">كل الرسائل</button></a>
                    <a href="/admin/comments"><button class="light-btn">كل التعليقات</button></a>
                    <a href="/admin/support"><button class="light-btn">الدعم الفني</button></a>
                    <a href="/workers-map"><button class="light-btn">الخريطة</button></a>
                    <a href="/admin/logout"><button>خروج الأدمن</button></a>
                </div>
                <span class="badge">لوحة تحكم الأدمن</span>
            </div>

            <div class="hero-panel" style="margin-top:14px;margin-bottom:16px;">
                <div class="inline" style="margin-bottom:10px;">
                    <span class="hero-badge">إدارة المستخدمين</span>
                    <span class="hero-badge">توثيق + تثبيت + تقييم</span>
                </div>
                <h2>لوحة الأدمن</h2>
                <div class="section-subtitle">واجهة أقوى لعرض الإحصائيات والمستخدمين وسجل العمليات الأخيرة بشكل أنظف.</div>
            </div>

            <div class="admin-stats-grid">
                <div class="admin-stat"><div class="label">عدد المستخدمين</div><div class="value">{users_count}</div></div>
                <div class="admin-stat"><div class="label">الحسابات المفعلة</div><div class="value">{verified_count}</div></div>
                <div class="admin-stat"><div class="label">العمال الموثوقون</div><div class="value">{trusted_count}</div></div>
                <div class="admin-stat"><div class="label">المثبتون</div><div class="value">{pinned_count}</div></div>
            </div>

            <div class="admin-stats-grid" style="margin-top:14px;">
                <div class="admin-stat"><div class="label">عدد الرسائل</div><div class="value">{messages_count}</div></div>
                <div class="admin-stat"><div class="label">عدد التعليقات</div><div class="value">{comments_count}</div></div>
                <div class="admin-stat"><div class="label">خريطة العمال</div><div class="value">جاهزة</div></div>
                <div class="admin-stat"><div class="label">البحث الاحترافي</div><div class="value">مفعل</div></div>
            </div>

            <div class="admin-search-box" style="margin-bottom:16px;">
                <h3 style="margin-bottom:8px;">بحث داخل لوحة الأدمن</h3>
                <form method="get" action="/admin/panel">
                    <div class="search-inline-grid">
                        <div>
                            <label>بحث بالاسم أو الهاتف أو الإيميل</label>
                            <input name="q" value="{admin_q}" placeholder="اكتب اسم المستخدم أو الهاتف أو البريد">
                        </div>
                        <div>
                            <label>&nbsp;</label>
                            <button>بحث</button>
                        </div>
                    </div>
                </form>
            </div>

            <h3>المستخدمون</h3>
            <div class="admin-users-grid">
                {users_html if users_html else '<div class="empty-state">لا يوجد مستخدمون</div>'}
            </div>

            <h3 style="margin-top:22px;">سجل الأدمن</h3>
            {logs_html}
        </div>
        </body></html>
        """
    )



@app.route("/admin/verify-worker/<int:user_id>")
def admin_verify_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET verified_worker=1 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("توثيق عامل", user["name"], f"تم توثيق المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/unverify-worker/<int:user_id>")
def admin_unverify_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET verified_worker=0 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("إلغاء توثيق عامل", user["name"], f"تم إلغاء توثيق المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/pin-worker/<int:user_id>")
def admin_pin_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET is_pinned=1 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("تثبيت عامل", user["name"], f"تم تثبيت المستخدم رقم {user_id} بالأعلى")
    return redirect(url_for("admin_panel"))


@app.route("/admin/unpin-worker/<int:user_id>")
def admin_unpin_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET is_pinned=0 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("إلغاء تثبيت عامل", user["name"], f"تم إلغاء تثبيت المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/workers-map")
def workers_map():
    with get_db() as con:
        workers = con.execute("""
            SELECT * FROM users
            WHERE is_verified=1 AND (role='worker' OR role IS NULL)
            ORDER BY is_pinned DESC, views DESC, id DESC
        """).fetchall()

    markers = []
    list_html = ""
    for w in workers:
        avg_rating, rating_count = get_worker_rating_summary(w["id"])
        lat, lng = governorate_coords(w["governorate"])
        popup = f"""
        <div style='min-width:190px;text-align:right;direction:rtl;line-height:1.7'>
            <div style='font-weight:700;font-size:15px;color:#0f172a'>⭐ {avg_rating} / 5</div>
            <div style='font-weight:800;font-size:16px;margin-top:2px;color:#111827'>{w["name"]}</div>
            <div style='font-size:13px;color:#334155'>{w["section"] or "-"}</div>
            <div style='font-size:13px;color:#475569'>📍 {w["city"] or "-"} - {w["governorate"] or "-"}</div>
        </div>
        """
        markers.append({
            "lat": lat,
            "lng": lng,
            "popup": popup,
            "link": f"/worker/{w['id']}"
        })
        list_html += f"""
        <div class="card" style="margin-bottom:10px;">
            <div class="inline" style="margin-bottom:8px;">
                <span class="worker-specialty-badge">{get_specialty_icon(w["section"])} {w["section"] or "-"}</span>
                <span class="badge">{w["governorate"] or "-"}</span>
                {trusted_badge_html(w)}
                {pinned_badge_html(w)}
            </div>
            <div class="worker-rating-line" style="margin-bottom:8px;">
                <span class="badge">⭐ {avg_rating} / 5</span>
                <span class="rating-stars">{render_stars(avg_rating)}</span>
                <span class="badge">👁 {w["views"] or 0}</span>
            </div>
            <h3>{w["name"]}</h3>
            <div class="small">📍 {w["city"] or "-"} - {w["governorate"] or "-"}</div>
            <div class="inline" style="margin-top:10px;">
                <a class="link-btn" href="/worker/{w['id']}">فتح الملف</a>
                <a class="link-btn map-link-btn" target="_blank" href="{worker_map_link(w)}">خرائط Google</a>
            </div>
        </div>
        """

    markers_json = json.dumps(markers, ensure_ascii=False)

    return render_template_string(
        STYLE + f"""
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
        <div class="container">
            <div class="topbar">
                <div><a href="/workers"><button class="light-btn">رجوع للعمال</button></a></div>
                <div class="inline"><span class="badge">خريطة العمال</span></div>
            </div>
            <div class="hero-panel" style="margin-bottom:16px;">
                <h2>خريطة العمال</h2>
                <div class="section-subtitle">عرض تقريبي لمواقع العمال حسب المحافظة ليسهل الوصول السريع لهم.</div>
            </div>

            <div class="map-page-grid">
                <div id="workersMap"></div>
                <div class="map-list-card">{list_html if list_html else '<div class="msg">لا يوجد عمال لعرضهم على الخريطة</div>'}</div>
            </div>
        </div>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <script>
        const markers = {markers_json};
        const map = L.map('workersMap').setView([33.3152, 44.3661], 6);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 18,
            attribution: '&copy; OpenStreetMap'
        }}).addTo(map);

        markers.forEach(function(item) {{
            const marker = L.marker([item.lat, item.lng]).addTo(map);
            marker.bindPopup(item.popup + '<div style="margin-top:8px"><a href="' + item.link + '">فتح الملف</a></div>');
        }});
        </script>
        </body></html>
        """
    )





@app.route("/admin/block-user/<int:user_id>")
def admin_block_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET is_blocked=1 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("حظر مستخدم", user["name"], f"تم حظر المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/unblock-user/<int:user_id>")
def admin_unblock_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET is_blocked=0 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("فك حظر", user["name"], f"تم فك حظر المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/hide-user/<int:user_id>")
def admin_hide_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET hidden_by_admin=1 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("إخفاء ملف", user["name"], f"تم إخفاء ملف المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))


@app.route("/admin/unhide-user/<int:user_id>")
def admin_unhide_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            con.execute("UPDATE users SET hidden_by_admin=0 WHERE id=?", (user_id,))
            con.commit()
            log_admin_action("إظهار ملف", user["name"], f"تم إظهار ملف المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))



@app.route("/admin/messages")
def admin_messages():
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        rows = con.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 300").fetchall()

    if not rows:
        messages_html = '<div class="msg">لا توجد رسائل</div>'
    else:
        blocks = []
        for row in rows:
            blocks.append(f"""
            <div class="card">
                <div><strong>من:</strong> {row["sender_name"]} <strong>إلى:</strong> {row["receiver_name"]}</div>
                <div style="margin-top:8px;">{row["msg"]}</div>
                <div class="small">{row["created_at"]}</div>
                <div style="margin-top:10px;">
                    <a class="link-btn link-red" href="/admin/delete-message/{row['id']}">حذف الرسالة</a>
                </div>
            </div>
            """)
        messages_html = "".join(blocks)

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <a href="/admin/panel"><button>رجوع للوحة الأدمن</button></a>
            <h2>كل الرسائل</h2>
            <div class="section-subtitle">هنا يقدر الأدمن يراجع آخر الرسائل ويحذف أي رسالة غير مناسبة.</div>
            {messages_html}
        </div>
        </body></html>
        """
    )


@app.route("/admin/delete-message/<int:message_id>")
def admin_delete_message(message_id):
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        row = con.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
        if row:
            con.execute("DELETE FROM messages WHERE id=?", (message_id,))
            con.commit()
            log_admin_action("حذف رسالة", row["sender_name"], f"تم حذف الرسالة رقم {message_id}")

    return redirect(url_for("admin_messages"))


@app.route("/admin/comments")
def admin_comments():
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        rows = con.execute("""
            SELECT comments.*, users.name AS worker_name
            FROM comments
            LEFT JOIN users ON users.id = comments.user_id
            ORDER BY comments.id DESC
            LIMIT 300
        """).fetchall()

    if not rows:
        comments_html = '<div class="msg">لا توجد تعليقات</div>'
    else:
        blocks = []
        for row in rows:
            stars = "★" * int(row["rating"] or 0) + "☆" * (5 - int(row["rating"] or 0))
            blocks.append(f"""
            <div class="card">
                <div><strong>{row["commenter_name"]}</strong> على <strong>{row["worker_name"] or "-"}</strong></div>
                <div class="star">{stars}</div>
                <div>{row["comment"]}</div>
                <div class="small">{row["created_at"]}</div>
                <div style="margin-top:10px;">
                    <a class="link-btn link-red" href="/admin/delete-comment/{row['id']}">حذف التعليق</a>
                </div>
            </div>
            """)
        comments_html = "".join(blocks)

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <a href="/admin/panel"><button>رجوع للوحة الأدمن</button></a>
            <h2>كل التعليقات</h2>
            <div class="section-subtitle">هنا يقدر الأدمن يراجع كل التعليقات ويحذف أي تعليق غير مناسب.</div>
            {comments_html}
        </div>
        </body></html>
        """
    )


@app.route("/admin/delete-comment/<int:comment_id>")
def admin_delete_comment(comment_id):
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        row = con.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
        if row:
            con.execute("DELETE FROM comments WHERE id=?", (comment_id,))
            con.commit()
            log_admin_action("حذف تعليق", row["commenter_name"], f"تم حذف التعليق رقم {comment_id}")

    return redirect(url_for("admin_comments"))


@app.route("/admin/edit-user/<int:user_id>", methods=["GET","POST"])
def admin_edit_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not user:
        return render_template_string(STYLE + '<div class="container"><div class="msg">المستخدم غير موجود</div><a href="/admin/panel"><button>رجوع</button></a></div></body></html>')

    if request.method == "POST":
        name = request.form.get("name","")
        phone = request.form.get("phone","")
        section = request.form.get("section","")
        governorate = request.form.get("governorate","")
        city = request.form.get("city","")
        bio = request.form.get("bio","")

        with get_db() as con:
            con.execute(
                "UPDATE users SET name=?, phone=?, section=?, governorate=?, city=?, bio=? WHERE id=?",
                (name, phone, section, governorate, city, bio, user_id)
            )
            con.commit()

        return redirect(url_for("admin_panel"))

    return render_template_string(
        STYLE + f'''
        <div class="container">
            <a href="/admin/panel"><button>رجوع للوحة الأدمن</button></a>
            <h2>تعديل بيانات المستخدم</h2>

            <form method="post">
                <label>الاسم</label>
                <input name="name" value="{user["name"] or ""}">

                <label>الهاتف</label>
                <input name="phone" value="{user["phone"] or ""}">

                <label>الاختصاص</label>
                <input name="section" value="{user["section"] or ""}">

                <label>المحافظة</label>
                <input name="governorate" value="{user["governorate"] or ""}">

                <label>المدينة</label>
                <input name="city" value="{user["city"] or ""}">

                <label>نبذة</label>
                <textarea name="bio">{user["bio"] or ""}</textarea>

                <button type="submit">حفظ التعديلات</button>
            </form>
        </div>
        </body></html>
        '''
    )
@app.route("/admin/delete-user/<int:user_id>")
def admin_delete_user(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not user:
        return render_template_string(STYLE + '<div class="container"><div class="msg">المستخدم غير موجود</div><a href="/admin/panel"><button>رجوع</button></a></div></body></html>')

    if user["profile_pic"]:
        delete_file_if_exists(user["profile_pic"])
    if user["work_images"]:
        for img in [x.strip() for x in user["work_images"].split(",") if x.strip()]:
            delete_file_if_exists(img)

    with get_db() as con:
        con.execute("DELETE FROM messages WHERE sender_name=? OR receiver_name=?", (user["name"], user["name"]))
        con.execute("DELETE FROM comments WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.commit()

    log_admin_action("حذف مستخدم", user["name"], f"تم حذف المستخدم رقم {user_id}")
    return redirect(url_for("admin_panel"))




@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings_page():
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        admin = con.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()

    if not admin:
        return render_template_string(STYLE + '<div class="container"><div class="msg">تعذر تحميل بيانات الأدمن</div><a href="/admin/panel"><button>رجوع</button></a></div></body></html>')

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_username = sanitize_input(request.form.get("new_username", ""), 50)
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not check_password_hash(admin["password"], current_password):
            return render_template_string(STYLE + '<div class="container narrow-container"><div class="msg">كلمة المرور الحالية غير صحيحة</div><a href="/admin/settings"><button>رجوع</button></a></div></body></html>')

        if not new_username:
            return render_template_string(STYLE + '<div class="container narrow-container"><div class="msg">اسم المستخدم الجديد مطلوب</div><a href="/admin/settings"><button>رجوع</button></a></div></body></html>')

        update_password_hash = admin["password"]
        password_changed = False
        if new_password or confirm_password:
            if not valid_password(new_password):
                return render_template_string(STYLE + '<div class="container narrow-container"><div class="msg">كلمة المرور الجديدة قصيرة</div><a href="/admin/settings"><button>رجوع</button></a></div></body></html>')

            if new_password != confirm_password:
                return render_template_string(STYLE + '<div class="container narrow-container"><div class="msg">تأكيد كلمة المرور غير مطابق</div><a href="/admin/settings"><button>رجوع</button></a></div></body></html>')

            update_password_hash = generate_password_hash(new_password)
            password_changed = True

        with get_db() as con:
            con.execute(
                "UPDATE admin_settings SET username=?, password=? WHERE id=1",
                (new_username, update_password_hash)
            )
            con.commit()

        old_username = admin["username"]
        session["admin"] = new_username
        details = "تم تحديث اسم المستخدم"
        if password_changed:
            details += " وكلمة المرور"
        log_admin_action("تعديل بيانات الأدمن", new_username, f"{details} من {old_username} إلى {new_username}")

        return render_template_string(STYLE + '<div class="container narrow-container"><div class="msg">تم تحديث بيانات الأدمن بنجاح</div><a href="/admin/panel"><button>الرجوع للوحة الأدمن</button></a></div></body></html>')

    return render_template_string(
        STYLE + f"""
        <div class="container narrow-container">
            <a href="/admin/panel"><button class="light-btn">رجوع للوحة الأدمن</button></a>
            <h2>إعدادات الأدمن</h2>
            <div class="msg">من هنا يقدر الأدمن يغيّر اسم المستخدم وكلمة المرور من صفحته.</div>
            <form method="post">
                <label>اسم المستخدم الجديد</label>
                <input name="new_username" value="{admin['username'] or ''}" placeholder="اسم المستخدم الجديد" required>

                <label>كلمة المرور الحالية</label>
                <input type="password" name="current_password" placeholder="كلمة المرور الحالية" required>

                <label>كلمة المرور الجديدة</label>
                <input type="password" name="new_password" placeholder="اتركها فارغة إذا ما تريد تغيرها">

                <label>تأكيد كلمة المرور الجديدة</label>
                <input type="password" name="confirm_password" placeholder="أعد كتابة كلمة المرور الجديدة">

                <button>حفظ بيانات الأدمن</button>
            </form>
        </div>
        </body></html>
        """
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


@app.route("/delete-account", methods=["GET", "POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_text = request.form.get("confirm_text", "").strip()

        if not check_password_hash(user["password"], password):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + """<div class="container"><div class="msg">كلمة المرور غير صحيحة</div><a href="/delete-account"><button>رجوع</button></a></div></body></html>""")

        if confirm_text != "احذف حسابي":
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + """<div class="container"><div class="msg">اكتب العبارة المطلوبة بشكل صحيح: احذف حسابي</div><a href="/delete-account"><button>رجوع</button></a></div></body></html>""")

        if user["profile_pic"]:
            delete_file_if_exists(user["profile_pic"])
        if user["work_images"]:
            for img in [x.strip() for x in user["work_images"].split(",") if x.strip()]:
                delete_file_if_exists(img)

        with get_db() as con:
            con.execute("DELETE FROM messages WHERE sender_name=? OR receiver_name=?", (user["name"], user["name"]))
            con.execute("DELETE FROM comments WHERE user_id=?", (user["id"],))
            con.execute("DELETE FROM users WHERE id=?", (user["id"],))
            con.commit()

        session.clear()
        return render_template_string(STYLE + """<div class="container"><div class="msg">تم حذف الحساب نهائياً</div><a href="/"><button>الصفحة الرئيسية</button></a></div></body></html>""")

    return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + """<div class="container"><a href="/settings"><button>رجوع</button></a><h2>حذف الحساب</h2><div class="msg">هذه العملية نهائية. اكتب كلمة المرور الحالية، ثم اكتب العبارة: احذف حسابي</div><form method="post"><input type="password" name="password" placeholder="كلمة المرور الحالية" required><input name="confirm_text" placeholder="اكتب هنا: احذف حسابي" required><button style="background:red;color:white;">تأكيد حذف الحساب</button></form></div></body></html>""")



@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("role") == "visitor":
        return redirect(url_for("visitor_account"))

    user = get_current_session_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    avg_rating, rating_count = get_worker_rating_summary(user["id"])
    stars = render_stars(avg_rating)

    profile_html = (
        f'<img src="{url_for("uploaded_file", filename=user["profile_pic"])}" class="profile-img-large" alt="profile">'
        if user["profile_pic"]
        else '<div class="profile-placeholder-large">👤</div>'
    )

    imgs = [x.strip() for x in (user["work_images"] or "").split(",") if x.strip()]
    work_images_html = ""
    if imgs:
        work_images_html = '<div class="work-grid">' + "".join(
            f'<img src="{url_for("uploaded_file", filename=img)}" alt="work">' for img in imgs
        ) + '</div>'

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <div class="topbar">
                <a href="/settings"><button class="light-btn">الإعدادات</button></a>
                <a href="/edit-profile"><button>تعديل الملف الشخصي</button></a>
            </div>

            <div class="worker-hero">
                <div class="worker-hero-grid">
                    <div class="center">{profile_html}</div>
                    <div>
                        <div class="inline" style="margin-bottom:10px;">
                            <span class="worker-specialty-badge">{get_specialty_icon(user["section"])} {user["section"] or "-"}</span>
                            <span class="badge">{user["governorate"] or "-"}</span>
                            <span class="badge">⭐ {avg_rating} / 5</span>
                            <span class="badge">{rating_count} تقييم</span>
                        </div>
                        <h2>{user["name"]}</h2>
                        <div class="worker-rating-line">
                            <span class="rating-stars">{stars}</span>
                        </div>
                        <div class="section-subtitle">هذه صفحتك الشخصية داخل التطبيق.</div>
                        <div style="margin-top:10px;">{user["bio"] or "لا توجد نبذة حالياً"}</div>

                        <div class="detail-grid">
                            <div class="detail-box"><strong>الهاتف</strong>{user["phone"] or "-"}</div>
                            <div class="detail-box"><strong>البريد الإلكتروني</strong>{user["email"] or "-"}</div>
                            <div class="detail-box"><strong>المدينة</strong>{user["city"] or "-"}</div>
                            <div class="detail-box"><strong>الخبرة</strong>{user["exp"] or "-"}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>أعمالي</h3>
                <div class="section-subtitle">الصور المرفوعة داخل ملفك الشخصي.</div>
                {work_images_html if work_images_html else f'<div class="empty-state">لا توجد أعمال حتى الآن</div>'}
            </div>
        </div>
        </body></html>
        """
    )


@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))

    user = get_current_session_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if session.get("role") == "visitor":
        buttons_html = """
            <a href="/visitor/account"><button>حساب الزائر</button></a>
            <a href="/visitor/edit-profile"><button class="light-btn">تعديل الحساب</button></a>
            <a href="/inbox"><button class="light-btn">الرسائل</button></a>
            <a href="/support"><button class="light-btn">الدعم الفني</button></a>
            <a href="/workers"><button class="light-btn">تصفح الاختصاصات</button></a>
            <a href="/change-password"><button class="light-btn">تغيير كلمة المرور</button></a>
            <a href="/logout"><button>تسجيل الخروج</button></a>
        """
    else:
        buttons_html = """
            <a href="/profile"><button>ملفي الشخصي</button></a>
            <a href="/edit-profile"><button class="light-btn">تعديل الملف الشخصي</button></a>
            <a href="/inbox"><button class="light-btn">الرسائل</button></a>
            <a href="/support"><button class="light-btn">الدعم الفني</button></a>
            <a href="/workers"><button class="light-btn">الاختصاصات</button></a>
            <a href="/change-password"><button class="light-btn">تغيير كلمة المرور</button></a>
            <a href="/logout"><button>تسجيل الخروج</button></a>
        """

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container">
            <h2>الإعدادات</h2>
            <div class="section-subtitle">اختر الصفحة التي تريدها.</div>

            <div class="card">
                {buttons_html}
            </div>
        </div>
        </body></html>
        """
    )


@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user" not in session:
        return redirect(url_for("login"))
    if session.get("role") == "visitor":
        return redirect(url_for("visitor_edit_profile"))

    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE name=?", (session["user"],)).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""), 80)
        phone = normalize_iraq_phone(sanitize_input(request.form.get("phone", ""), 25))
        email = sanitize_input(request.form.get("email", ""), 120).lower()
        section = sanitize_input(request.form.get("section", ""), 80)
        governorate = sanitize_input(request.form.get("governorate", ""), 80)
        city = sanitize_input(request.form.get("city", ""), 80)
        exp = sanitize_input(request.form.get("exp", ""), 30)
        bio = sanitize_input(request.form.get("bio", ""), 500)

        if not name or not phone or not email:
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container">
                    <div class="msg">الاسم والهاتف والبريد الإلكتروني حقول مطلوبة</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        if not valid_email(email):
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container">
                    <div class="msg">البريد الإلكتروني غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        if not valid_phone(phone):
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container">
                    <div class="msg">رقم الهاتف غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        if governorate and governorate not in IRAQ_GOVERNORATES:
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container">
                    <div class="msg">المحافظة غير صحيحة</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        if section and section not in SPECIALTIES:
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container">
                    <div class="msg">الاختصاص غير صحيح</div>
                    <a href="/edit-profile"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        with get_db() as con:
            cur = con.cursor()
            exists = cur.execute(
                "SELECT id FROM users WHERE (phone=? OR email=?) AND id != ?",
                (phone, email, user["id"])
            ).fetchone()

            if exists:
                return render_template_string(
                    STYLE + (settings_corner() if 'user' in session else '') + """
                    <div class="container">
                        <div class="msg">رقم الهاتف أو البريد الإلكتروني مستخدم من حساب آخر</div>
                        <a href="/edit-profile"><button>رجوع</button></a>
                    </div>
                    </body></html>
                    """
                )

            new_profile_pic = user["profile_pic"]
            profile_file = request.files.get("profile_pic")

            if profile_file and profile_file.filename:
                valid_img, msg = validate_uploaded_image(profile_file)
                if not valid_img:
                    return render_template_string(
                        STYLE + (settings_corner() if 'user' in session else '') + f"""
                        <div class="container">
                            <div class="msg">{msg}</div>
                            <a href="/edit-profile"><button>رجوع</button></a>
                        </div>
                        </body></html>
                        """
                    )

                saved_profile = save_uploaded_file(profile_file)
                if saved_profile:
                    if user["profile_pic"]:
                        delete_file_if_exists(user["profile_pic"])
                    new_profile_pic = saved_profile

            cur.execute(
                "UPDATE users SET name=?, phone=?, email=?, section=?, governorate=?, city=?, exp=?, bio=?, profile_pic=? WHERE id=?",
                (name, phone, email, section, governorate, city, exp, bio, new_profile_pic, user["id"])
            )
            con.commit()

        session["user"] = name
        return render_template_string(
            STYLE + (settings_corner() if 'user' in session else '') + """
            <div class="container">
                <div class="msg">تم تحديث البروفايل بنجاح</div>
                <a href="/settings"><button>الرجوع للإعدادات</button></a>
            </div>
            </body></html>
            """
        )

    profile_preview = (
        f'<img src="{url_for("uploaded_file", filename=user["profile_pic"])}" class="profile-img-large" alt="profile">'
        if user["profile_pic"]
        else '<div class="profile-placeholder-large">👤</div>'
    )

    selected_group = get_main_group_by_specialty(user["section"] or "")
    group_options = build_main_groups_options(selected_group)
    gov_options = build_governorates_options(user["governorate"] or "")
    specialty_options = build_specialties_options(user["section"] or "", selected_group)

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/settings"><button>رجوع</button></a>
            <h2>تعديل البروفايل</h2>
            {profile_preview}
            <form method="post" enctype="multipart/form-data">
                <input name="name" value="{user['name'] or ''}" placeholder="الاسم الكامل" required>
                <input name="phone" value="{user['phone'] or ''}" placeholder="07XXXXXXXXX" required>
                <input name="email" value="{user['email'] or ''}" placeholder="البريد الإلكتروني" required>

                <label>القسم الرئيسي</label>
                <select name="main_group" id="main_group" onchange="updateSpecialties()">
                    <option value="">اختر القسم الرئيسي</option>
                    {group_options}
                </select>

                <label>الاختصاص</label>
                <select name="section" id="section">{specialty_options}</select>

                <label>المحافظة</label>
                <select name="governorate" required>
                    <option value="">اختر المحافظة</option>
                    {gov_options}
                </select>

                <input name="city" value="{user['city'] or ''}" placeholder="المدينة / المنطقة">
                <input name="exp" value="{user['exp'] or ''}" placeholder="سنوات الخبرة">
                <textarea name="bio" placeholder="نبذة عنك">{user['bio'] or ''}</textarea>

                <label>تغيير الصورة الشخصية</label>
                <input type="file" name="profile_pic" accept=".png,.jpg,.jpeg,.gif,.webp">

                <button>حفظ التعديلات</button>
            </form>

            <a href="/change-password"><button>تغيير كلمة المرور</button></a>
            <a href="/manage-work-images/{user['id']}"><button>إدارة أعمالي</button></a>
            <a href="/delete-account"><button style="background:red;color:white;">حذف الحساب</button></a>
        </div>
        {specialty_script(user['section'] or '')}
        </body></html>
        """
    )



@app.route("/passkey/setup")
def passkey_setup():
    if "user" not in session:
        return redirect(url_for("login"))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    if not passkeys_supported():
        return render_template_string(
            STYLE + """
            <div class="container">
                <a href="/settings"><button>رجوع</button></a>
                <h2>الدخول بالبصمة</h2>
                <div class="msg">ميزة البصمة غير مفعلة حالياً على السيرفر. ثبّت مكتبة webauthn أولاً.</div>
            </div>
            </body></html>
            """
        )

    return render_template_string(
        STYLE + """
        <div class="container narrow-container">
            <a href="/settings"><button>رجوع</button></a>
            <h2>تفعيل الدخول بالبصمة</h2>
            <div class="msg">بعد التفعيل، تقدر تدخل بالبصمة أو قفل الجهاز المحفوظ على هاتفك.</div>
            <button id="setupPasskeyBtn" type="button">تفعيل البصمة على هذا الجهاز</button>
            <div id="passkeySetupMsg" class="notice" style="margin-top:12px;"></div>
        </div>

        <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
        <script>
        async function setupPasskey() {
            const msg = document.getElementById("passkeySetupMsg");
            try {
                msg.textContent = "جاري تجهيز طلب البصمة...";
                const beginResp = await fetch("/passkey/register/begin", {method: "POST"});
                const beginText = await beginResp.text();
                let beginData = {};
                try { beginData = JSON.parse(beginText); } catch(e) { throw new Error("السيرفر لم يرجع JSON صحيح عند بدء التفعيل"); }
                if (!beginResp.ok) {
                    msg.textContent = beginData.error || "تعذر بدء التفعيل";
                    return;
                }

                const credential = await SimpleWebAuthnBrowser.startRegistration({optionsJSON: beginData});
                const finishResp = await fetch("/passkey/register/finish", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify(credential),
                });
                const finishText = await finishResp.text();
                let finishData = {};
                try { finishData = JSON.parse(finishText); } catch(e) { throw new Error("السيرفر لم يرجع JSON صحيح عند إنهاء التفعيل"); }
                msg.textContent = finishData.message || "تمت العملية";
            } catch (err) {
                msg.textContent = "فشل التفعيل: " + (err.message || err);
            }
        }
        document.getElementById("setupPasskeyBtn").addEventListener("click", setupPasskey);
        </script>
        </body></html>
        """
    )


@app.route("/passkey/login")
def passkey_login():
    return render_template_string(
        STYLE + """
        <div class="container narrow-container">
            <a href="/login"><button>رجوع</button></a>
            <h2>الدخول بالبصمة</h2>
            <div class="section-subtitle">ضع بصمتك فقط، وإذا كانت البصمة مفعلة على هذا الجهاز سيدخل الحساب مباشرة بدون كتابة البريد الإلكتروني.</div>
            <button id="passkeyLoginBtn" type="button">الدخول بالبصمة</button>
            <div id="passkeyLoginMsg" class="notice" style="margin-top:12px;"></div>
        </div>

        <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
        <script>
        async function loginPasskey() {
            const msg = document.getElementById("passkeyLoginMsg");
            try {
                msg.textContent = "جاري تجهيز طلب الدخول...";
                const beginResp = await fetch("/passkey/auth/begin", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({}),
                });
                const beginText = await beginResp.text();
                let beginData = {};
                try { beginData = JSON.parse(beginText); } catch(e) { throw new Error("السيرفر لم يرجع JSON صحيح"); }

                if (!beginResp.ok) {
                    msg.textContent = beginData.error || "تعذر بدء الدخول";
                    return;
                }

                const assertion = await SimpleWebAuthnBrowser.startAuthentication({optionsJSON: beginData});
                const finishResp = await fetch("/passkey/auth/finish", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({credential: assertion}),
                });
                const finishText = await finishResp.text();
                let finishData = {};
                try { finishData = JSON.parse(finishText); } catch(e) { throw new Error("السيرفر لم يرجع JSON صحيح"); }

                if (finishData.ok) {
                    window.location.href = finishData.redirect || "/workers";
                } else {
                    msg.textContent = finishData.error || "فشل الدخول بالبصمة";
                }
            } catch (err) {
                msg.textContent = "فشل الدخول: " + (err.message || err);
            }
        }
        document.getElementById("passkeyLoginBtn").addEventListener("click", loginPasskey);
        </script>
        </body></html>
        """
    )

@app.route("/passkey/register/begin", methods=["POST"])
def passkey_register_begin():
    if "user" not in session:
        return jsonify({"error": "يجب تسجيل الدخول أولاً"}), 401
    if not passkeys_supported():
        return jsonify({"error": "مكتبة WebAuthn غير مثبتة على السيرفر"}), 400

    try:
        user = get_current_session_user()
        if not user:
            return jsonify({"error": "تعذر تحديد المستخدم الحالي"}), 401

        with get_db() as con:
            existing = con.execute("SELECT credential_id FROM user_passkeys WHERE user_id=?", (user["id"],)).fetchall()

        exclude_credentials = []
        for row in existing:
            cid = row["credential_id"]
            if cid:
                exclude_credentials.append(PublicKeyCredentialDescriptor(id=b64url_decode_to_bytes(cid)))

        options = generate_registration_options(
            rp_id=get_rp_id(),
            rp_name="المسطر",
            user_id=str(user["id"]).encode("utf-8"),
            user_name=user["email"],
            user_display_name=user["name"],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=exclude_credentials,
        )

        session["passkey_reg_challenge"] = b64url_encode_bytes(options.challenge)
        return jsonify(json.loads(options_to_json(options)))
    except Exception as e:
        return jsonify({"error": "تعذر بدء التفعيل: " + str(e)}), 500


@app.route("/passkey/register/finish", methods=["POST"])
def passkey_register_finish():
    if "user" not in session:
        return jsonify({"message": "يجب تسجيل الدخول أولاً"}), 401
    if not passkeys_supported():
        return jsonify({"message": "WebAuthn غير مفعل"}), 400

    credential = request.get_json(silent=True) or {}
    challenge_b64 = session.get("passkey_reg_challenge")
    if not challenge_b64:
        return jsonify({"message": "انتهت جلسة التفعيل"}), 400

    user = get_current_session_user()
    if not user:
        return jsonify({"message": "تعذر تحديد المستخدم الحالي"}), 401

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_origin=get_origin(),
            expected_rp_id=get_rp_id(),
            require_user_verification=True,
        )
        with get_db() as con:
            con.execute(
                "INSERT OR REPLACE INTO user_passkeys (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)",
                (
                    user["id"],
                    b64url_encode_bytes(verification.credential_id),
                    b64url_encode_bytes(verification.credential_public_key),
                    int(verification.sign_count or 0),
                ),
            )
            con.commit()
        session.pop("passkey_reg_challenge", None)
        return jsonify({"message": "تم تفعيل الدخول بالبصمة بنجاح"})
    except Exception as e:
        return jsonify({"message": "فشل التفعيل: " + str(e)}), 400


@app.route("/passkey/auth/begin", methods=["POST"])
def passkey_auth_begin():
    if not passkeys_supported():
        return jsonify({"error": "مكتبة WebAuthn غير مثبتة على السيرفر"}), 400

    with get_db() as con:
        count_row = con.execute("SELECT COUNT(*) AS c FROM user_passkeys").fetchone()

    if not count_row or int(count_row["c"] or 0) == 0:
        return jsonify({"error": "لا توجد أي بصمة مفعلة حتى الآن"}), 400

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    session["passkey_auth_challenge"] = b64url_encode_bytes(options.challenge)
    return jsonify(json.loads(options_to_json(options)))

@app.route("/passkey/auth/finish", methods=["POST"])
def passkey_auth_finish():
    if not passkeys_supported():
        return jsonify({"ok": False, "error": "WebAuthn غير مفعل"}), 400

    data = request.get_json(silent=True) or {}
    credential = data.get("credential") or {}
    challenge_b64 = session.get("passkey_auth_challenge")

    if not challenge_b64:
        return jsonify({"ok": False, "error": "انتهت جلسة الدخول بالبصمة"}), 400

    cred_id = credential.get("id") or credential.get("rawId") or ""
    if not cred_id:
        return jsonify({"ok": False, "error": "معرّف البصمة غير موجود"}), 400

    with get_db() as con:
        row = con.execute("SELECT * FROM user_passkeys WHERE credential_id=?", (cred_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "هذه البصمة غير مرتبطة بأي حساب"}), 404

        user = con.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        if not user:
            return jsonify({"ok": False, "error": "الحساب المرتبط بالبصمة غير موجود"}), 404

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=get_rp_id(),
            expected_origin=get_origin(),
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"] or 0),
            require_user_verification=True,
        )

        with get_db() as con:
            con.execute(
                "UPDATE user_passkeys SET sign_count=? WHERE id=?",
                (int(verification.new_sign_count or 0), row["id"]),
            )
            con.commit()

        session.permanent = True
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        resp = jsonify({"ok": True, "redirect": url_for("workers")})
        resp.set_cookie("remember_email", user["email"], max_age=60*60*24*30)
        session.pop("passkey_auth_challenge", None)
        session.pop("passkey_auth_email", None)
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": "فشل التحقق من البصمة: " + str(e)}), 400


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
