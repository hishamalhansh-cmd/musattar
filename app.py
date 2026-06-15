import os
import re
import sqlite3

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except Exception:
    psycopg2 = None
    PSYCOPG2_AVAILABLE = False
import random
import smtplib
import uuid
import json
import base64
import datetime
import secrets
import time
import urllib.request
import urllib.error
from io import BytesIO
from urllib.parse import quote

from flask import Flask, render_template_string, request, redirect, session, url_for, send_from_directory, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    Image = None
    PIL_AVAILABLE = False


try:
    import cloudinary
    import cloudinary.uploader
    CLOUDINARY_SDK_AVAILABLE = True
except Exception:
    cloudinary = None
    CLOUDINARY_SDK_AVAILABLE = False
# For PostgreSQL on Render free plan, install psycopg2-binary in requirements.txt

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
app.permanent_session_lifetime = timedelta(days=180)
PERSISTENT_LOGIN_DAYS = 180


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

# OneSignal Push Notifications (optional; disabled until env vars are set)
ONESIGNAL_APP_ID = os.environ.get("ONESIGNAL_APP_ID", "").strip()
ONESIGNAL_REST_API_KEY = (os.environ.get("ONESIGNAL_REST_API_KEY", "").strip() or os.environ.get("ONESIGNAL_API_KEY", "").strip())
ONESIGNAL_ADMIN_SUBSCRIPTION_IDS = os.environ.get("ONESIGNAL_ADMIN_SUBSCRIPTION_IDS", "").strip()

CONTACT_PHONE = "+9647864145165"
CONTACT_EMAIL = "hishamalhansh@gmail.com"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
APP_DATA_DIR = os.environ.get("APP_DATA_DIR", "").strip() or os.environ.get("RENDER_DISK_PATH", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_PATH = os.path.join(APP_DATA_DIR or BASE_DIR, "database.db")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "").strip() or os.path.join(APP_DATA_DIR or BASE_DIR, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL", "").strip()
CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME", "").strip()
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY", "").strip()
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET", "").strip()
CLOUDINARY_UPLOAD_FOLDER = os.environ.get("CLOUDINARY_UPLOAD_FOLDER", "musattar").strip() or "musattar"
CLOUDINARY_ENABLED = bool(CLOUDINARY_SDK_AVAILABLE and (CLOUDINARY_URL or (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET)))
if CLOUDINARY_ENABLED:
    if CLOUDINARY_URL:
        cloudinary.config(cloudinary_url=CLOUDINARY_URL, secure=True)
    else:
        cloudinary.config(
            cloud_name=CLOUDINARY_CLOUD_NAME,
            api_key=CLOUDINARY_API_KEY,
            api_secret=CLOUDINARY_API_SECRET,
            secure=True,
        )

APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "production")).strip().lower()
USING_POSTGRES = bool(DATABASE_URL and PSYCOPG2_AVAILABLE)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_ENV == "production"
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # 30MB request cap
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=180)

DEFAULT_SECRET_KEY = "adam_secret_key_2026"
app.secret_key = os.environ.get("SECRET_KEY", DEFAULT_SECRET_KEY)
if APP_ENV == "production" and app.secret_key == DEFAULT_SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set in production environment")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    csp = "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data: blob:; media-src 'self' https: data: blob:;"
    response.headers.setdefault("Content-Security-Policy", csp)
    return response

DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)
DB_OPERATIONAL_ERRORS = (sqlite3.OperationalError,)
if PSYCOPG2_AVAILABLE:
    DB_INTEGRITY_ERRORS = DB_INTEGRITY_ERRORS + (psycopg2.IntegrityError,)
    DB_OPERATIONAL_ERRORS = DB_OPERATIONAL_ERRORS + (psycopg2.OperationalError,)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_SINGLE_FILE_SIZE = 5 * 1024 * 1024
MAX_SUPPORT_MEDIA_SIZE = 20 * 1024 * 1024
MAX_WORK_IMAGES = 10
ALLOWED_SUPPORT_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_SUPPORT_VIDEO_EXTENSIONS = {"mp4", "mov", "webm", "m4v", "avi"}

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
    if "user" in session:
        return

    remember_token = (request.cookies.get("remember_token") or "").strip()
    email_cookie = (request.cookies.get("remember_email") or "").strip().lower()
    if email_cookie:
        session["last_email"] = email_cookie

    if not remember_token:
        return

    try:
        with get_db() as con:
            user = con.execute("SELECT * FROM users WHERE remember_token=?", (remember_token,)).fetchone()
        if not user:
            return
        if int((user["is_blocked"] if user["is_blocked"] is not None else 0) or 0) == 1:
            return
        session.permanent = True
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        session["role"] = user["role"] or "worker"
        session["last_email"] = user["email"] or email_cookie
    except Exception:
        return


def create_remember_token():
    return secrets.token_urlsafe(48)


def store_remember_token(user_id):
    token = create_remember_token()
    with get_db() as con:
        con.execute("UPDATE users SET remember_token=? WHERE id=?", (token, user_id))
        con.commit()
    return token


def clear_remember_token(user_id):
    if not user_id:
        return
    try:
        with get_db() as con:
            con.execute("UPDATE users SET remember_token='' WHERE id=?", (user_id,))
            con.commit()
    except Exception:
        pass


@app.before_request
def keep_user_logged_in():
    auto_login_from_cookie()


def get_current_session_user():
    user_id = session.get("user_id")
    user_name = session.get("user")
    with get_db() as con:
        if user_id:
            user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if user:
                session["user"] = user["name"]
                session["user_id"] = user["id"]
                session["role"] = user["role"] or "worker"
                session["last_email"] = user["email"] or session.get("last_email", "")
                return user
        if user_name:
            user = con.execute("SELECT * FROM users WHERE name=?", (user_name,)).fetchone()
            if user:
                session["user"] = user["name"]
                session["user_id"] = user["id"]
                session["role"] = user["role"] or "worker"
                session["last_email"] = user["email"] or session.get("last_email", "")
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
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if digits.startswith("0"):
        digits = "964" + digits[1:]
    return f"https://api.whatsapp.com/send?phone={digits}"
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


def is_favorite(visitor_id, worker_id):
    try:
        with get_db() as con:
            row = con.execute(
                "SELECT id FROM favorites WHERE visitor_id=? AND worker_id=?",
                (visitor_id, worker_id)
            ).fetchone()
            return row is not None
    except Exception:
        return False


def favorites_count(visitor_id):
    try:
        with get_db() as con:
            row = con.execute(
                "SELECT COUNT(*) AS c FROM favorites WHERE visitor_id=?",
                (visitor_id,)
            ).fetchone()
            return int((row["c"] if row else 0) or 0)
    except Exception:
        return 0


def allowed_file(filename):
    return True


def make_cloudinary_ref(public_id, secure_url):
    return f"cld|{public_id}|{secure_url}"


def parse_cloudinary_ref(value):
    value = (value or "").strip()
    if not value.startswith("cld|"):
        return None
    parts = value.split("|", 2)
    if len(parts) != 3:
        return None
    return {"public_id": parts[1], "url": parts[2]}


def media_url(value):
    value = (value or "").strip()
    if not value:
        return ""
    cloud_ref = parse_cloudinary_ref(value)
    if cloud_ref:
        return cloud_ref["url"]
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return url_for("uploaded_file", filename=value)


def is_cloudinary_ref(value):
    return bool(value and isinstance(value, str) and value.startswith("cld|"))


def make_cloudinary_ref(public_id, secure_url):
    return f"cld|{public_id}|{secure_url}"


def parse_cloudinary_ref(value):
    if not is_cloudinary_ref(value):
        return None
    parts = value.split("|", 2)
    if len(parts) != 3:
        return None
    return {"public_id": parts[1], "secure_url": parts[2]}


def media_url(value):
    if not value:
        return ""
    ref = parse_cloudinary_ref(value)
    if ref and ref.get("secure_url"):
        return ref["secure_url"]
    return url_for("uploaded_file", filename=value)


def external_image_href(value, back="/workers"):
    if not value:
        return "#"
    if is_cloudinary_ref(value):
        return media_url(value)
    return f'{url_for("view_image", filename=value)}?back={back}'


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
    else:
        ext = "jpg"

    if not CLOUDINARY_ENABLED:
        raise RuntimeError("Cloudinary غير مفعل في إعدادات البيئة")

    try:
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        upload_result = cloudinary.uploader.upload(
            file_obj.stream,
            resource_type="image",
            folder=CLOUDINARY_UPLOAD_FOLDER,
            public_id=f"{uuid.uuid4().hex}",
            format=ext,
            overwrite=True
        )
        secure_url = (upload_result.get("secure_url") or "").strip()
        public_id = (upload_result.get("public_id") or "").strip()
        if not secure_url or not public_id:
            raise RuntimeError("فشل Cloudinary بإرجاع رابط الصورة")
        return make_cloudinary_ref(public_id, secure_url)
    except Exception as e:
        print("CLOUDINARY UPLOAD ERROR:", repr(e))
        raise RuntimeError("فشل رفع الصورة إلى Cloudinary")


def delete_file_if_exists(filename):
    if not filename:
        return

    cloud_ref = parse_cloudinary_ref(filename)
    if cloud_ref and CLOUDINARY_ENABLED:
        try:
            cloudinary.uploader.destroy(cloud_ref["public_id"], resource_type="image", invalidate=True)
        except Exception:
            pass
        return

    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


def support_media_kind(filename="", mimetype=""):
    name = (filename or "").lower()
    mime = (mimetype or "").lower()
    ext = name.rsplit(".", 1)[1] if "." in name else ""

    if ext in ALLOWED_SUPPORT_IMAGE_EXTENSIONS or mime.startswith("image/"):
        return "image"
    if ext in ALLOWED_SUPPORT_VIDEO_EXTENSIONS or mime.startswith("video/"):
        return "video"
    return ""


def validate_support_media(file_obj):
    if not file_obj or not file_obj.filename:
        return False, "لا يوجد ملف مرفوع"

    media_kind = support_media_kind(file_obj.filename, getattr(file_obj, "mimetype", ""))
    if media_kind not in {"image", "video"}:
        return False, "الملف يجب أن يكون صورة أو فيديو"

    if not file_size_ok(file_obj):
        return False, "حجم الملف أكبر من المسموح"

    try:
        file_obj.stream.seek(0)
    except Exception:
        pass
    return True, ""


def save_support_media(file_obj):
    if not file_obj or not file_obj.filename:
        return "", ""

    is_valid, msg = validate_support_media(file_obj)
    if not is_valid:
        raise RuntimeError(msg)

    media_kind = support_media_kind(file_obj.filename, getattr(file_obj, "mimetype", ""))
    original = secure_filename(file_obj.filename)
    ext = original.rsplit(".", 1)[1].lower() if "." in original else ("jpg" if media_kind == "image" else "mp4")
    support_dir = os.path.join(app.config["UPLOAD_FOLDER"], "support")
    os.makedirs(support_dir, exist_ok=True)

    if CLOUDINARY_ENABLED:
        try:
            try:
                file_obj.stream.seek(0)
            except Exception:
                pass

            upload_result = cloudinary.uploader.upload(
                file_obj.stream,
                resource_type="video" if media_kind == "video" else "image",
                folder=f"{CLOUDINARY_UPLOAD_FOLDER}/support",
                public_id=f"{uuid.uuid4().hex}",
                format=ext,
                overwrite=True
            )
            secure_url = (upload_result.get("secure_url") or "").strip()
            public_id = (upload_result.get("public_id") or "").strip()
            if not secure_url or not public_id:
                raise RuntimeError("فشل رفع الملف")
            return make_cloudinary_ref(public_id, secure_url), media_kind
        except Exception as e:
            print("SUPPORT MEDIA CLOUDINARY ERROR:", repr(e))

    filename = f"support_{uuid.uuid4().hex}.{ext}"
    save_path = os.path.join(support_dir, filename)
    try:
        file_obj.save(save_path)
    except Exception:
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        with open(save_path, "wb") as f:
            f.write(file_obj.read())

    return os.path.join("support", filename).replace("\\", "/"), media_kind


def render_support_attachment(attachment, attachment_type):
    attachment = (attachment or "").strip()
    attachment_type = (attachment_type or "").strip().lower()
    if not attachment:
        return ""

    url = media_url(attachment)
    if not url:
        return ""

    if attachment_type == "video":
        return f"""
        <div class="support-media-wrap">
            <video controls preload="metadata" style="width:100%;max-height:260px;border-radius:16px;background:#000;">
                <source src="{url}">
                المتصفح لا يدعم عرض الفيديو.
            </video>
            <div style="margin-top:8px;"><a class="link-btn secondary" href="{url}" target="_blank">فتح الفيديو</a></div>
        </div>
        """

    return f"""
    <div class="support-media-wrap">
        <a href="{url}" target="_blank">
            <img src="{url}" alt="attachment" style="width:100%;max-height:260px;object-fit:contain;border-radius:16px;background:#f8fbff;border:1px solid rgba(47,111,237,.14);">
        </a>
    </div>
    """

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
    except DB_OPERATIONAL_ERRORS:
        con.execute("""
        INSERT INTO users
        (name, phone, email, password, role, birthdate, section, governorate, city, exp, bio, profile_pic, work_images)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            payload["name"], payload["phone"], payload["email"], payload["password"], payload["role"], payload["birthdate"],
            payload["section"], payload["governorate"], payload["city"], payload["exp"], payload["bio"], payload["profile_pic"], payload["work_images"]
        ))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/view-image")
def view_image():
    back = request.args.get("back", "/workers")
    if not back.startswith("/"):
        back = "/workers"

    image_ref = (request.args.get("image") or "").strip()
    images_raw = (request.args.get("images") or "").strip()

    image_refs = [x.strip() for x in images_raw.split("||") if x.strip()]
    if not image_refs and image_ref:
        image_refs = [image_ref]

    image_urls = []
    for ref in image_refs:
        url = media_url(ref)
        if url:
            image_urls.append(url)

    if not image_urls:
        single_url = media_url(image_ref)
        if single_url:
            image_urls = [single_url]
        else:
            return redirect(back)

    try:
        current_index = int(request.args.get("idx", "0"))
    except Exception:
        current_index = 0

    if current_index < 0:
        current_index = 0
    if current_index >= len(image_urls):
        current_index = len(image_urls) - 1

    slides_html = "".join(
        f'<div class="gallery-slide{" active" if i == current_index else ""}"><img src="{url}" alt="work"></div>'
        for i, url in enumerate(image_urls)
    )
    dots_html = "".join(
        f'<button type="button" class="gallery-dot{" active" if i == current_index else ""}" onclick="showGallerySlide({i})" aria-label="صورة {i + 1}"></button>'
        for i in range(len(image_urls))
    )
    image_urls_json = json.dumps(image_urls, ensure_ascii=False)

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container gallery-page-wrap">
            <div class="gallery-topbar">
                <a href="{back}"><button class="light-btn">رجوع</button></a>
                <span class="badge">{len(image_urls)} صورة</span>
            </div>
            <h2>عرض الصور</h2>
            <div class="section-subtitle">تقدر تسحب يمين ويسار أو تستخدم الأسهم حتى تنتقل بين الصور.</div>

            <div class="card gallery-viewer-card">
                <div class="gallery-viewer" id="galleryViewer">
                    {slides_html}

                    <button type="button" class="gallery-nav prev" onclick="moveGallery(-1)">‹</button>
                    <button type="button" class="gallery-nav next" onclick="moveGallery(1)">›</button>
                </div>
                <div class="gallery-counter" id="galleryCounter">{current_index + 1} / {len(image_urls)}</div>
                <div class="gallery-dots">{dots_html}</div>
            </div>
        </div>

        <script>
        const galleryImages = {image_urls_json};
        let galleryIndex = {current_index};
        let touchStartX = 0;
        let touchEndX = 0;

        function showGallerySlide(index) {{
            if (!galleryImages.length) return;
            if (index < 0) index = galleryImages.length - 1;
            if (index >= galleryImages.length) index = 0;
            galleryIndex = index;

            const slides = document.querySelectorAll('.gallery-slide');
            const dots = document.querySelectorAll('.gallery-dot');
            slides.forEach((slide, i) => slide.classList.toggle('active', i === galleryIndex));
            dots.forEach((dot, i) => dot.classList.toggle('active', i === galleryIndex));

            const counter = document.getElementById('galleryCounter');
            if (counter) counter.textContent = `${{galleryIndex + 1}} / ${{galleryImages.length}}`;
        }}

        function moveGallery(step) {{
            showGallerySlide(galleryIndex + step);
        }}

        const galleryViewer = document.getElementById('galleryViewer');
        if (galleryViewer) {{
            galleryViewer.addEventListener('touchstart', function(e) {{
                touchStartX = e.changedTouches[0].screenX;
            }}, {{passive:true}});

            galleryViewer.addEventListener('touchend', function(e) {{
                touchEndX = e.changedTouches[0].screenX;
                const diff = touchEndX - touchStartX;
                if (Math.abs(diff) > 40) {{
                    if (diff < 0) moveGallery(1);
                    else moveGallery(-1);
                }}
            }}, {{passive:true}});
        }}
        </script>
        </body></html>
        """
    )


class PostgresCursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, sql, params=None):
        self.cursor.execute(convert_sql_for_backend(sql), params or ())
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(row) for row in self.cursor.fetchall()]


class PostgresConnectionWrapper:
    def __init__(self, dsn):
        self.connection = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.RealDictCursor)

    def cursor(self):
        return PostgresCursorWrapper(self.connection.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params or ())
        return cur

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            try:
                self.rollback()
            finally:
                self.close()
        else:
            try:
                self.commit()
            finally:
                self.close()


def convert_sql_for_backend(sql):
    sql_text = sql
    if USING_POSTGRES:
        sql_text = sql_text.replace("INSERT OR IGNORE INTO", "INSERT INTO")
        sql_text = sql_text.replace("?", "%s")
        if "INSERT INTO favorites" in sql_text and "ON CONFLICT" not in sql_text:
            sql_text = sql_text.strip().rstrip(";") + " ON CONFLICT (visitor_id, worker_id) DO NOTHING"
    return sql_text


def get_db():
    if USING_POSTGRES:
        return PostgresConnectionWrapper(DATABASE_URL)

    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return con


def table_columns(cur, table_name):
    if USING_POSTGRES:
        cur.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position",
            (table_name,)
        )
        return [row["column_name"] for row in cur.fetchall()]

    cur.execute(f"PRAGMA table_info({table_name})")
    return [col[1] for col in cur.fetchall()]


def column_exists(cur, table_name, column_name):
    return column_name in table_columns(cur, table_name)


def init_db_sqlite(cur):
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
        bio TEXT,
        remember_token TEXT DEFAULT ''
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

    if not column_exists(cur, "users", "remember_token"):
        cur.execute("ALTER TABLE users ADD COLUMN remember_token TEXT DEFAULT ''")

    if not column_exists(cur, "users", "onesignal_subscription_id"):
        cur.execute("ALTER TABLE users ADD COLUMN onesignal_subscription_id TEXT DEFAULT ''")

    if not column_exists(cur, "users", "onesignal_player_id"):
        cur.execute("ALTER TABLE users ADD COLUMN onesignal_player_id TEXT DEFAULT ''")

    if not column_exists(cur, "users", "push_enabled"):
        cur.execute("ALTER TABLE users ADD COLUMN push_enabled INTEGER DEFAULT 1")

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
    CREATE TABLE IF NOT EXISTS conversations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visitor_id INTEGER NOT NULL,
        worker_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(visitor_id, worker_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER,
        sender_id INTEGER,
        receiver_id INTEGER,
        sender_role TEXT,
        receiver_role TEXT,
        sender_name TEXT,
        receiver_name TEXT,
        msg TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    if not column_exists(cur, "messages", "conversation_id"):
        cur.execute("ALTER TABLE messages ADD COLUMN conversation_id INTEGER")

    if not column_exists(cur, "messages", "sender_id"):
        cur.execute("ALTER TABLE messages ADD COLUMN sender_id INTEGER")

    if not column_exists(cur, "messages", "receiver_id"):
        cur.execute("ALTER TABLE messages ADD COLUMN receiver_id INTEGER")

    if not column_exists(cur, "messages", "sender_role"):
        cur.execute("ALTER TABLE messages ADD COLUMN sender_role TEXT DEFAULT ''")

    if not column_exists(cur, "messages", "receiver_role"):
        cur.execute("ALTER TABLE messages ADD COLUMN receiver_role TEXT DEFAULT ''")

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
    CREATE TABLE IF NOT EXISTS favorites(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visitor_id INTEGER NOT NULL,
        worker_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(visitor_id, worker_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS support_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        sender_type TEXT,
        message TEXT,
        attachment TEXT DEFAULT '',
        attachment_type TEXT DEFAULT '',
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

    if not column_exists(cur, "support_messages", "attachment"):
        cur.execute("ALTER TABLE support_messages ADD COLUMN attachment TEXT DEFAULT ''")

    if not column_exists(cur, "support_messages", "attachment_type"):
        cur.execute("ALTER TABLE support_messages ADD COLUMN attachment_type TEXT DEFAULT ''")


def init_db_postgres(cur):
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id BIGSERIAL PRIMARY KEY,
        name TEXT,
        phone TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT,
        birthdate TEXT DEFAULT '',
        section TEXT DEFAULT '',
        city TEXT DEFAULT '',
        exp TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        is_verified INTEGER DEFAULT 0,
        profile_pic TEXT DEFAULT '',
        work_images TEXT DEFAULT '',
        governorate TEXT DEFAULT '',
        show_phone INTEGER DEFAULT 1,
        show_whatsapp INTEGER DEFAULT 1,
        allow_messages INTEGER DEFAULT 1,
        views INTEGER DEFAULT 0,
        verified_worker INTEGER DEFAULT 0,
        is_pinned INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        hidden_by_admin INTEGER DEFAULT 0,
        remember_token TEXT DEFAULT '',
        onesignal_subscription_id TEXT DEFAULT '',
        onesignal_player_id TEXT DEFAULT '',
        push_enabled INTEGER DEFAULT 1
    )
    """)

    for alter_sql in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS birthdate TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_pic TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS work_images TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS governorate TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS show_phone INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS show_whatsapp INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS allow_messages INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_worker INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pinned INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS hidden_by_admin INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS remember_token TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS onesignal_subscription_id TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS onesignal_player_id TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS push_enabled INTEGER DEFAULT 1"
    ]:
        cur.execute(alter_sql)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_passkeys(
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL,
        credential_id TEXT UNIQUE,
        public_key TEXT,
        sign_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS conversations(
        id BIGSERIAL PRIMARY KEY,
        visitor_id BIGINT NOT NULL,
        worker_id BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(visitor_id, worker_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id BIGSERIAL PRIMARY KEY,
        conversation_id BIGINT,
        sender_id BIGINT,
        receiver_id BIGINT,
        sender_role TEXT DEFAULT '',
        receiver_role TEXT DEFAULT '',
        sender_name TEXT,
        receiver_name TEXT,
        msg TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0
    )
    """)

    for alter_sql in [
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS conversation_id BIGINT",
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_id BIGINT",
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS receiver_id BIGINT",
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_role TEXT DEFAULT ''",
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS receiver_role TEXT DEFAULT ''",
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read INTEGER DEFAULT 0"
    ]:
        cur.execute(alter_sql)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_settings(
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_logs(
        id BIGSERIAL PRIMARY KEY,
        admin_username TEXT,
        action TEXT,
        target_name TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS comments(
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT,
        commenter_name TEXT,
        rating INTEGER,
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS favorites(
        id BIGSERIAL PRIMARY KEY,
        visitor_id BIGINT NOT NULL,
        worker_id BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(visitor_id, worker_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS support_messages(
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT,
        sender_type TEXT DEFAULT 'user',
        message TEXT DEFAULT '',
        attachment TEXT DEFAULT '',
        attachment_type TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read_admin INTEGER DEFAULT 0,
        is_read_user INTEGER DEFAULT 0
    )
    """)

    for alter_sql in [
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS user_id BIGINT",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS sender_type TEXT DEFAULT 'user'",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS message TEXT DEFAULT ''",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS is_read_admin INTEGER DEFAULT 0",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS is_read_user INTEGER DEFAULT 0",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS attachment TEXT DEFAULT ''",
        "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS attachment_type TEXT DEFAULT ''"
    ]:
        cur.execute(alter_sql)


def init_db():
    with get_db() as con:
        cur = con.cursor()

        if USING_POSTGRES:
            init_db_postgres(cur)
        else:
            init_db_sqlite(cur)

        admin_row = cur.execute("SELECT * FROM admin_settings WHERE id=1").fetchone()
        if not admin_row:
            cur.execute(
                "INSERT INTO admin_settings (id, username, password) VALUES (1, ?, ?)",
                ("admin", generate_password_hash("1234"))
            )

        con.commit()

    db_label = "PostgreSQL" if USING_POSTGRES else "SQLite"
    print(f"تم تجهيز قاعدة البيانات بنجاح: {db_label}")


init_db()


def build_pretty_email_html(title, code, intro_text, note_text):
    return f"""
    <div dir="rtl" style="margin:0;padding:0;background:#eef4fb;font-family:Arial,Tahoma,sans-serif;">
        <div style="max-width:680px;margin:0 auto;padding:34px 16px;">
            <div style="background:linear-gradient(180deg,#f7faff 0%,#eef4ff 55%,#edf3fb 100%);border-radius:28px;overflow:hidden;border:1px solid rgba(37,99,235,.16);box-shadow:0 22px 60px rgba(15,39,71,.20);">

                <div style="padding:30px 24px 14px 24px;text-align:center;color:#1f2f4a;">
                    <div style="display:inline-block;background:rgba(255,255,255,.10);padding:10px 18px;border-radius:999px;font-size:14px;margin-bottom:18px;border:1px solid rgba(255,255,255,.12);">
                        منصة المسطر
                    </div>

                    <h1 style="margin:0;font-size:31px;font-weight:800;letter-spacing:.2px;">{title}</h1>

                    <p style="margin:14px 0 0 0;font-size:17px;line-height:2;color:#2455c8;">
                        {intro_text}
                    </p>
                </div>

                <div style="padding:24px;">
                    <div style="background:#ffffff;border-radius:24px;padding:30px 22px;text-align:center;border:1px solid rgba(47,111,237,.12);">
                        <div style="font-size:14px;color:#64748b;margin-bottom:10px;">رمز التحقق الخاص بك</div>

                        <div style="display:inline-block;background:linear-gradient(180deg,#2563eb 0%,#1d4ed8 100%);color:#1f2f4a;font-size:42px;font-weight:800;letter-spacing:8px;padding:18px 28px;border-radius:20px;box-shadow:0 14px 28px rgba(37,99,235,.24);">
                            {code}
                        </div>

                        <p style="margin:18px 0 0 0;font-size:15px;line-height:1.9;color:#475569;">
                            {note_text}
                        </p>
                    </div>

                    <div style="margin-top:16px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.08);padding:16px 18px;border-radius:18px;color:#2455c8;font-size:14px;line-height:1.95;">
                        تم إرسال هذه الرسالة من <strong>المسطر</strong>. إذا لم تطلب هذا الإجراء، تجاهل الرسالة ولا تشارك الرمز مع أي شخص.
                    </div>
                </div>

                <div style="padding:0 24px 28px 24px;text-align:center;color:#6b7a90;font-size:14px;line-height:1.9;">
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




def onesignal_enabled():
    return bool(ONESIGNAL_APP_ID and ONESIGNAL_REST_API_KEY)


def parse_onesignal_ids(value):
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = str(value).replace("\n", ",").replace(";", ",").split(",")
    cleaned = []
    for item in raw_items:
        item = str(item or "").strip()
        if item and item not in cleaned:
            cleaned.append(item)
    return cleaned


def absolute_app_url(path="/"):
    path = path or "/"
    try:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return request.url_root.rstrip("/") + (path if path.startswith("/") else "/" + path)
    except Exception:
        return path


def send_onesignal_payload(payload):
    if not onesignal_enabled():
        return False
    try:
        req = urllib.request.Request(
            "https://api.onesignal.com/api/v1/notifications",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Basic {ONESIGNAL_REST_API_KEY}",
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
                "User-Agent": "musattar-app/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=18) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            print("ONESIGNAL STATUS:", getattr(resp, "status", "unknown"), raw)
            return 200 <= int(getattr(resp, "status", 0) or 0) < 300
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="ignore")
        except Exception:
            detail = str(e)
        print("ONESIGNAL HTTP ERROR:", e.code, detail)
        return False
    except Exception as e:
        print("ONESIGNAL SEND ERROR:", repr(e))
        return False


def send_push_to_subscription_ids(subscription_ids, title, message, url=""):
    subscription_ids = parse_onesignal_ids(subscription_ids)
    if not subscription_ids:
        return False
    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_subscription_ids": subscription_ids,
        "headings": {"en": title, "ar": title},
        "contents": {"en": message, "ar": message},
    }
    if url:
        payload["url"] = absolute_app_url(url)
    return send_onesignal_payload(payload)


def send_push_to_player_ids(player_ids, title, message, url=""):
    player_ids = parse_onesignal_ids(player_ids)
    if not player_ids:
        return False
    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_player_ids": player_ids,
        "headings": {"en": title, "ar": title},
        "contents": {"en": message, "ar": message},
    }
    if url:
        payload["url"] = absolute_app_url(url)
    return send_onesignal_payload(payload)


def get_user_push_ids(user):
    if not user:
        return [], []
    subscription_ids = []
    player_ids = []
    try:
        if "push_enabled" in user.keys() and int((user["push_enabled"] if user["push_enabled"] is not None else 1) or 0) == 0:
            return [], []
    except Exception:
        pass
    try:
        if "onesignal_subscription_id" in user.keys():
            subscription_ids = parse_onesignal_ids(user["onesignal_subscription_id"] or "")
    except Exception:
        subscription_ids = []
    try:
        if "onesignal_player_id" in user.keys():
            player_ids = parse_onesignal_ids(user["onesignal_player_id"] or "")
    except Exception:
        player_ids = []
    return subscription_ids, player_ids


def send_push_to_user(user_id, title, message, url=""):
    try:
        with get_db() as con:
            user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    except Exception:
        user = None
    subscription_ids, player_ids = get_user_push_ids(user)
    sent = False
    if subscription_ids:
        sent = send_push_to_subscription_ids(subscription_ids, title, message, url) or sent
    if player_ids:
        sent = send_push_to_player_ids(player_ids, title, message, url) or sent
    return sent


def send_push_to_admins(title, message, url="/admin/pending-workers"):
    admin_ids = parse_onesignal_ids(ONESIGNAL_ADMIN_SUBSCRIPTION_IDS)
    if not admin_ids:
        return False
    return send_push_to_subscription_ids(admin_ids, title, message, url)


def notify_admin_new_worker(worker):
    if not worker:
        return False
    try:
        name = worker["name"] or "مختص جديد"
        section = worker["section"] or "بدون اختصاص"
    except Exception:
        name = "مختص جديد"
        section = "بدون اختصاص"
    return send_push_to_admins(
        "حساب مختص جديد",
        f"{name} سجل في المسطر وينتظر المراجعة - {section}",
        "/admin/pending-workers"
    )

def push_preview_text(text, max_length=120):
    text = sanitize_input(text or "", max_length * 2)
    if len(text) > max_length:
        return text[:max_length].rstrip() + "..."
    return text


def notify_new_direct_message(receiver_id, sender_name, msg, conversation_id):
    try:
        sender_name = sanitize_input(sender_name or "مستخدم", 80)
        preview = push_preview_text(msg, 110)
        return send_push_to_user(
            receiver_id,
            "رسالة جديدة في المسطر",
            f"{sender_name}: {preview}",
            f"/conversation/{conversation_id}"
        )
    except Exception as e:
        print("DIRECT MESSAGE PUSH ERROR:", repr(e))
        return False


def notify_new_worker_rating(worker_id, commenter_name, rating, comment):
    try:
        commenter_name = sanitize_input(commenter_name or "زائر", 80)
        preview = push_preview_text(comment, 105)
        return send_push_to_user(
            worker_id,
            "تقييم جديد على ملفك",
            f"{commenter_name} قيّمك {rating}/5: {preview}",
            f"/worker/{worker_id}"
        )
    except Exception as e:
        print("RATING PUSH ERROR:", repr(e))
        return False


def notify_admin_support_message(user, msg, attachment_type=""):
    try:
        if not user:
            return False
        name = sanitize_input(user["name"] or "مستخدم", 80)
        preview = push_preview_text(msg, 95)
        if not preview and attachment_type:
            preview = "أرسل مرفقاً جديداً"
        return send_push_to_admins(
            "رسالة دعم جديدة",
            f"{name}: {preview}",
            f"/admin/support?user_id={user['id']}"
        )
    except Exception as e:
        print("ADMIN SUPPORT PUSH ERROR:", repr(e))
        return False


def notify_user_support_reply(user_id, msg, attachment_type=""):
    try:
        preview = push_preview_text(msg, 110)
        if not preview and attachment_type:
            preview = "تم إرسال مرفق من الدعم الفني"
        return send_push_to_user(
            user_id,
            "رد جديد من الدعم الفني",
            f"الدعم الفني: {preview}",
            "/support"
        )
    except Exception as e:
        print("USER SUPPORT PUSH ERROR:", repr(e))
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


def set_pending_registration(data, otp, role):
    session["pending_register_data"] = data
    session["pending_register_otp"] = otp
    session["pending_register_role"] = role
    session["pending_register_otp_created_at"] = time.time()


def clear_pending_registration():
    session.pop("pending_register_data", None)
    session.pop("pending_register_otp", None)
    session.pop("pending_register_role", None)
    session.pop("pending_register_otp_created_at", None)


def send_registration_otp(email, otp):
    verify_html = build_pretty_email_html(
        "تأكيد إنشاء الحساب",
        otp,
        "وصلنا طلب إنشاء حساب جديد في المسطر. استخدم رمز التحقق التالي حتى نكمل التسجيل بأمان.",
        "أدخل هذا الرمز داخل صفحة تأكيد إنشاء الحساب لإكمال التسجيل."
    )
    return send_mail(
        email,
        "رمز تأكيد إنشاء الحساب في المسطر",
        f"رمز تأكيد إنشاء الحساب هو: {otp}",
        html_body=verify_html
    )


def complete_pending_registration():
    pending_data = session.get("pending_register_data") or {}
    role = session.get("pending_register_role") or pending_data.get("role") or "worker"
    email = (pending_data.get("email") or "").strip().lower()

    if not pending_data or not email:
        return False, "انتهت جلسة التحقق", None

    try:
        with get_db() as con:
            if role == "visitor":
                old = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                if old:
                    return False, "هذا البريد مستخدم مسبقاً", None

                insert_user_record(con, {
                    "name": pending_data.get("name", ""),
                    "phone": "",
                    "email": email,
                    "password": pending_data.get("password", ""),
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
                return True, "تم إنشاء حساب الزائر بنجاح", url_for("visitor_login")

            phone = pending_data.get("phone", "")
            old = con.execute("SELECT id FROM users WHERE phone=? OR email=?", (phone, email)).fetchone()
            if old:
                cleanup_saved_files(pending_data)
                return False, "رقم الهاتف أو البريد مستخدم مسبقاً", None

            insert_user_record(con, {
                "name": pending_data.get("name", ""),
                "phone": phone,
                "email": email,
                "password": pending_data.get("password", ""),
                "role": "worker",
                "birthdate": "",
                "section": pending_data.get("section", ""),
                "governorate": pending_data.get("governorate", ""),
                "city": pending_data.get("city", ""),
                "exp": pending_data.get("exp", ""),
                "bio": pending_data.get("bio", ""),
                "profile_pic": pending_data.get("profile_pic", ""),
                "work_images": pending_data.get("work_images", ""),
            })
            # بعد تأكيد البريد، حساب المختص لا يظهر للزوار إلا بعد موافقة الإدارة.
            con.execute(
                "UPDATE users SET is_verified=0, hidden_by_admin=0, admin_warning=? WHERE phone=? OR email=?",
                ("قيد مراجعة الإدارة", phone, email)
            )
            new_worker = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            con.commit()
            try:
                notify_admin_new_worker(new_worker)
            except Exception as notify_error:
                print("ADMIN PUSH NOTIFY ERROR:", repr(notify_error))
            return True, "تم تأكيد البريد وإنشاء الحساب. الحساب الآن قيد مراجعة الإدارة ولن يظهر للزائرين إلا بعد الموافقة.", url_for("login")
    except DB_INTEGRITY_ERRORS:
        if role != "visitor":
            cleanup_saved_files(pending_data)
        return False, "تعذر حفظ الحساب: البيانات مستخدمة مسبقاً", None
    except Exception as e:
        if role != "visitor":
            cleanup_saved_files(pending_data)
        label = "حساب الزائر" if role == "visitor" else "الحساب"
        return False, f"تعذر إنشاء {label}: {str(e)}", None


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
body{margin:0;padding:0;font-family:Tahoma,Arial,sans-serif;background:radial-gradient(circle at top right, rgba(47,111,237,.11), transparent 24%),radial-gradient(circle at top left, rgba(212,160,23,.08), transparent 18%),linear-gradient(180deg,#f7f9fd 0%, #eef4fb 52%, #edf3fa 100%);color:var(--text)}
a{text-decoration:none;color:inherit}
.container{width:min(94%,1120px);margin:24px auto;background:linear-gradient(180deg,#ffffff 0%, #fbfdff 100%);backdrop-filter:blur(10px);border:1px solid rgba(47,111,237,.12);border-radius:30px;padding:22px;box-shadow:var(--shadow)}
.narrow-container{width:min(94%,620px)}
h1,h2,h3,h4{margin:0 0 14px} h1{font-size:36px} h2{font-size:28px} h3{font-size:20px}
.small{font-size:13px;color:var(--muted)} .center{text-align:center}
.section-subtitle{font-size:14px;color:var(--muted);margin-bottom:14px}
input,select,textarea,button{width:100%;margin:8px 0;padding:13px 14px;border-radius:16px;border:1px solid rgba(47,111,237,.14);font-size:16px;background:#ffffff;color:var(--text)}
input:focus,select:focus,textarea:focus{outline:none;border-color:rgba(47,111,237,.48);box-shadow:0 0 0 4px rgba(47,111,237,.12)}
textarea{min-height:120px;resize:vertical}
button{background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#f8fbff;border:none;cursor:pointer;font-weight:700;box-shadow:0 10px 18px rgba(47,111,237,.20)} button:hover{transform:translateY(-1px);opacity:.98}
button.light-btn{background:#f3f7ff;color:#2455c8;border:1px solid rgba(47,111,237,.22)}
label{display:block;font-weight:bold;margin-top:10px;color:#31415d}
.msg,.notice-box{background:#eef4ff;border:1px solid rgba(47,111,237,.18);padding:14px;border-radius:18px;text-align:center;margin:12px 0;color:#2455c8}
.notice{font-size:13px;text-align:center;color:var(--muted);margin-top:8px}
hr{border:none;border-top:1px solid rgba(47,111,237,.10);margin:18px 0}
.row,.inline,.topbar,.worker-hero-top,.admin-panel-top{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.row>*{flex:1;min-width:220px}
.hero-panel,.card,.specialty-group-card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box{background:#ffffff;border:1px solid rgba(47,111,237,.12);border-radius:24px;box-shadow:var(--soft-shadow)}
.hero-panel,.card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box,.comment-card{padding:18px}
.hero-badge,.badge,.worker-specialty-badge{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:34px;padding:7px 12px;border-radius:999px;font-size:12px;font-weight:700}
.hero-badge,.badge{background:#eef4ff;color:#2455c8;border:1px solid rgba(47,111,237,.18)}
.worker-specialty-badge{background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#eff6ff}
.home-grid,.home-features-grid,.home-stats-grid,.specialties-grid,.work-grid,.admin-stats-grid,.admin-users-grid{display:grid;gap:14px}
.home-grid{grid-template-columns:1.4fr .9fr}.home-features-grid,.home-stats-grid{grid-template-columns:repeat(3,1fr)}
.home-feature-icon{width:54px;height:54px;border-radius:18px;background:linear-gradient(180deg,#eef4ff 0%, #f9fbff 100%);border:1px solid rgba(47,111,237,.16);display:flex;align-items:center;justify-content:center;font-size:26px;margin-bottom:10px;color:#2455c8}
.profile-img,.profile-img-large{object-fit:cover;border-radius:50%;border:4px solid rgba(47,111,237,.34);background:#f8fbff}
.profile-img{width:88px;height:88px}.profile-img-large{width:128px;height:128px;display:block}
.profile-placeholder,.profile-placeholder-large{display:flex;align-items:center;justify-content:center;background:#f6f9ff;border-radius:50%;color:#7a8aa5;border:3px solid rgba(47,111,237,.18)}
.profile-placeholder{width:88px;height:88px;font-size:32px}.profile-placeholder-large{width:128px;height:128px;font-size:42px;margin:0 auto}
.worker-card{display:grid;grid-template-columns:96px 1fr;gap:16px;align-items:start}
.worker-info-grid,.detail-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:12px}
.info-chip,.detail-box{background:#fbfdff;border:1px solid rgba(47,111,237,.12);border-radius:16px;padding:10px 12px;font-size:14px}
.work-grid{grid-template-columns:repeat(3,1fr);margin-top:12px}
.work-grid img{width:100%;aspect-ratio:1/1;object-fit:cover;border-radius:18px;border:2px solid rgba(47,111,237,.20);background:#f8fbff}
.specialties-grid{grid-template-columns:repeat(3,minmax(0,1fr));margin-top:14px}
.specialty-group-card{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;min-height:148px;padding:16px 12px}.specialty-group-card h3{margin:8px 0 6px;color:var(--text);font-size:18px;line-height:1.35}.section-subtitle{font-size:13px;line-height:1.5;color:var(--muted);margin-top:2px}.specialty-items{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.specialty-item{display:block;background:#ffffff;border:1px solid rgba(47,111,237,.14);border-radius:16px;padding:14px 8px;text-align:center;transition:.2s;color:var(--text)}
.specialty-item:hover{transform:translateY(-2px);box-shadow:0 8px 18px rgba(47,111,237,.10);border-color:rgba(47,111,237,.26)}
input::placeholder, textarea::placeholder{color:#9aa7bb;opacity:1}
.specialty-group-card,.card,.worker-hero,.settings-group,.settings-profile-wrap,.hero-panel,.search-panel{position:relative;overflow:hidden}
.specialty-group-card::before,.card::before,.worker-hero::before,.settings-group::before,.settings-profile-wrap::before,.hero-panel::before,.search-panel::before{content:"";position:absolute;right:18px;left:18px;top:0;height:3px;border-radius:999px;background:linear-gradient(90deg,rgba(47,111,237,.95),rgba(212,160,23,.70));opacity:.9}
.active-specialty-item{background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#eff6ff;border-color:#255fda}.active-specialty-item .specialty-name,.active-specialty-item .specialty-icon{color:#eff6ff}
.specialty-icon{font-size:28px;margin-bottom:6px}.specialty-name{font-size:14px;font-weight:700;color:var(--text);line-height:1.6}
.link-btn,.bottom-corner-link,.settings-btn{display:inline-flex;align-items:center;justify-content:center;gap:8px}
.link-btn{background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#eff6ff;padding:10px 14px;border-radius:14px;margin:4px 0;font-size:14px;font-weight:700;border:1px solid rgba(47,111,237,.18);box-shadow:0 6px 16px rgba(47,111,237,.16)}.link-red{background:linear-gradient(180deg,#ef4444 0%, #dc2626 100%);color:#fff}
.search-panel{display:none;margin-bottom:16px}.search-panel.show{display:block}.search-inline-grid{display:grid;grid-template-columns:1.3fr 1fr 1fr auto;gap:10px;align-items:end}
.settings-floating{position:fixed;top:14px;left:66px;z-index:9999}.settings-btn{position:relative;display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;background:#ffffff;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:#2455c8;border-radius:999px;font-size:21px;text-decoration:none;box-shadow:0 8px 18px rgba(31,47,74,.10);border:1px solid rgba(47,111,237,.12);transition:transform .18s ease, box-shadow .18s ease, background .18s ease}.settings-btn:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(31,47,74,.12);background:#f8fbff}
.bottom-corner-link{position:fixed;bottom:18px;z-index:9999;min-width:86px;height:46px;padding:0 16px;background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#eff6ff;border-radius:999px;box-shadow:0 6px 16px rgba(47,111,237,.16);font-size:14px;font-weight:700;border:1px solid rgba(47,111,237,.18)}.bottom-left-link{left:16px}.bottom-right-link{right:16px}
.global-back-wrap{position:fixed;top:14px;right:14px;z-index:9999}.global-back-btn{display:inline-flex;align-items:center;justify-content:center;min-width:112px;height:46px;padding:0 16px;background:linear-gradient(180deg,#3f7ff4 0%, #255fda 100%);color:#eff6ff;border-radius:999px;box-shadow:0 6px 16px rgba(47,111,237,.16);font-size:14px;font-weight:800;border:1px solid rgba(47,111,237,.18)}
.settings-profile-wrap{display:flex;align-items:center;gap:14px}.settings-profile-info{flex:1}.settings-section-title{font-size:18px;font-weight:700;margin:0 0 10px;text-align:right}
.worker-hero-grid{display:grid;grid-template-columns:140px 1fr;gap:18px;align-items:start}
.star{font-size:20px;color:#d4a017;margin:6px 0}.comment-card{margin:10px 0}
.admin-stats-grid{grid-template-columns:repeat(4,1fr);margin-bottom:16px}.admin-stat .label{font-size:13px;color:var(--muted);margin-bottom:8px}.admin-stat .value{font-size:28px;font-weight:700}
.admin-users-grid{grid-template-columns:repeat(2,1fr)}
.empty-state{padding:24px;text-align:center;border-radius:22px;background:#f8fbff;border:1px dashed rgba(47,111,237,.18);color:#6b7a90}
.footer-note{text-align:center;color:var(--muted);font-size:13px;margin-top:16px}
@media (max-width:960px){.home-grid,.home-features-grid,.home-stats-grid,.admin-stats-grid,.admin-users-grid{grid-template-columns:1fr}.specialties-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.search-inline-grid{grid-template-columns:1fr}}
@media (max-width:720px){h1{font-size:28px}h2{font-size:24px}.container{padding:16px;border-radius:24px}.worker-card,.worker-hero-grid,.settings-profile-wrap{grid-template-columns:1fr;display:grid}.worker-info-grid,.detail-grid,.work-grid,.specialty-items{grid-template-columns:1fr 1fr}.specialties-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.specialty-group-card{min-height:132px;padding:14px 10px}.specialty-group-card h3{font-size:16px}.section-subtitle{font-size:12px}}
@media (max-width:520px){.work-grid,.worker-info-grid,.detail-grid,.specialty-items{grid-template-columns:1fr}.bottom-corner-link{font-size:13px;min-width:74px;padding:0 12px}}

.worker-rating-line{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
.rating-stars{font-size:16px;color:#fbbf24;letter-spacing:2px}
.rating-text{font-size:13px;color:#6b7a90}
.verified-badge{background:#ecfdf5;border-color:rgba(22,163,74,.28);color:#15803d}
.pinned-badge{background:#fff8e7;border-color:rgba(212,160,23,.28);color:#b7791f}
.filter-grid-pro{display:grid;grid-template-columns:1.2fr 1fr 1fr 1fr 1fr auto;gap:10px;align-items:end}
.map-link-btn{background:#f8fbff;border:1px solid rgba(47,111,237,.18);color:var(--text)}
.mini-stat{background:#fbfdff;border:1px solid rgba(47,111,237,.12);border-radius:16px;padding:10px 12px}
.map-page-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:14px}
#workersMap{width:100%;height:620px;border-radius:22px;border:1px solid rgba(47,111,237,.14);overflow:hidden}
.map-list-card{max-height:620px;overflow:auto}
@media (max-width:960px){.filter-grid-pro,.map-page-grid{grid-template-columns:1fr}}


/* Soft elegant typography tuning */
:root{
    --text:#1f2f4a;
    --muted:#6b7a90;
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
  .global-back-btn{height:40px;min-width:94px;font-size:13px;padding:0 12px}.settings-floating{top:14px;left:62px}.settings-btn{width:40px;height:40px;font-size:19px;padding:0}
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

.message-floating-wrap{position:fixed;top:14px;left:118px;z-index:9999}
.message-floating-btn{position:relative;display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;background:rgba(255,255,255,.88);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:#0f172a;border-radius:999px;box-shadow:0 8px 22px rgba(15,23,42,.14);font-size:22px;text-decoration:none;border:1px solid rgba(148,163,184,.22);transition:transform .18s ease, box-shadow .18s ease, background .18s ease}
.message-floating-btn:hover{transform:translateY(-1px);box-shadow:0 10px 26px rgba(15,23,42,.18);background:rgba(255,255,255,.96)}
.msg-badge-count{position:absolute;top:-3px;right:-3px;display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;border-radius:999px;background:#ef4444;color:#fff;font-size:10px;font-weight:800;border:2px solid #fff;line-height:1}
.msg-toast{position:fixed;top:66px;left:50%;transform:translateX(-50%) translateY(-8px);z-index:10000;min-width:150px;max-width:84vw;padding:8px 12px;border-radius:999px;background:rgba(15,23,42,.82);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:#fff;text-align:center;font-size:12px;font-weight:700;box-shadow:0 8px 24px rgba(15,23,42,.18);opacity:0;transition:all .22s ease;border:1px solid rgba(255,255,255,.12)}
.msg-toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media (max-width:520px){.settings-floating{top:14px;left:60px}.settings-btn{width:40px;height:40px;font-size:19px}.message-floating-wrap{top:62px;left:14px}.message-floating-btn{width:40px;height:40px;font-size:20px}.msg-toast{top:104px;font-size:11px;min-width:132px;padding:7px 10px}}


.worker-hero-pro{position:relative;overflow:hidden}
.worker-hero-pro::after{content:"";position:absolute;inset:auto -40px -60px auto;width:180px;height:180px;border-radius:50%;background:radial-gradient(circle,rgba(96,165,250,.18),transparent 65%);pointer-events:none}
.stat-mini-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:14px}
.stat-mini-card{background:rgba(255,255,255,.05);border:1px solid rgba(96,165,250,.16);border-radius:18px;padding:12px 10px;text-align:center}
.stat-mini-label{font-size:12px;color:#bfd4ee;margin-bottom:6px}
.stat-mini-value{font-size:18px;font-weight:800;color:#fff}
.profile-actions-bar{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.action-pill{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:999px;background:linear-gradient(135deg,rgba(37,99,235,.95),rgba(59,130,246,.82));color:#fff!important;font-weight:800;border:1px solid rgba(147,197,253,.24);box-shadow:0 10px 24px rgba(37,99,235,.18)}
.action-pill.secondary{background:rgba(255,255,255,.06);color:#dbeafe!important}
.action-pill:hover{transform:translateY(-1px);filter:brightness(1.04)}
.profile-bio-box{margin-top:12px;padding:14px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(96,165,250,.14);border-radius:18px;line-height:1.9}
.gallery-head,.reviews-head{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}
.work-grid img{cursor:zoom-in}
.review-card-pro{padding:14px 16px;border-radius:20px;background:rgba(255,255,255,.045);border:1px solid rgba(96,165,250,.14);margin-top:10px}
.review-top{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.review-name{font-weight:800;color:#fff}
.review-date{font-size:12px;color:#bcd0ea}
.review-text{line-height:1.9;color:#e6eefb}
.rating-pill{display:inline-flex;align-items:center;gap:6px;background:rgba(245,158,11,.14);color:#fde68a;border:1px solid rgba(245,158,11,.24);padding:6px 10px;border-radius:999px;font-size:13px;font-weight:700}
.review-form-pro .rating-row{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.review-form-pro input[type=radio]{display:none}
.review-form-pro .rate-pill{display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border-radius:999px;border:1px solid rgba(96,165,250,.2);background:rgba(255,255,255,.04);color:#2455c8;font-weight:800;cursor:pointer;min-width:78px}
.review-form-pro input[type=radio]:checked + .rate-pill{background:linear-gradient(135deg,rgba(37,99,235,.95),rgba(59,130,246,.82));color:#fff;border-color:rgba(147,197,253,.35)}
.review-form-pro textarea{min-height:120px}
@media (max-width:720px){.profile-actions-bar{display:grid;grid-template-columns:1fr 1fr}.action-pill{padding:10px 12px;font-size:14px}.stat-mini-grid{grid-template-columns:1fr 1fr}}




/* Gallery layout + swipe viewer fix */
.work-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:12px}
.work-grid a.work-tile{display:block;width:100%}
.work-thumb,.work-grid img{width:100%;height:145px;aspect-ratio:auto;object-fit:cover;border-radius:14px;border:2px solid rgba(47,111,237,.20);background:#f8fbff;display:block}
.work-grid label img{margin-bottom:8px}
.gallery-page-wrap{max-width:760px}
.gallery-topbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.gallery-viewer-card{padding:14px}
.gallery-viewer{position:relative;overflow:hidden;border-radius:20px;background:rgba(15,23,42,.04);min-height:280px}
.gallery-slide{display:none;align-items:center;justify-content:center;min-height:280px}
.gallery-slide.active{display:flex}
.gallery-slide img{width:100%;max-height:76vh;object-fit:contain;background:#f8fbff;border-radius:18px}
.gallery-nav{position:absolute;top:50%;transform:translateY(-50%);width:46px;height:46px;border-radius:999px;border:none;background:rgba(15,23,42,.55);color:#fff;font-size:28px;line-height:1;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:2}
.gallery-nav.prev{right:12px}
.gallery-nav.next{left:12px}
.gallery-counter{text-align:center;font-weight:700;margin-top:12px}
.gallery-dots{display:flex;justify-content:center;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px}
.gallery-dot{width:10px;height:10px;border-radius:999px;border:none;background:rgba(148,163,184,.55);padding:0;cursor:pointer}
.gallery-dot.active{background:#2563eb;transform:scale(1.15)}
@media (max-width:720px){
  .work-grid{grid-template-columns:repeat(2,minmax(0,1fr)) !important;gap:10px}
  .work-thumb,.work-grid img{height:128px}
}
@media (max-width:520px){
  .work-grid{grid-template-columns:repeat(2,minmax(0,1fr)) !important;gap:8px}
  .work-thumb,.work-grid img{height:118px;border-radius:12px}
  .gallery-nav{width:40px;height:40px;font-size:24px}
  .gallery-slide,.gallery-viewer{min-height:220px}
}

/* Tuned contrast + tighter specialty layout */
:root{--text:#13233f;--muted:#54657f;--bg:#f4d35e;--panel:#fffdf7;--card:#fffdf7;--border:rgba(120,88,0,.14);--shadow:0 16px 34px rgba(120,88,0,.12);--soft-shadow:0 8px 18px rgba(120,88,0,.08)}
body{color:var(--text);background:radial-gradient(circle at top right, rgba(255,255,255,.22), transparent 22%),radial-gradient(circle at top left, rgba(255,255,255,.18), transparent 18%),linear-gradient(180deg,#f7d774 0%, #f4d35e 54%, #efc95a 100%)}
.container{background:linear-gradient(180deg,#fffdf7 0%, #fff9e8 100%);box-shadow:var(--shadow);padding:18px 18px 16px}
h1,h2,h3,h4,.specialty-group-card h3,.specialty-name,label{color:var(--text)!important}
.section-subtitle,.small,.notice,.footer-note,.rating-text{color:var(--muted)!important}
input,select,textarea{color:var(--text)!important;background:#fffef9;border:1px solid rgba(120,88,0,.16)}
input::placeholder, textarea::placeholder{color:#7a8aa3;opacity:1}
.hero-panel,.card,.specialty-group-card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box{border-color:rgba(120,88,0,.12)!important;box-shadow:var(--soft-shadow)!important}
button{box-shadow:0 10px 20px rgba(37,99,235,.18)!important}
button.light-btn{background:#f8fbff!important;color:#2455c8!important;border:1px solid rgba(37,99,235,.22)!important}
.hero-panel,.card,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box,.comment-card{padding:15px!important}
.topbar,.inline,.row,.worker-hero-top,.admin-panel-top{gap:10px!important}
.specialties-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:12px!important;margin-top:14px!important}
.specialty-group-card{padding:14px 12px!important;border-radius:22px!important;display:flex!important;flex-direction:column!important;align-items:center!important;justify-content:center!important;text-align:center!important;min-height:146px!important}
.specialty-group-card::before{right:14px!important;left:14px!important;height:4px!important;background:linear-gradient(90deg,rgba(37,99,235,.92),rgba(212,160,23,.78))!important}
.specialty-group-card h3{margin:8px 0 6px!important;font-size:18px!important;line-height:1.35!important}
.specialty-items{gap:8px!important;margin-top:4px}
.specialty-item{padding:12px 10px!important;border-radius:14px!important}
.specialty-icon{margin-bottom:4px!important}
.worker-card{gap:12px!important}
.worker-info-grid,.detail-grid{gap:8px!important}
.info-chip,.detail-box,.mini-stat{background:#f8fbff!important}
@media (max-width:900px){.specialties-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media (max-width:720px){.container{padding:14px}.specialty-group-card{padding:12px 10px!important;min-height:128px!important}.specialty-group-card h3{font-size:16px!important}.section-subtitle{font-size:12px!important;line-height:1.45!important}}

/* === FORCE BLACK GOLD AFTER GUEST UPDATE === */
html,body{
    background:
      radial-gradient(circle at top right, rgba(212,160,23,.18), transparent 28%),
      radial-gradient(circle at bottom left, rgba(184,134,11,.14), transparent 32%),
      linear-gradient(180deg,#050505 0%,#111111 55%,#050505 100%) !important;
    color:#f5e6a8 !important;
}
.container{
    background:linear-gradient(180deg,#181818 0%,#101010 100%) !important;
    border:1px solid rgba(212,160,23,.30) !important;
    box-shadow:0 18px 42px rgba(0,0,0,.55) !important;
}
.card,.hero-panel,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,
.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box,
.specialty-group-card,.chat-screen,.chat-list-shell,.review-card-pro,.stat-mini-card,.profile-bio-box{
    background:linear-gradient(180deg,#1c1c1c 0%,#121212 100%) !important;
    border:1px solid rgba(212,160,23,.26) !important;
    color:#f5e6a8 !important;
}
h1,h2,h3,h4,label,.specialty-name,.review-name{
    color:#ffd966 !important;
}
.small,.section-subtitle,.notice,.footer-note,.rating-text,.chat-time,.chat-user-sub,.stat-mini-label{
    color:#c8b36a !important;
}
input,select,textarea{
    background:#0f0f0f !important;
    color:#f5e6a8 !important;
    border:1px solid rgba(212,160,23,.35) !important;
}
input::placeholder,textarea::placeholder{
    color:#9f8d52 !important;
}
button,.link-btn,.bottom-corner-link,.global-back-btn,.action-pill,.chat-send-btn{
    background:linear-gradient(180deg,#ffd966 0%,#b8860b 100%) !important;
    color:#000000 !important;
    border:1px solid rgba(255,217,102,.35) !important;
    font-weight:800 !important;
}
button.light-btn,.action-pill.secondary,.link-btn.secondary,.settings-btn,.message-floating-btn{
    background:#1f1f1f !important;
    color:#ffd966 !important;
    border:1px solid rgba(212,160,23,.38) !important;
}
.badge,.hero-badge,.chat-status-chip,.rating-pill,.chat-list-chip{
    background:rgba(212,160,23,.14) !important;
    color:#ffd966 !important;
    border:1px solid rgba(212,160,23,.34) !important;
}
.info-chip,.detail-box,.mini-stat,.empty-state,.msg,.notice-box{
    background:#111111 !important;
    border:1px solid rgba(212,160,23,.25) !important;
    color:#f5e6a8 !important;
}


/* === FIX REGISTER DROPDOWN COLORS: WHITE OPTIONS + BIGGER TEXT === */
select{
    background:#0f0f0f !important;
    color:#ffffff !important;
    border:1px solid rgba(212,160,23,.40) !important;
    font-size:16px !important;
    font-weight:700 !important;
    min-height:44px !important;
}

select:focus{
    outline:none !important;
    border-color:#ffd966 !important;
    box-shadow:0 0 0 3px rgba(255,217,102,.18) !important;
}

select option{
    background:#ffffff !important;
    color:#111111 !important;
    font-size:16px !important;
    font-weight:700 !important;
    padding:10px !important;
}

select option:checked,
select option:hover,
select option:focus{
    background:#ffffff !important;
    color:#111111 !important;
}


/* WhatsApp button beside call button */
.whatsapp-pill{
    background:linear-gradient(180deg,#25D366 0%,#128C7E 100%) !important;
    color:#ffffff !important;
    border:1px solid rgba(37,211,102,.35) !important;
    box-shadow:0 10px 24px rgba(37,211,102,.20) !important;
}


/* clearer section titles */
.section-card h3,
.section-title,
.specialty-title,
.worker-card-title,
.category-title,
a h3{
    color:#ffd966 !important;
    font-size:28px !important;
    font-weight:900 !important;
}


/* force category names visible */
.section-card *,
.worker-group-card *,
.home-feature-card *,
.specialty-group-card *{
 color:#ffd966 !important;
}
.section-card a,
.worker-group-card a,
.home-feature-card a,
.specialty-group-card a{
 font-size:30px !important;
 font-weight:900 !important;
}


/* force main section names */
.specialty-group-card h3{
    color:#ffffff !important;
    font-size:32px !important;
    font-weight:900 !important;
}
.specialty-group-card .section-subtitle{
    color:#f5d77a !important;
    font-size:18px !important;
}


/* === CLEAN WHITE BLUE YELLOW THEME === */
:root{
    --primary:#2563eb !important;
    --primary-2:#60a5fa !important;
    --accent:#facc15 !important;
    --bg:#f8fbff !important;
    --panel:#ffffff !important;
    --card:#ffffff !important;
    --text:#12325f !important;
    --muted:#5f78a0 !important;
    --border:rgba(37,99,235,.18) !important;
    --shadow:0 16px 34px rgba(37,99,235,.10) !important;
    --soft-shadow:0 8px 22px rgba(37,99,235,.08) !important;
}

html,body{
    background:
        radial-gradient(circle at top right, rgba(96,165,250,.18), transparent 30%),
        radial-gradient(circle at bottom left, rgba(250,204,21,.16), transparent 32%),
        linear-gradient(180deg,#ffffff 0%,#f8fbff 55%,#eef6ff 100%) !important;
    color:#12325f !important;
}

.container,
.card,
.hero-panel,
.search-panel,
.settings-group,
.settings-profile-wrap,
.worker-hero,
.comment-card,
.admin-stat,
.admin-search-box,
.admin-user-card,
.admin-log-card,
.home-feature-card,
.home-stat,
.home-cta-box,
.specialty-group-card,
.chat-screen,
.chat-list-shell,
.review-card-pro,
.stat-mini-card,
.profile-bio-box,
.empty-state,
.msg,
.notice-box{
    background:#ffffff !important;
    color:#12325f !important;
    border:1px solid rgba(37,99,235,.18) !important;
    box-shadow:0 12px 28px rgba(37,99,235,.08) !important;
}

.container{
    border-radius:28px !important;
}

h1,h2,h3,h4,
label,
.specialty-name,
.review-name,
.worker-card-title,
.category-title,
a h3{
    color:#12325f !important;
}

.small,
.section-subtitle,
.notice,
.footer-note,
.rating-text,
.chat-time,
.chat-user-sub,
.stat-mini-label{
    color:#5f78a0 !important;
}

input,
select,
textarea{
    background:#ffffff !important;
    color:#12325f !important;
    border:1px solid rgba(37,99,235,.25) !important;
    box-shadow:none !important;
}

input:focus,
select:focus,
textarea:focus{
    border-color:#2563eb !important;
    box-shadow:0 0 0 4px rgba(37,99,235,.12) !important;
}

input::placeholder,
textarea::placeholder{
    color:#7d94b5 !important;
}

button,
.link-btn,
.global-back-btn,
.bottom-corner-link,
.action-pill,
.chat-send-btn{
    background:linear-gradient(180deg,#60a5fa 0%,#2563eb 100%) !important;
    color:#ffffff !important;
    border:1px solid rgba(37,99,235,.28) !important;
    box-shadow:0 10px 20px rgba(37,99,235,.18) !important;
}

button.light-btn,
.link-btn.secondary,
.action-pill.secondary,
.settings-btn,
.message-floating-btn{
    background:#ffffff !important;
    color:#2563eb !important;
    border:1px solid rgba(37,99,235,.25) !important;
}

.visitor-big-entry,
.badge,
.hero-badge,
.rating-pill,
.chat-status-chip,
.chat-list-chip,
.worker-specialty-badge,
.pinned-badge{
    background:linear-gradient(180deg,#fde68a 0%,#facc15 100%) !important;
    color:#12325f !important;
    border:1px solid rgba(250,204,21,.55) !important;
    box-shadow:0 10px 22px rgba(250,204,21,.18) !important;
}

.verified-badge{
    background:#eaf4ff !important;
    color:#2563eb !important;
    border:1px solid rgba(37,99,235,.24) !important;
}

.info-chip,
.detail-box,
.mini-stat{
    background:#f8fbff !important;
    color:#12325f !important;
    border:1px solid rgba(37,99,235,.14) !important;
}

.specialty-group-card::before,
.card::before,
.worker-hero::before,
.settings-group::before,
.settings-profile-wrap::before,
.hero-panel::before,
.search-panel::before{
    background:linear-gradient(90deg,#2563eb,#facc15) !important;
}

.specialty-group-card h3{
    color:#12325f !important;
    font-size:28px !important;
    font-weight:900 !important;
}

.specialty-group-card .section-subtitle{
    color:#5f78a0 !important;
    font-size:15px !important;
}

.specialty-group-card *,
.home-feature-card *,
.worker-group-card *,
.section-card *{
    color:#12325f !important;
}

.chat-bubble.mine,
.support-media-wrap + div,
.whatsapp-pill{
    background:linear-gradient(180deg,#60a5fa 0%,#2563eb 100%) !important;
    color:#ffffff !important;
}

.chat-bubble.theirs{
    background:#f8fbff !important;
    color:#12325f !important;
}

.link-red{
    background:linear-gradient(180deg,#facc15 0%,#eab308 100%) !important;
    color:#12325f !important;
}

select option{
    background:#ffffff !important;
    color:#12325f !important;
}

a{
    color:#2563eb !important;
}


/* === 44608 VIDEO HOME DESIGN - SAME COLORS === */
.musattar-app-shell{
    width:min(96%,520px);
    margin:10px auto 74px;
    padding:0 10px 12px;
    color:#12325f;
}
.musattar-app-top{
    position:sticky;
    top:0;
    z-index:80;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    padding:10px 4px 8px;
    background:linear-gradient(180deg,rgba(248,251,255,.98),rgba(248,251,255,.86));
    backdrop-filter:blur(12px);
    -webkit-backdrop-filter:blur(12px);
}
.ms-round-btn{
    width:38px;
    height:38px;
    border-radius:14px;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#ffffff;
    color:#2563eb!important;
    border:1px solid rgba(37,99,235,.14);
    box-shadow:0 8px 20px rgba(37,99,235,.08);
    font-size:18px;
    font-weight:900;
}
.ms-title-lockup{
    display:flex;
    align-items:center;
    gap:8px;
    font-weight:900;
    color:#12325f;
}
.ms-title-logo{
    width:42px;
    height:42px;
    border-radius:15px;
    display:flex;
    align-items:center;
    justify-content:center;
    background:linear-gradient(180deg,#fde68a,#facc15);
    color:#12325f;
    box-shadow:0 10px 24px rgba(250,204,21,.20);
    border:1px solid rgba(250,204,21,.58);
    font-size:22px;
}
.ms-search-card{
    background:#ffffff;
    border:1px solid rgba(37,99,235,.14);
    border-radius:24px;
    padding:12px;
    box-shadow:0 14px 34px rgba(37,99,235,.10);
    margin:4px 0 14px;
}
.ms-search-title{
    display:flex;
    align-items:center;
    justify-content:space-between;
    color:#12325f;
    font-size:13px;
    font-weight:900;
    margin-bottom:8px;
}
.ms-search-main{
    display:grid;
    grid-template-columns:1fr 72px;
    gap:8px;
    align-items:center;
    direction:rtl;
}
.ms-search-main input{
    margin:0!important;
    height:43px!important;
    border-radius:18px!important;
    background:#f8fbff!important;
    font-size:13px!important;
    color:#12325f!important;
}
.ms-search-main button{
    margin:0!important;
    height:43px!important;
    border-radius:18px!important;
    padding:0!important;
    font-size:13px!important;
}
.ms-filter-row{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:8px;
    margin-top:8px;
}
.ms-filter-row select{
    margin:0!important;
    height:40px!important;
    border-radius:16px!important;
    background:#ffffff!important;
    color:#12325f!important;
    font-size:12px!important;
    font-weight:800!important;
}
.ms-filter-label{
    margin:8px 0 2px;
    font-size:12px;
    color:#5f78a0;
    font-weight:800;
}
.ms-quick-actions{
    display:flex;
    gap:8px;
    margin-top:10px;
    overflow-x:auto;
    padding-bottom:2px;
    scrollbar-width:none;
}
.ms-quick-actions::-webkit-scrollbar{display:none}
.ms-action-chip{
    flex:0 0 auto;
    min-width:118px;
    height:38px;
    border-radius:999px;
    display:flex;
    align-items:center;
    justify-content:center;
    gap:6px;
    padding:0 12px;
    background:#ffffff;
    color:#2563eb!important;
    border:1px solid rgba(37,99,235,.16);
    box-shadow:0 8px 20px rgba(37,99,235,.06);
    font-size:12px;
    font-weight:900;
}
.ms-hero-banner{
    position:relative;
    overflow:hidden;
    border-radius:26px;
    padding:18px 18px 20px;
    min-height:128px;
    color:#ffffff;
    background:
      radial-gradient(circle at 16% 28%, rgba(255,255,255,.24), transparent 24%),
      linear-gradient(135deg,#60a5fa 0%,#2563eb 100%);
    box-shadow:0 18px 38px rgba(37,99,235,.22);
    border:1px solid rgba(96,165,250,.30);
    margin:12px 0 16px;
}
.ms-hero-banner:before{
    content:"";
    position:absolute;
    left:-36px;
    top:-28px;
    width:112px;
    height:112px;
    border-radius:50%;
    background:rgba(255,255,255,.16);
}
.ms-hero-kicker{
    display:inline-flex;
    align-items:center;
    gap:6px;
    padding:6px 10px;
    border-radius:999px;
    background:rgba(255,255,255,.16);
    font-size:12px;
    font-weight:800;
    margin-bottom:10px;
}
.ms-hero-title{
    font-size:19px;
    line-height:1.55;
    font-weight:900;
    margin:0;
    color:#ffffff!important;
}
.ms-hero-sub{
    color:rgba(255,255,255,.88);
    font-size:12px;
    margin-top:5px;
}
.ms-section-head{
    display:flex;
    align-items:center;
    justify-content:space-between;
    margin:12px 0 10px;
}
.ms-section-head h2{
    font-size:17px!important;
    color:#12325f!important;
    margin:0!important;
}
.ms-section-head a{
    font-size:12px;
    font-weight:900;
    color:#2563eb!important;
}
.ms-fast-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:8px;
    margin-bottom:14px;
}
.ms-fast-card{
    min-height:74px;
    border-radius:20px;
    background:#ffffff;
    border:1px solid rgba(37,99,235,.12);
    box-shadow:0 10px 22px rgba(37,99,235,.07);
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    gap:6px;
    color:#12325f!important;
    font-size:11px;
    font-weight:900;
    text-align:center;
}
.ms-fast-icon{
    font-size:21px;
    line-height:1;
}
.ms-main-grid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:10px;
}
.ms-main-card{
    position:relative;
    overflow:hidden;
    min-height:132px;
    border-radius:24px;
    background:#ffffff;
    border:1px solid rgba(37,99,235,.14);
    box-shadow:0 12px 26px rgba(37,99,235,.08);
    display:flex;
    flex-direction:column;
    justify-content:center;
    align-items:center;
    text-align:center;
    gap:7px;
    padding:14px 10px;
    color:#12325f!important;
}
.ms-main-card:before{
    content:"";
    position:absolute;
    top:0;
    right:18px;
    left:18px;
    height:4px;
    border-radius:0 0 999px 999px;
    background:linear-gradient(90deg,#2563eb,#facc15);
}
.ms-main-icon{
    font-size:30px;
    margin-bottom:2px;
}
.ms-main-title{
    color:#12325f;
    font-size:16px;
    font-weight:950;
    line-height:1.35;
}
.ms-main-sub{
    color:#5f78a0;
    font-size:11px;
    line-height:1.45;
}
.ms-results-wrap{
    margin-top:12px;
}
.ms-results-wrap .card{
    border-radius:22px!important;
}
.ms-bottom-nav{
    position:fixed;
    right:50%;
    transform:translateX(50%);
    bottom:10px;
    z-index:120;
    width:min(94%,500px);
    height:58px;
    display:grid;
    grid-template-columns:repeat(5,1fr);
    gap:4px;
    padding:6px;
    border-radius:22px;
    background:rgba(255,255,255,.88);
    backdrop-filter:blur(14px);
    -webkit-backdrop-filter:blur(14px);
    border:1px solid rgba(37,99,235,.12);
    box-shadow:0 18px 44px rgba(37,99,235,.18);
    direction:rtl;
}
.ms-nav-item{
    border-radius:17px;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    gap:2px;
    color:#5f78a0!important;
    font-size:10px;
    font-weight:900;
}
.ms-nav-item span{font-size:17px;line-height:1}
.ms-nav-item.active{
    background:linear-gradient(180deg,#fde68a,#facc15);
    color:#12325f!important;
    box-shadow:0 8px 18px rgba(250,204,21,.22);
}
.ms-empty-soft{
    background:#ffffff;
    border:1px dashed rgba(37,99,235,.20);
    border-radius:22px;
    padding:18px;
    color:#5f78a0;
    text-align:center;
    font-size:13px;
    font-weight:800;
}
@media(max-width:430px){
    .musattar-app-shell{width:100%;padding:0 8px 12px;margin-top:4px}
    .ms-fast-grid{grid-template-columns:repeat(4,1fr);gap:7px}
    .ms-fast-card{min-height:68px;border-radius:18px;font-size:10px}
    .ms-main-grid{gap:8px}
    .ms-main-card{min-height:122px;border-radius:22px}
    .ms-main-title{font-size:15px}
    .ms-hero-banner{min-height:116px;padding:16px}
    .ms-hero-title{font-size:17px}
    .ms-bottom-nav{height:56px;bottom:8px}
}



/* === HIDE TOP SETTINGS ON HOME, KEEP BOTTOM SETTINGS ONLY === */
.ms-top-spacer{
    width:42px !important;
    height:42px !important;
    display:inline-block !important;
    flex:0 0 42px !important;
}
@media(max-width:520px){
    .ms-top-spacer{width:38px !important;height:38px !important;flex-basis:38px !important;}
}



/* === HIDE TOP SETTINGS ON MODERN HOME VERIFIED === */
body:has(.musattar-app-shell) .settings-floating,
body:has(.musattar-app-shell) .message-floating-wrap{
    display:none !important;
    visibility:hidden !important;
    opacity:0 !important;
    pointer-events:none !important;
}
.musattar-app-shell .musattar-app-top a[href="/settings"],
.musattar-app-shell .musattar-app-top .settings-btn{
    display:none !important;
    visibility:hidden !important;
    opacity:0 !important;
    pointer-events:none !important;
}

</style>

<script>
function attachImageCompressionForms() {
  const forms = document.querySelectorAll('form[enctype="multipart/form-data"]');
  forms.forEach((form) => {
    if (form.dataset.compressBound === '1') return;
    const fileInputs = form.querySelectorAll('input[type="file"]');
    if (!fileInputs.length) return;
    form.dataset.compressBound = '1';
    form.addEventListener('submit', async function(e) {
      if (form.dataset.compressing === '1') return;
      const selectedInputs = Array.from(fileInputs).filter(inp => inp.files && inp.files.length);
      if (!selectedInputs.length) return;
      e.preventDefault();
      form.dataset.compressing = '1';
      const submitBtn = form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
      const oldText = submitBtn ? (submitBtn.innerText || submitBtn.value || '') : '';
      if (submitBtn) {
        if ('disabled' in submitBtn) submitBtn.disabled = true;
        if ('innerText' in submitBtn) submitBtn.innerText = 'جاري تجهيز الصور...';
        else submitBtn.value = 'جاري تجهيز الصور...';
      }
      try {
        for (const input of selectedInputs) {
          const dt = new DataTransfer();
          for (const file of Array.from(input.files)) {
            if (!file.type.startsWith('image/')) { dt.items.add(file); continue; }
            const compressed = await compressImageFile(file);
            dt.items.add(compressed || file);
          }
          input.files = dt.files;
        }
      } catch (err) {
        console.log('compress fallback', err);
      }
      if (submitBtn) {
        if ('innerText' in submitBtn) submitBtn.innerText = 'جاري الرفع...';
        else submitBtn.value = 'جاري الرفع...';
      }
      form.submit();
      setTimeout(() => {
        if (submitBtn) {
          if ('disabled' in submitBtn) submitBtn.disabled = false;
          if ('innerText' in submitBtn) submitBtn.innerText = oldText || 'حفظ';
          else submitBtn.value = oldText || 'حفظ';
        }
        form.dataset.compressing = '0';
      }, 1500);
    });
  });
}
async function compressImageFile(file) {
  if (!(file instanceof File)) return file;
  if (file.size <= 900 * 1024) return file;
  const bitmap = await createImageBitmap(file);
  const maxSide = 1600;
  let { width, height } = bitmap;
  if (Math.max(width, height) > maxSide) {
    const ratio = maxSide / Math.max(width, height);
    width = Math.max(1, Math.round(width * ratio));
    height = Math.max(1, Math.round(height * ratio));
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { alpha: false });
  ctx.drawImage(bitmap, 0, 0, width, height);
  const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.82));
  if (!blob || blob.size >= file.size) return file;
  const name = (file.name || 'image').replace(/\\.[^.]+$/, '') + '.jpg';
  return new File([blob], name, { type: 'image/jpeg', lastModified: Date.now() });
}
document.addEventListener('DOMContentLoaded', attachImageCompressionForms);
</script>

<script>
/* remove top settings on /workers verified */
document.addEventListener('DOMContentLoaded', function(){
  if (window.location.pathname === '/workers' || window.location.pathname.startsWith('/workers-')) {
    document.querySelectorAll('.settings-floating, .message-floating-wrap, .musattar-app-top a[href="/settings"], .musattar-app-top .settings-btn').forEach(function(el){
      try { el.remove(); } catch(e) { el.style.display = 'none'; }
    });
  }
});
</script>

</head>
<body>
"""

def get_unread_message_count(user_id):
    try:
        with get_db() as con:
            row = con.execute(
                "SELECT COUNT(*) AS c FROM messages WHERE receiver_id=? AND COALESCE(is_read,0)=0",
                (user_id,)
            ).fetchone()
            return int((row["c"] if row else 0) or 0)
    except Exception:
        return 0


def message_notifier_html():
    if "user" not in session:
        return ""
    current_user = get_current_session_user()
    if not current_user:
        return ""

    unread_count = get_unread_message_count(current_user["id"])
    badge_html = f'<span id="msg-badge-count" class="msg-badge-count" style="display:{"inline-flex" if unread_count > 0 else "none"};">{unread_count}</span>'

    return f'''
    <div class="message-floating-wrap">
        <a class="message-floating-btn" href="/inbox" title="الرسائل" aria-label="الرسائل">
            💬
            {badge_html}
        </a>
    </div>
    <div id="msg-toast" class="msg-toast" style="display:none;">💬 رسالة جديدة</div>
    <script>
    (function() {{
        let lastUnread = {unread_count};
        let lastToastAt = 0;

        function updateBadge(count) {{
            const badge = document.getElementById('msg-badge-count');
            if (!badge) return;
            if (count > 0) {{
                badge.style.display = 'inline-flex';
                badge.textContent = count;
            }} else {{
                badge.style.display = 'none';
            }}
        }}

        function showToast(text) {{
            const toast = document.getElementById('msg-toast');
            if (!toast) return;
            toast.textContent = text || '💬 رسالة جديدة';
            toast.style.display = 'block';
            toast.classList.add('show');
            setTimeout(function() {{
                toast.classList.remove('show');
                setTimeout(function() {{
                    toast.style.display = 'none';
                }}, 250);
            }}, 3500);
        }}

        async function pollMessageStatus() {{
            if (document.hidden) return;
            try {{
                const res = await fetch('/api/message_status', {{cache: 'no-store'}});
                const data = await res.json();
                if (!data.ok) return;
                const unread = Number(data.unread_count || 0);
                updateBadge(unread);
                if (unread > lastUnread && Date.now() - lastToastAt > 2500) {{
                    lastToastAt = Date.now();
                    showToast('💬 رسالة جديدة');
                }}
                lastUnread = unread;
            }} catch (e) {{}}
        }}

        setInterval(pollMessageStatus, 7000);
    }})();
    </script>
    '''




def push_notifier_html():
    if "user" not in session or not ONESIGNAL_APP_ID:
        return ""
    app_id_js = json.dumps(ONESIGNAL_APP_ID)
    html = """
    <script src="https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.page.js" defer></script>
    <script>
    window.OneSignalDeferred = window.OneSignalDeferred || [];
    window.musattarEnableNotifications = async function() {
        if (!window.OneSignalDeferred) return;
        window.OneSignalDeferred.push(async function(OneSignal) {
            try {
                await OneSignal.init({ appId: __APP_ID__, serviceWorkerPath: "/OneSignalSDKWorker.js" });
                if (OneSignal.Notifications && OneSignal.Notifications.permission !== true) {
                    await OneSignal.Notifications.requestPermission();
                }
                let subId = "";
                try { subId = OneSignal.User && OneSignal.User.PushSubscription ? OneSignal.User.PushSubscription.id : ""; } catch(e) {}
                if (subId) {
                    await fetch('/api/push-subscription', {
                        method:'POST',
                        headers:{'Content-Type':'application/json'},
                        body:JSON.stringify({subscription_id: subId})
                    });
                }
            } catch(e) { console.log('OneSignal init error', e); }
        });
    };
    window.OneSignalDeferred.push(async function(OneSignal) {
        try {
            await OneSignal.init({ appId: __APP_ID__, serviceWorkerPath: "/OneSignalSDKWorker.js" });
            let subId = "";
            try { subId = OneSignal.User && OneSignal.User.PushSubscription ? OneSignal.User.PushSubscription.id : ""; } catch(e) {}
            if (subId) {
                await fetch('/api/push-subscription', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({subscription_id: subId})
                });
            }
            if (OneSignal.User && OneSignal.User.PushSubscription && OneSignal.User.PushSubscription.addEventListener) {
                OneSignal.User.PushSubscription.addEventListener('change', async function(event) {
                    const id = (event && event.current && event.current.id) || (OneSignal.User.PushSubscription.id || '');
                    if (id) {
                        await fetch('/api/push-subscription', {
                            method:'POST',
                            headers:{'Content-Type':'application/json'},
                            body:JSON.stringify({subscription_id: id})
                        });
                    }
                });
            }
        } catch(e) { console.log('OneSignal passive init error', e); }
    });
    </script>
    """
    return html.replace("__APP_ID__", app_id_js)

def settings_corner():
    hidden_paths = {"/login", "/register", "/forgot", "/reset"}
    # إلغاء أيقونات الإعدادات/الرسائل العلوية من كل صفحات الأقسام.
    if request.path.startswith("/workers"):
        return ""
    if "user" in session and request.path not in hidden_paths:
        return '''
        <div class="settings-floating">
            <a class="settings-btn" href="/settings" title="الإعدادات" aria-label="الإعدادات">⚙️</a>
        </div>
        ''' + message_notifier_html() + push_notifier_html()
    return ""


@app.route("/api/push-subscription", methods=["POST"])
def api_push_subscription():
    if "user" not in session:
        return jsonify({"ok": False, "error": "login_required"}), 401
    current_user = get_current_session_user()
    if not current_user:
        return jsonify({"ok": False, "error": "user_not_found"}), 404
    data = request.get_json(silent=True) or {}
    subscription_id = sanitize_input(data.get("subscription_id", ""), 220)
    player_id = sanitize_input(data.get("player_id", ""), 220)
    if not subscription_id and not player_id:
        return jsonify({"ok": False, "error": "missing_subscription"}), 400
    try:
        with get_db() as con:
            if subscription_id and player_id:
                con.execute(
                    "UPDATE users SET onesignal_subscription_id=?, onesignal_player_id=?, push_enabled=1 WHERE id=?",
                    (subscription_id, player_id, current_user["id"])
                )
            elif subscription_id:
                con.execute(
                    "UPDATE users SET onesignal_subscription_id=?, push_enabled=1 WHERE id=?",
                    (subscription_id, current_user["id"])
                )
            else:
                con.execute(
                    "UPDATE users SET onesignal_player_id=?, push_enabled=1 WHERE id=?",
                    (player_id, current_user["id"])
                )
            con.commit()
        return jsonify({"ok": True})
    except Exception as e:
        print("PUSH SUBSCRIPTION SAVE ERROR:", repr(e))
        return jsonify({"ok": False, "error": "save_failed"}), 500


@app.route("/api/push-disable", methods=["POST"])
def api_push_disable():
    if "user" not in session:
        return jsonify({"ok": False, "error": "login_required"}), 401
    current_user = get_current_session_user()
    if not current_user:
        return jsonify({"ok": False, "error": "user_not_found"}), 404
    try:
        with get_db() as con:
            con.execute("UPDATE users SET push_enabled=0 WHERE id=?", (current_user["id"],))
            con.commit()
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "save_failed"}), 500


@app.route("/OneSignalSDKWorker.js")
@app.route("/OneSignalSDKUpdaterWorker.js")
def onesignal_service_worker():
    js = "importScripts('https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.sw.js');"
    return app.response_class(js, mimetype="application/javascript")


HOME_HTML = STYLE + """
<div class="container narrow-container" style="margin-top:70px;text-align:center;">
    <h1 style="font-size:42px;margin-bottom:20px;">المسطر</h1>
    <div class="section-subtitle" style="margin-bottom:18px;">تسجيل دخول المختصين فقط. الزائر يستطيع الدخول والتصفح مباشرة بدون إنشاء حساب.</div>

    <form action="/login" method="post">
        <input type="email" name="email" value="{{ last_email }}" placeholder="البريد الإلكتروني للمختص" required>
        <input type="password" name="password" placeholder="كلمة سر المختص" required>
        <button type="submit">تسجيل دخول المختص</button>
    </form>

    <a href="/workers" class="visitor-big-entry">
        <div class="visitor-big-icon">👤</div>
        <div class="visitor-big-title">الدخول كزائر</div>
        <div class="visitor-big-subtitle">تصفح الأقسام والمختصين بدون تسجيل دخول</div>
    </a>

    <div class="inline" style="justify-content:space-between;margin-top:14px;">
        <a href="/register" style="color:#ffd966;font-weight:700;">إنشاء حساب مختص</a>
        <a href="/forgot" style="color:#c8b36a;">نسيت كلمة السر</a>
    </div>
</div>

<style>
.visitor-big-entry{
    display:block;
    margin:22px auto 4px;
    padding:24px 18px;
    border-radius:26px;
    background:linear-gradient(180deg,#ffd966 0%,#b8860b 100%);
    color:#000 !important;
    border:1px solid rgba(255,217,102,.55);
    box-shadow:0 14px 32px rgba(212,160,23,.30);
    text-align:center;
}
.visitor-big-icon{
    width:86px;
    height:86px;
    margin:0 auto 10px;
    border-radius:50%;
    background:rgba(0,0,0,.14);
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:48px;
}
.visitor-big-title{
    font-size:25px;
    font-weight:900;
    margin-bottom:6px;
}
.visitor-big-subtitle{
    font-size:14px;
    font-weight:700;
    opacity:.88;
}
.visitor-big-entry:hover{
    transform:translateY(-2px);
    filter:brightness(1.04);
}
@media(max-width:520px){
    .visitor-big-entry{padding:20px 14px;border-radius:22px;}
    .visitor-big-icon{width:74px;height:74px;font-size:40px;}
    .visitor-big-title{font-size:22px;}
}
</style>

<a class="bottom-corner-link bottom-left-link" href="/admin">🛠️</a>
</body></html>
"""


@app.route("/")
def home():
    auto_login_from_cookie()

    if "user" in session:
        return redirect(url_for("workers"))

    return render_template_string(
        HOME_HTML,
        last_email=(
            session.get("last_email")
            or request.cookies.get("remember_email", "")
        )
    )

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

        session.clear()
        session.permanent = True
        session["last_email"] = email
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        session["role"] = user["role"] or "worker"
        session["last_email"] = user["email"] or email
        remember_token = store_remember_token(user["id"])
        LOGIN_ATTEMPTS.pop(ip, None)
        resp = redirect(url_for("workers"))
        resp.set_cookie("remember_email", email, max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
        resp.set_cookie("remember_token", remember_token, max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
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

        session.clear()
        session.permanent = True
        session["user"] = user["name"]
        session["user_id"] = user["id"]
        session["role"] = "visitor"
        session["last_email"] = user["email"] or email
        remember_token = store_remember_token(user["id"])
        LOGIN_ATTEMPTS.pop(f"visitor:{ip}", None)
        resp = redirect(url_for("workers"))
        resp.set_cookie("remember_email", email, max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
        resp.set_cookie("remember_token", remember_token, max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
        return resp

    remembered_email = session.get("last_email") or request.cookies.get("remember_email", "")
    return render_template_string(
        STYLE + """
        <div class="container narrow-container" style="margin-top:70px;">
            <a href="/"><button class="light-btn">رجوع للرئيسية</button></a>
            <h2>دخول الزائر</h2>
            <div class="section-subtitle">إذا كان عندك حساب زائر، سجّل دخولك من هنا.</div>
            <form method="post">
                <input type="email" name="email" value="{{ remembered_email }}" placeholder="البريد الإلكتروني" required>
                <input type="password" name="password" placeholder="كلمة السر" required>
                <button>دخول الزائر</button>
            </form>
            <div class="inline" style="justify-content:space-between;margin-top:12px;">
                <div class="notice" style="margin:0;">ما عندك حساب؟ <a href="/visitor/register" style="color:#93c5fd;font-weight:700;">أنشئ حساب جديد</a></div>
                <a href="/forgot" style="color:#cbd5e1;font-weight:700;">نسيت كلمة السر</a>
            </div>
        </div>
        </body></html>
        """, remembered_email=remembered_email
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
        otp = str(random.randint(100000, 999999))
        set_pending_registration(d, otp, "visitor")

        sent = send_registration_otp(d["email"], otp)
        if not sent:
            clear_pending_registration()
            return render_template_string(STYLE + '<div class="container"><div class="msg">فشل إرسال كود التحقق إلى البريد الإلكتروني</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        return redirect(url_for("visitor_verify"))

    return render_template_string(
        STYLE + """
        <div class="container narrow-container" style="margin-top:70px;">
            <a href="/visitor/login"><button class="light-btn">رجوع</button></a>
            <h2>إنشاء حساب زائر</h2>
            <div class="section-subtitle">أنشئ حساب زائر بسيط بالاسم والبريد الإلكتروني وكلمة السر فقط، وبعدها نرسل كود تحقق إلى بريدك.</div>
            <form method="post">
                <input name="name" placeholder="الاسم" required>
                <input type="email" name="email" placeholder="البريد الإلكتروني" required>
                <input type="password" name="password" placeholder="كلمة السر" required>
                <button>إرسال كود التحقق</button>
            </form>
            <div class="notice">لن يكتمل إنشاء الحساب إلا بعد تأكيد كود التحقق من البريد الإلكتروني.</div>
        </div>
        </body></html>
        """
    )


@app.route("/visitor/verify", methods=["GET", "POST"])
def visitor_verify():
    pending_data = session.get("pending_register_data") or {}
    if session.get("pending_register_role") != "visitor" or not pending_data:
        return redirect(url_for("visitor_register"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if otp_is_expired("pending_register_otp_created_at"):
            clear_pending_registration()
            return render_template_string(STYLE + '<div class="container"><div class="msg">انتهت صلاحية كود التحقق</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        if otp != session.get("pending_register_otp"):
            return render_template_string(STYLE + '<div class="container"><div class="msg">كود التحقق غير صحيح</div><a href="/visitor/verify"><button>رجوع</button></a></div></body></html>')

        ok, msg, next_url = complete_pending_registration()
        clear_pending_registration()
        if not ok:
            return render_template_string(STYLE + f'<div class="container"><div class="msg">{msg}</div><a href="/visitor/register"><button>رجوع</button></a></div></body></html>')

        return render_template_string(STYLE + '<div class="container"><div class="msg">تم تأكيد البريد الإلكتروني وإنشاء الحساب بنجاح</div><a href="/visitor/login"><button>دخول الزائر</button></a></div></body></html>')

    return render_template_string(
        STYLE + f"""
        <div class="container narrow-container" style="margin-top:70px;">
            <a href="/visitor/register"><button class="light-btn">رجوع</button></a>
            <h2>تأكيد البريد الإلكتروني</h2>
            <div class="section-subtitle">أرسلنا كود تحقق إلى البريد: {pending_data.get('email', '')}</div>
            <form method="post">
                <input name="otp" placeholder="كود التحقق" required>
                <button>تأكيد وإنشاء الحساب</button>
            </form>
            <div class="notice">لن يتم إنشاء حساب الزائر إلا بعد إدخال الكود الصحيح.</div>
        </div>
        </body></html>
        """
    )


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
            f"<label style='display:block;text-align:center;'><img src='{media_url(img)}' alt='work'><div class='small'><input type='checkbox' name='remove_images' value='{img}'> حذف هذه الصورة</div></label>"
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
        try:
            profile_pic = save_uploaded_file(profile_file)
        except Exception as e:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">فشل رفع الصورة الشخصية: {str(e)}</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        d["profile_pic"] = profile_pic
        d["work_images"] = ""
        d["password"] = generate_password_hash(d["password"])

        try:
            with get_db() as con:
                old = con.execute("SELECT id FROM users WHERE phone=? OR email=?", (d["phone"], d["email"])).fetchone()
                if old:
                    cleanup_saved_files(d)
                    return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">رقم الهاتف أو البريد مستخدم مسبقاً</div><a href="/register"><button>رجوع</button></a></div></body></html>')
        except Exception:
            cleanup_saved_files(d)
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تعذر التحقق من البيانات حالياً</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        otp = str(random.randint(100000, 999999))
        set_pending_registration(d, otp, "worker")
        sent = send_registration_otp(d["email"], otp)
        if not sent:
            cleanup_saved_files(d)
            clear_pending_registration()
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">فشل إرسال كود التحقق إلى البريد الإلكتروني</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        return redirect(url_for("verify"))

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

                <div class="section-subtitle" style="margin-top:8px;">تقدر تضيف صور أعمالك لاحقاً من داخل الحساب بعد التسجيل.</div>

                <button>إرسال كود التحقق</button>
            </form>
            <div class="section-subtitle" style="margin-top:10px;">لن يكتمل إنشاء الحساب إلا بعد تأكيد كود التحقق المرسل إلى بريدك الإلكتروني.</div>

        </div>
        {specialty_script("")}
        </body></html>
        """
    )


@app.route("/verify", methods=["GET", "POST"])
def verify():
    pending_data = session.get("pending_register_data") or {}
    if session.get("pending_register_role") != "worker" or not pending_data:
        return redirect(url_for("register"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        if otp_is_expired("pending_register_otp_created_at"):
            cleanup_saved_files(pending_data)
            clear_pending_registration()
            return render_template_string(STYLE + '<div class="container"><div class="msg">انتهت صلاحية كود التحقق</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        if otp != session.get("pending_register_otp"):
            return render_template_string(STYLE + '<div class="container"><div class="msg">كود التحقق غير صحيح</div><a href="/verify"><button>رجوع</button></a></div></body></html>')

        ok, msg, next_url = complete_pending_registration()
        clear_pending_registration()
        if not ok:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">{msg}</div><a href="/register"><button>رجوع</button></a></div></body></html>')

        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + f'<div class="container"><div class="msg">{msg}</div><a href="/login"><button>تسجيل الدخول</button></a></div></body></html>')

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container">
            <a href="/register"><button class="light-btn">رجوع</button></a>
            <h2>تأكيد البريد الإلكتروني</h2>
            <div class="section-subtitle">أرسلنا كود تحقق إلى البريد: {pending_data.get('email', '')}</div>
            <form method="post">
                <input name="otp" placeholder="كود التحقق" required>
                <button>تأكيد وإنشاء الحساب</button>
            </form>
            <div class="notice">لن يتم إنشاء الحساب إلا بعد إدخال الكود الصحيح.</div>
        </div>
        </body></html>
        """
    )


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


def get_or_create_conversation(visitor_id, worker_id):
    visitor_id = int(visitor_id)
    worker_id = int(worker_id)

    with get_db() as con:
        row = con.execute(
            "SELECT * FROM conversations WHERE visitor_id=? AND worker_id=?",
            (visitor_id, worker_id)
        ).fetchone()
        if row:
            return row["id"]

        con.execute(
            "INSERT INTO conversations (visitor_id, worker_id, last_message_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (visitor_id, worker_id)
        )
        con.commit()

        row = con.execute(
            "SELECT * FROM conversations WHERE visitor_id=? AND worker_id=?",
            (visitor_id, worker_id)
        ).fetchone()
        return row["id"] if row else 0


def get_conversation_for_user(conversation_id, current_user_id):
    with get_db() as con:
        return con.execute(
            """
            SELECT c.*,
                   v.name AS visitor_name,
                   v.email AS visitor_email,
                   v.profile_pic AS visitor_profile_pic,
                   w.name AS worker_name,
                   w.email AS worker_email,
                   w.profile_pic AS worker_profile_pic,
                   w.allow_messages AS worker_allow_messages
            FROM conversations c
            JOIN users v ON v.id = c.visitor_id
            JOIN users w ON w.id = c.worker_id
            WHERE c.id=? AND (c.visitor_id=? OR c.worker_id=?)
            """,
            (conversation_id, current_user_id, current_user_id)
        ).fetchone()


def get_other_party_from_conversation(conversation, current_user_id):
    if int(conversation["visitor_id"]) == int(current_user_id):
        return {
            "id": conversation["worker_id"],
            "name": conversation["worker_name"],
            "email": conversation["worker_email"],
            "profile_pic": conversation["worker_profile_pic"],
            "role": "worker",
        }
    return {
        "id": conversation["visitor_id"],
        "name": conversation["visitor_name"],
        "email": conversation["visitor_email"],
        "profile_pic": conversation["visitor_profile_pic"],
        "role": "visitor",
    }


def format_chat_datetime(value):
    if value is None:
        return ""
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        value = str(value).strip()
        if not value:
            return ""
        try:
            dt = datetime.datetime.fromisoformat(value)
        except Exception:
            return value
    return dt.strftime("%Y-%m-%d %H:%M")


def build_conversation_messages_html(messages, current_user, other):
    chat_html = ""
    for m in messages:
        mine = int(m["sender_id"] or 0) == int(current_user["id"])
        row_class = "chat-row mine" if mine else "chat-row theirs"
        bubble_class = "chat-bubble mine" if mine else "chat-bubble theirs"
        label = "أنت" if mine else other["name"]
        read_state = ""
        if mine:
            is_read = int(m["is_read"] or 0)
            state_text = "مقروءة" if is_read else "مرسلة"
            state_icon = "✓✓" if is_read else "✓"
            read_state = f'<span class="msg-read-state">{state_icon} {state_text}</span>'
        chat_html += f"""
        <div class="{row_class}">
            <div class="{bubble_class}">
                <div class="msg-label">{label}</div>
                <div class="msg-text">{m["msg"]}</div>
                <div class="msg-meta">
                    <span>{format_chat_datetime(m["created_at"] or "")}</span>
                    {read_state}
                </div>
            </div>
        </div>
        """

    if not chat_html:
        chat_html = '<div class="empty-state">لا توجد رسائل بعد. اكتب أول رسالة الآن.</div>'
    return chat_html


def profile_thumb_html(filename, size_class="profile-img"):
    if filename:
        placeholder_class = "profile-placeholder-large" if size_class == "profile-img-large" else "profile-placeholder"
        return (
            f'<img src="{media_url(filename)}" class="{size_class}" alt="" '
            f'onerror="this.outerHTML=\'<div class=&quot;{placeholder_class}&quot;>👤</div>\'">'
        )
    if size_class == "profile-img-large":
        return '<div class="profile-placeholder-large">👤</div>'
    return '<div class="profile-placeholder">👤</div>'


def worker_card(worker):
    profile_html = (
        f'<img src="{media_url(worker["profile_pic"])}" class="profile-img" alt="" onerror="this.outerHTML=\'<div class=&quot;profile-placeholder&quot;>👤</div>\'">'
        if worker["profile_pic"]
        else '<div class="profile-placeholder">👤</div>'
    )

    work_images_html = ""
    imgs = [x.strip() for x in (worker["work_images"] or "").split(",") if x.strip()]
    if imgs:
        gallery_refs = quote("||".join(imgs), safe="")
        blocks = []
        for idx, img in enumerate(imgs[:6]):
            blocks.append(f'<a class="work-tile" href="{url_for("view_image")}?image={quote(img, safe="")}&images={gallery_refs}&idx={idx}&back=/worker/{worker["id"]}"><img src="{media_url(img)}" alt="work" class="work-thumb"></a>')
        work_images_html = f'<div class="work-grid">{"".join(blocks)}</div>'

    phone_html = f'<div class="info-chip"><strong>الهاتف</strong><div>{worker["phone"]}</div></div>' if worker["show_phone"] else ""
    wa_html = ""
    map_html = ""
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



def build_video_fast_categories():
    # الأقسام السريعة تفتح التقسيمات/الاختصاصات داخل كل قسم
    fast_items = []
    for group_name, items in SPECIALTY_GROUPS.items():
        icon = get_specialty_icon(items[0]) if items else "🛠️"
        fast_items.append((group_name, icon))
    html = '<div class="ms-fast-grid">'
    for group_name, icon in fast_items:
        html += f"""
        <a class="ms-fast-card" href="/workers-group/{group_name}">
            <div class="ms-fast-icon">{icon}</div>
            <div>{group_name}</div>
        </a>
        """
    html += '</div>'
    return html


def build_video_main_categories():
    html = '<div class="ms-main-grid">'
    for group_name, items in SPECIALTY_GROUPS.items():
        icon = get_specialty_icon(items[0]) if items else "🛠️"
        html += f"""
        <a class="ms-main-card" href="/workers-group/{group_name}">
            <div class="ms-main-icon">{icon}</div>
            <div class="ms-main-title">{group_name}</div>
            <div class="ms-main-sub">عرض اختصاصات {group_name}</div>
        </a>
        """
    html += '</div>'
    return html


def build_video_bottom_nav(active="home"):
    favorites_link = "/favorites" if ("user" in session and session.get("role") == "visitor") else "/workers"
    account_link = "/settings" if "user" in session else "/"
    items = [
        ("home", "/workers", "🏠", "الرئيسية"),
        ("sections", "/workers", "☰", "الأقسام"),
        ("work", "/workers", "💼", "العمل"),
        ("favorite", favorites_link, "⭐", "المفضلة"),
        ("settings", account_link, "⚙️", "إعدادات"),
    ]
    html = '<div class="ms-bottom-nav">'
    for key, href, icon, label in items:
        cls = " active" if key == active else ""
        html += f'<a class="ms-nav-item{cls}" href="{href}"><span>{icon}</span><small>{label}</small></a>'
    html += '</div>'
    return html


def search_workers_rows(q="", governorate="", specialty="", limit=40):
    q = sanitize_input(q, 80)
    governorate = sanitize_input(governorate, 80)
    specialty = sanitize_input(specialty, 80)
    sql = """
        SELECT *
        FROM users
        WHERE is_verified=1
          AND COALESCE(is_blocked,0)=0
          AND COALESCE(hidden_by_admin,0)=0
          AND (role='worker' OR role IS NULL)
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (name LIKE ? OR city LIKE ? OR governorate LIKE ? OR section LIKE ?)"
        params.extend([like, like, like, like])
    if governorate and governorate in IRAQ_GOVERNORATES:
        sql += " AND governorate=?"
        params.append(governorate)
    if specialty and specialty in SPECIALTIES:
        sql += " AND section=?"
        params.append(specialty)
    sql += " ORDER BY is_pinned DESC, views DESC, id DESC LIMIT ?"
    params.append(int(limit))
    with get_db() as con:
        return con.execute(sql, tuple(params)).fetchall()



@app.route("/workers")
def workers():
    auto_login_from_cookie()

    q = sanitize_input(request.args.get("q", ""), 80)
    governorate = sanitize_input(request.args.get("governorate", ""), 80)
    specialty = sanitize_input(request.args.get("specialty", ""), 80)
    has_search = bool(q or governorate or specialty)

    fast_cards = build_video_fast_categories()
    bottom_nav = build_video_bottom_nav("home")
    gov_options = build_governorates_options(governorate)
    specialty_options = build_specialties_options(specialty, "")

    results_html = ""
    if has_search:
        rows = search_workers_rows(q, governorate, specialty)
        if rows:
            cards = "".join(worker_card(row) for row in rows)
            results_html = f'''
            <div class="ms-results-wrap">
                <div class="ms-section-head">
                    <h2>نتائج البحث</h2>
                    <a href="/workers">مسح البحث</a>
                </div>
                {cards}
            </div>
            '''
        else:
            results_html = '''
            <div class="ms-results-wrap">
                <div class="ms-empty-soft">ماكو نتائج مطابقة حالياً. جرّب اسم أو محافظة ثانية.</div>
            </div>
            '''

    return render_template_string(
        STYLE + f'''
        <div class="musattar-app-shell">

            <div class="musattar-app-top">
                <a class="ms-round-btn" href="/">‹</a>
                <div class="ms-title-lockup">
                    <span>المسطر</span>
                    <span class="ms-title-logo">🏗️</span>
                </div>
                <span class="ms-top-spacer" aria-hidden="true"></span>
            </div>

            <!-- تم إلغاء مربع البحث السريع من الصفحة الرئيسية بطلبك -->

            <div class="ms-hero-banner">
                <div class="ms-hero-kicker">✨ تطبيق خدمات البناء</div>
                <h1 class="ms-hero-title">كل مختص تحتاجه تلقاه بسرعة</h1>
                <div class="ms-hero-sub">اختر القسم، شوف الأعمال والفيديوهات، وتواصل واتساب مباشرة.</div>
            </div>

            {results_html}

            <div class="ms-section-head">
                <h2>الأقسام السريعة</h2>
                <span></span>
            </div>
            {fast_cards}

            {bottom_nav}
        </div>
        </body></html>
        '''
    )


@app.route("/workers-quick/<path:group_name>")
def workers_quick_group(group_name):
    # أي رابط قديم للأقسام السريعة يحوّل الآن إلى صفحة التقسيمات/الاختصاصات
    group_name = sanitize_input(group_name, 80)
    return redirect(url_for("workers_group", group_name=group_name))


@app.route("/workers-group/<path:group_name>")
def workers_group(group_name):
    auto_login_from_cookie()
    group_name = sanitize_input(group_name, 80)

    if group_name not in SPECIALTY_GROUPS:
        return render_template_string(
            STYLE + '''
            <div class="container">
                <div class="msg">القسم المطلوب غير موجود</div>
                <a href="/workers"><button>رجوع</button></a>
            </div>
            </body></html>
            '''
        )

    specialties_cards = build_group_specialties_cards(group_name)
    bottom_nav = build_video_bottom_nav("sections")

    user_buttons = ""

    return render_template_string(
        STYLE + f'''
        <div class="container">
            <div class="topbar">
                <div><a href="/workers"><button class="light-btn">رجوع للأقسام</button></a></div>
                <div class="inline"><span class="badge">{group_name}</span></div>
            </div>

            <div class="hero-panel" style="margin-bottom:16px;">
                <h2>اختصاصات {group_name}</h2>
                
            </div>

            {user_buttons}
            {specialties_cards}
            {bottom_nav}
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
            STYLE + '''
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
    bottom_nav = build_video_bottom_nav("sections")

    user_buttons = ""

    return render_template_string(
        STYLE + f'''
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
                
            </div>

            {user_buttons}

            <div id="results" style="margin-top:18px;">
                {cards}
            </div>
            {bottom_nav}
        </div>
        </body></html>
        '''
    )


@app.route("/worker/<int:user_id>", methods=["GET", "POST"])
def worker_profile(user_id):
    try:
        with get_db() as con:
            worker = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            comments = con.execute(
                "SELECT * FROM comments WHERE user_id=? ORDER BY id DESC",
                (user_id,)
            ).fetchall()

        if not worker:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا الملف غير موجود</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

        is_blocked = int((worker["is_blocked"] if worker["is_blocked"] is not None else 0) or 0)
        is_hidden = int((worker["hidden_by_admin"] if worker["hidden_by_admin"] is not None else 0) or 0)
        if is_blocked or is_hidden:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا الملف غير متاح حالياً</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

        with get_db() as con:
            con.execute("UPDATE users SET views = COALESCE(views, 0) + 1 WHERE id=?", (user_id,))
            con.commit()
            worker = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

        current_session_user = get_current_session_user() if "user" in session else None
        current_session_user_id = int(current_session_user["id"]) if current_session_user else None
        is_self_worker_profile = current_session_user_id is not None and int(current_session_user_id) == int(user_id)

        if request.method == "POST":
            if is_self_worker_profile:
                return render_template_string(
                    STYLE + (settings_corner() if 'user' in session else '') +
                    '<div class="container"><div class="msg">لا يمكن لك تقييم أو التعليق على ملفك الشخصي</div><a href="/worker/%d"><button>رجوع</button></a></div></body></html>' % user_id
                )

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

            try:
                notify_new_worker_rating(user_id, commenter_name, rating, comment)
            except Exception as notify_error:
                print("WORKER RATING PUSH ERROR:", repr(notify_error))

            return redirect(url_for("worker_profile", user_id=user_id))

        avg_rating, rating_count = get_worker_rating_summary(user_id)
        stars = render_stars(avg_rating)
        profile_pic = worker["profile_pic"] or ""
        profile_html = profile_thumb_html(profile_pic, "profile-img-large")

        work_images_raw = worker["work_images"] or ""
        imgs = [x.strip() for x in work_images_raw.split(",") if x.strip()]
        work_images_html = ""
        if imgs:
            gallery_refs = quote("||".join(imgs), safe="")
            work_images_html = '<div class="work-grid">' + "".join(
                f'<a class="work-tile" href="{url_for("view_image")}?image={quote(img, safe="")}&images={gallery_refs}&idx={idx}&back=/worker/{worker["id"]}"><img src="{media_url(img)}" alt="work" class="work-thumb"></a>' for idx, img in enumerate(imgs)
            ) + '</div>'

        phone_html = f'<div class="detail-box"><strong>الهاتف</strong>{worker["phone"]}</div>' if int((worker["show_phone"] if worker["show_phone"] is not None else 0) or 0) and worker["phone"] else ""
        wa_html = ""
        map_html = ""
        call_html = f'<a class="action-pill secondary" href="tel:{worker["phone"]}">📞 اتصال</a>' if int((worker["show_phone"] if worker["show_phone"] is not None else 0) or 0) and worker["phone"] else ""

        if int((worker["show_phone"] if worker["show_phone"] is not None else 0) or 0) and worker["phone"]:
            whatsapp_text = quote("السلام عليكم، شاهدت ملفك في تطبيق المسطر وأريد أسألك عن خدمة.")
            phone = "".join(ch for ch in str(worker["phone"]) if ch.isdigit())
            if phone.startswith("0"):
                phone = "964" + phone[1:]
            whatsapp_url = f"https://api.whatsapp.com/send?phone={phone}&text={whatsapp_text}"
            wa_html = f'<a class="action-pill whatsapp-pill" href="{whatsapp_url}" target="_blank" rel="noopener">🟢 واتساب فقط</a>'

        comments_html = ""
        if comments:
            blocks = []
            for c in comments:
                cstars = "★" * int(c["rating"] or 0) + "☆" * (5 - int(c["rating"] or 0))
                blocks.append(f"""
                <div class="review-card-pro">
                    <div class="review-top">
                        <div>
                            <div class="review-name">{c["commenter_name"]}</div>
                            <div class="review-date">{format_chat_datetime(c["created_at"] or "")}</div>
                        </div>
                        <div class="rating-pill">{cstars}</div>
                    </div>
                    <div class="review-text">{c["comment"]}</div>
                </div>
                """)
            comments_html = "".join(blocks)
        else:
            comments_html = '<div class="empty-state">لا توجد تقييمات بعد</div>'

        message_button = ""

        favorite_button = ""
        if "user" in session and session.get("role") == "visitor":
            fav_on = is_favorite(session.get("user_id"), worker["id"])
            fav_text = "💔 إزالة من المفضلة" if fav_on else "❤️ إضافة للمفضلة"
            favorite_button = f'<a class="action-pill secondary" href="/toggle-favorite/{worker["id"]}?next=/worker/{worker["id"]}">{fav_text}</a>'

        works_count = len(imgs)
        city_value = worker["city"] or "-"
        exp_value = worker["exp"] or "-"
        message_status_value = 'مفعل' if int((worker["allow_messages"] if worker["allow_messages"] is not None else 0) or 0) else 'معطل'
        stats_html = f"""
            <div class="stat-mini-grid">
                <div class="stat-mini-card"><div class="stat-mini-label">التقييم</div><div class="stat-mini-value">{avg_rating}</div></div>
                <div class="stat-mini-card"><div class="stat-mini-label">التقييمات</div><div class="stat-mini-value">{rating_count}</div></div>
                <div class="stat-mini-card"><div class="stat-mini-label">الأعمال</div><div class="stat-mini-value">{works_count}</div></div>
                <div class="stat-mini-card"><div class="stat-mini-label">المشاهدات</div><div class="stat-mini-value">{worker["views"] or 0}</div></div>
            </div>
        """

        verified_badge = trusted_badge_html(worker)
        pinned_badge = pinned_badge_html(worker)

        comment_form = ""
        if not is_self_worker_profile:
            comment_form = """
            <div class="card review-form-pro">
                <h3>إضافة تقييم</h3>
                <div class="section-subtitle">اختر التقييم ثم اكتب رأيك بشكل مختصر وواضح.</div>
                <form method="post">
                    <div class="rating-row">
                        <label><input type="radio" name="rating" value="5" checked><span class="rate-pill">⭐⭐⭐⭐⭐</span></label>
                        <label><input type="radio" name="rating" value="4"><span class="rate-pill">⭐⭐⭐⭐</span></label>
                        <label><input type="radio" name="rating" value="3"><span class="rate-pill">⭐⭐⭐</span></label>
                        <label><input type="radio" name="rating" value="2"><span class="rate-pill">⭐⭐</span></label>
                        <label><input type="radio" name="rating" value="1"><span class="rate-pill">⭐</span></label>
                    </div>
                    <textarea name="comment" placeholder="اكتب تقييمك وتعليقك" required></textarea>
                    <button>نشر التقييم</button>
                </form>
            </div>
            """

        return render_template_string(
            STYLE + (settings_corner() if 'user' in session else '') + f"""
            <div class="container">
                <a href="/workers"><button class="light-btn">رجوع</button></a>

                <div class="worker-hero worker-hero-pro">
                    <div class="worker-hero-grid">
                        <div class="center">{profile_html}</div>
                        <div>
                            <div class="inline" style="margin-bottom:10px;">
                                <span class="worker-specialty-badge">{get_specialty_icon(worker["section"])} {worker["section"] or "-"}</span>
                                <span class="badge">{worker["governorate"] or "-"}</span>
                                {verified_badge}
                                {pinned_badge}
                            </div>
                            <h2>{worker["name"]}</h2>
                            <div class="worker-rating-line">
                                <span class="rating-stars">{stars}</span>
                                <span class="badge">⭐ {avg_rating} / 5</span>
                                <span class="badge">{rating_count} تقييم</span>
                            </div>
                            <div class="section-subtitle">ملف مرتب يعرض نبذة المختص وأعماله وطرق التواصل بشكل أوضح وأسهل.</div>
                            <div class="profile-bio-box">{worker["bio"] or "لا توجد نبذة حالياً"}</div>
                            {stats_html}

                            <div class="detail-grid">
                                <div class="detail-box"><strong>المدينة</strong>{city_value}</div>
                                <div class="detail-box"><strong>الخبرة</strong>{exp_value}</div>
                                {phone_html}
                                <div class="detail-box"><strong>استقبال الرسائل</strong>{message_status_value}</div>
                            </div>

                            <div class="profile-actions-bar">
                                {message_button}
                                {favorite_button}
                                {wa_html}
                                {call_html}
                                {map_html}
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="gallery-head">
                        <h3>معرض الأعمال</h3>
                        <span class="badge">{works_count} صورة</span>
                    </div>
                    <div class="section-subtitle">صور الأعمال المعروضة داخل الملف الشخصي.</div>
                    {work_images_html if work_images_html else '<div class="empty-state">لا توجد أعمال حتى الآن</div>'}
                </div>

                <div class="card">
                    <div class="reviews-head">
                        <h3>التقييمات</h3>
                        <span class="badge">{rating_count} تقييم</span>
                    </div>
                    {comments_html}
                </div>
                {comment_form}
            </div>
            </body></html>
            """
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template_string(STYLE + '<div class="container"><div class="msg">صار خطأ أثناء فتح الملف الشخصي</div><div class="notice">' + sanitize_input(str(e), 300) + '</div><a href="/workers"><button>رجوع</button></a></div></body></html>')


@app.route("/favorites")
def favorites_page():
    if "user" not in session:
        return redirect(url_for("visitor_login"))
    if session.get("role") != "visitor":
        return redirect(url_for("workers"))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("visitor_login"))

    with get_db() as con:
        rows = con.execute(
            """
            SELECT u.*, f.created_at AS favorited_at
            FROM favorites f
            JOIN users u ON u.id = f.worker_id
            WHERE f.visitor_id=?
              AND COALESCE(u.is_blocked,0)=0
              AND COALESCE(u.hidden_by_admin,0)=0
            ORDER BY f.id DESC
            """,
            (current_user["id"],)
        ).fetchall()

    cards = "".join(worker_card(row) for row in rows) if rows else '<div class="empty-state">ماكو مختصين محفوظين بالمفضلة بعد</div>'
    total = len(rows)

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container">
            <a href="/workers"><button class="light-btn">رجوع</button></a>
            <h2>المفضلة ❤️</h2>
            <div class="section-subtitle">هنا تظهر كل المختصين اللي حفظتهم حتى ترجع لهم بسرعة.</div>
            <div class="inline" style="margin-bottom:14px;">
                <span class="badge">عدد المحفوظين: {total}</span>
            </div>
            {cards}
        </div>
        </body></html>
        """
    )


@app.route("/toggle-favorite/<int:worker_id>")
def toggle_favorite(worker_id):
    if "user" not in session:
        return redirect(url_for("visitor_login"))
    if session.get("role") != "visitor":
        return redirect(url_for("worker_profile", user_id=worker_id))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("visitor_login"))

    with get_db() as con:
        worker = con.execute("SELECT * FROM users WHERE id=?", (worker_id,)).fetchone()
        if not worker or worker["role"] != "worker":
            return redirect(url_for("workers"))

        row = con.execute(
            "SELECT id FROM favorites WHERE visitor_id=? AND worker_id=?",
            (current_user["id"], worker_id)
        ).fetchone()

        if row:
            con.execute(
                "DELETE FROM favorites WHERE visitor_id=? AND worker_id=?",
                (current_user["id"], worker_id)
            )
        else:
            con.execute(
                "INSERT OR IGNORE INTO favorites (visitor_id, worker_id) VALUES (?, ?)",
                (current_user["id"], worker_id)
            )
        con.commit()

    next_url = request.args.get("next", "").strip()
    if next_url.startswith("/"):
        return redirect(next_url)
    return redirect(url_for("worker_profile", user_id=worker_id))


@app.route("/message/<int:user_id>", methods=["GET", "POST"])
def message_user(user_id):
    if "user" not in session:
        return redirect(url_for("login"))

    sender = get_current_session_user()
    if not sender:
        session.clear()
        return redirect(url_for("login"))

    with get_db() as con:
        receiver = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not receiver:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">المستخدم غير موجود</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

    if int(receiver["id"]) == int(sender["id"]):
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">لا يمكنك مراسلة نفسك</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

    if session.get("role") != "visitor" and receiver["role"] == "visitor":
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">المحادثات متاحة بين الزائر والمختص فقط</div><a href="/workers"><button>رجوع</button></a></div></body></html>')

    if session.get("role") == "visitor" and not receiver["allow_messages"]:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا المستخدم عطّل استقبال الرسائل</div><a href="/worker/%d"><button>رجوع</button></a></div></body></html>' % user_id)

    if session.get("role") == "visitor":
        conversation_id = get_or_create_conversation(sender["id"], receiver["id"])
    else:
        conversation_id = get_or_create_conversation(receiver["id"], sender["id"])

    if request.method == "POST":
        msg = sanitize_input(request.form.get("msg", ""), 1000)
        if not msg:
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">اكتب الرسالة أولاً</div><a href="/conversation/%d"><button>رجوع</button></a></div></body></html>' % conversation_id)

        ip = get_client_ip()
        key = f"{ip}:{sender['id']}:{receiver['id']}"
        if too_many_attempts(MESSAGE_RATE_LIMIT, key, MESSAGE_WINDOW_SECONDS, MESSAGE_MAX_COUNT):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تم تجاوز عدد الرسائل المسموح مؤقتاً</div><a href="/conversation/%d"><button>رجوع</button></a></div></body></html>' % conversation_id)

        with get_db() as con:
            con.execute(
                """
                INSERT INTO messages
                (conversation_id, sender_id, receiver_id, sender_role, receiver_role, sender_name, receiver_name, msg, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    conversation_id,
                    sender["id"],
                    receiver["id"],
                    sender["role"] or session.get("role", ""),
                    receiver["role"] or "",
                    sender["name"],
                    receiver["name"],
                    msg,
                )
            )
            con.execute(
                "UPDATE conversations SET last_message_at=CURRENT_TIMESTAMP WHERE id=?",
                (conversation_id,)
            )
            con.commit()

        try:
            notify_new_direct_message(receiver["id"], sender["name"], msg, conversation_id)
        except Exception as notify_error:
            print("DIRECT MESSAGE PUSH ERROR:", repr(notify_error))

        return redirect(url_for("conversation_view", conversation_id=conversation_id))

    return redirect(url_for("conversation_view", conversation_id=conversation_id))


@app.route("/conversation/<int:conversation_id>/messages_fragment")
def conversation_messages_fragment(conversation_id):
    if "user" not in session:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return jsonify({"ok": False, "error": "session_expired"}), 401

    conversation = get_conversation_for_user(conversation_id, current_user["id"])
    if not conversation:
        return jsonify({"ok": False, "error": "not_found"}), 404

    other = get_other_party_from_conversation(conversation, current_user["id"])

    with get_db() as con:
        messages = con.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC",
            (conversation_id,)
        ).fetchall()
        con.execute(
            "UPDATE messages SET is_read=1 WHERE conversation_id=? AND receiver_id=?",
            (conversation_id, current_user["id"])
        )
        con.commit()

    html = build_conversation_messages_html(messages, current_user, other)
    last_id = messages[-1]["id"] if messages else 0
    return jsonify({"ok": True, "html": html, "last_id": last_id, "count": len(messages)})


@app.route("/conversation/<int:conversation_id>", methods=["GET", "POST"])
def conversation_view(conversation_id):
    if "user" not in session:
        return redirect(url_for("login"))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    conversation = get_conversation_for_user(conversation_id, current_user["id"])
    if not conversation:
        return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">المحادثة غير موجودة أو غير متاحة لك</div><a href="/inbox"><button>رجوع</button></a></div></body></html>')

    other = get_other_party_from_conversation(conversation, current_user["id"])

    if request.method == "POST":
        msg = sanitize_input(request.form.get("msg", ""), 1000)
        if not msg:
            return redirect(url_for("conversation_view", conversation_id=conversation_id))

        if session.get("role") == "visitor" and other["role"] == "worker" and not int(conversation["worker_allow_messages"] or 0):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">هذا المستخدم عطّل استقبال الرسائل</div><a href="/inbox"><button>رجوع</button></a></div></body></html>')

        ip = get_client_ip()
        key = f"{ip}:{current_user['id']}:{other['id']}"
        if too_many_attempts(MESSAGE_RATE_LIMIT, key, MESSAGE_WINDOW_SECONDS, MESSAGE_MAX_COUNT):
            return render_template_string(STYLE + (settings_corner() if 'user' in session else '') + '<div class="container"><div class="msg">تم تجاوز عدد الرسائل المسموح مؤقتاً</div><a href="/conversation/%d"><button>رجوع</button></a></div></body></html>' % conversation_id)

        with get_db() as con:
            con.execute(
                """
                INSERT INTO messages
                (conversation_id, sender_id, receiver_id, sender_role, receiver_role, sender_name, receiver_name, msg, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    conversation_id,
                    current_user["id"],
                    other["id"],
                    current_user["role"] or session.get("role", ""),
                    other["role"],
                    current_user["name"],
                    other["name"],
                    msg,
                )
            )
            con.execute(
                "UPDATE conversations SET last_message_at=CURRENT_TIMESTAMP WHERE id=?",
                (conversation_id,)
            )
            con.commit()

        try:
            notify_new_direct_message(other["id"], current_user["name"], msg, conversation_id)
        except Exception as notify_error:
            print("CONVERSATION MESSAGE PUSH ERROR:", repr(notify_error))

        return redirect(url_for("conversation_view", conversation_id=conversation_id))

    with get_db() as con:
        messages = con.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC",
            (conversation_id,)
        ).fetchall()
        con.execute(
            "UPDATE messages SET is_read=1 WHERE conversation_id=? AND receiver_id=?",
            (conversation_id, current_user["id"])
        )
        con.commit()

    chat_html = build_conversation_messages_html(messages, current_user, other)
    header_profile = profile_thumb_html(other.get("profile_pic"), "profile-img")
    header_badge = "مختص" if other["role"] == "worker" else "زائر"

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <style>
        .conversation-shell{{max-width:860px;margin:0 auto;}}
        .chat-screen{{background:linear-gradient(180deg, rgba(255,255,255,.03) 0%, rgba(255,255,255,.02) 100%);border:1px solid rgba(96,165,250,.20);border-radius:26px;box-shadow:0 18px 45px rgba(2,6,23,.22);overflow:hidden;}}
        .chat-topbar{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;background:linear-gradient(180deg, rgba(37,99,235,.22), rgba(37,99,235,.10));border-bottom:1px solid rgba(96,165,250,.18);}}
        .chat-topbar-right{{display:flex;align-items:center;gap:12px;min-width:0;}}
        .chat-user-meta{{min-width:0;}}
        .chat-user-meta h3{{margin:0 0 4px 0;font-size:20px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
        .chat-user-sub{{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
        .chat-header-actions{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end;}}
        .chat-status-chip{{padding:6px 10px;border-radius:999px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.10);font-size:12px;color:var(--muted);}}
        .chat-body{{padding:16px;background:
            radial-gradient(circle at top right, rgba(59,130,246,.10), transparent 30%),
            radial-gradient(circle at bottom left, rgba(99,102,241,.08), transparent 26%),
            rgba(15,23,42,.18);}}
        .chat-messages{{padding:8px 6px;max-height:480px;overflow:auto;scroll-behavior:smooth;}}
        .chat-row{{display:flex;margin:10px 0;}}
        .chat-row.mine{{justify-content:flex-end;}}
        .chat-row.theirs{{justify-content:flex-start;}}
        .chat-bubble{{max-width:min(78%, 560px);padding:12px 14px;border-radius:22px;border:1px solid rgba(148,163,184,.14);backdrop-filter:blur(6px);}}
        .chat-bubble.mine{{background:linear-gradient(180deg,#2563eb 0%, #1d4ed8 100%);color:#fff;border-bottom-left-radius:22px;border-bottom-right-radius:8px;box-shadow:0 10px 24px rgba(37,99,235,.24);}}
        .chat-bubble.theirs{{background:rgba(255,255,255,.08);color:var(--text);border-bottom-left-radius:8px;border-bottom-right-radius:22px;}}
        .msg-label{{font-size:12px;opacity:.84;margin-bottom:5px;}}
        .msg-text{{white-space:pre-wrap;word-break:break-word;line-height:1.7;font-size:15px;}}
        .msg-meta{{margin-top:7px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:11px;opacity:.92;}}
        .msg-read-state{{opacity:.98;}}
        .chat-compose{{padding:14px 16px 16px 16px;background:rgba(2,6,23,.18);border-top:1px solid rgba(96,165,250,.14);}}
        .chat-compose form{{margin:0;display:flex;align-items:flex-end;gap:10px;}}
        .chat-compose textarea{{margin:0;min-height:54px;max-height:140px;border-radius:18px;padding:14px 16px;resize:vertical;background:rgba(255,255,255,.08);}}
        .chat-send-btn{{min-width:56px;height:54px;border-radius:18px;padding:0 16px;font-size:22px;display:flex;align-items:center;justify-content:center;box-shadow:0 12px 24px rgba(37,99,235,.22);}}
        .chat-empty-note{{padding:0 0 10px 0;font-size:12px;color:var(--muted);}}
        @media (max-width: 640px){{
            .conversation-shell{{max-width:100%;}}
            .chat-topbar{{padding:12px;}}
            .chat-user-meta h3{{font-size:18px;}}
            .chat-header-actions{{gap:6px;}}
            .chat-bubble{{max-width:88%;}}
            .chat-compose form{{gap:8px;}}
            .chat-send-btn{{min-width:50px;height:50px;border-radius:16px;font-size:20px;}}
        }}
        </style>
        <div class="container narrow-container conversation-shell">
            <div style="margin-bottom:12px;"><a href="/inbox"><button class="light-btn">رجوع للرسائل</button></a></div>

            <div class="chat-screen">
                <div class="chat-topbar">
                    <div class="chat-topbar-right">
                        <div>{header_profile}</div>
                        <div class="chat-user-meta">
                            <h3>{other["name"]}</h3>
                            <div class="chat-user-sub">{other["email"] or header_badge}</div>
                        </div>
                    </div>
                    <div class="chat-header-actions">
                        <span class="chat-status-chip">{header_badge}</span>
                        {"<a class='link-btn' href='/worker/%d'>الملف</a>" % other["id"] if other["role"] == "worker" else ""}
                    </div>
                </div>

                <div class="chat-body">
                    <div class="chat-empty-note">✓ مرسلة &nbsp;&nbsp; ✓✓ مقروءة</div>
                    <div id="chat-box" class="chat-messages">{chat_html}</div>
                </div>

                <div class="chat-compose">
                    <form method="post" id="chat-form">
                        <textarea id="msg-input" name="msg" placeholder="اكتب رسالتك هنا" required></textarea>
                        <button class="chat-send-btn" aria-label="إرسال">📨</button>
                    </form>
                </div>
            </div>
        </div>
        <script>
        (function() {{
            const chatBox = document.getElementById('chat-box');
            const msgInput = document.getElementById('msg-input');
            const chatForm = document.getElementById('chat-form');
            let lastHtml = chatBox ? chatBox.innerHTML : '';

            function nearBottom() {{
                if (!chatBox) return true;
                return (chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight) < 120;
            }}

            function scrollToBottom(force) {{
                if (!chatBox) return;
                if (force || nearBottom()) {{
                    chatBox.scrollTop = chatBox.scrollHeight;
                }}
            }}

            async function refreshChat() {{
                if (document.hidden) return;
                if (msgInput && msgInput.value.trim().length > 0) return;
                try {{
                    const res = await fetch('/conversation/{conversation_id}/messages_fragment', {{cache: 'no-store'}});
                    const data = await res.json();
                    if (!data.ok) return;
                    const shouldStickBottom = nearBottom();
                    if (typeof data.html === 'string' && data.html !== lastHtml) {{
                        chatBox.innerHTML = data.html;
                        lastHtml = data.html;
                        scrollToBottom(shouldStickBottom);
                    }}
                }} catch (e) {{}}
            }}

            if (msgInput && chatForm) {{
                msgInput.addEventListener('keydown', function(e) {{
                    if (e.key === 'Enter' && !e.shiftKey) {{
                        e.preventDefault();
                        if (msgInput.value.trim()) chatForm.submit();
                    }}
                }});
                setTimeout(() => msgInput.focus(), 180);
            }}

            scrollToBottom(true);
            setInterval(refreshChat, 5000);
        }})();
        </script>
        </body></html>
        """
    )


@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    with get_db() as con:
        conversations = con.execute(
            """
            SELECT c.*,
                   v.name AS visitor_name,
                   v.profile_pic AS visitor_profile_pic,
                   w.name AS worker_name,
                   w.profile_pic AS worker_profile_pic,
                   (
                       SELECT msg FROM messages m
                       WHERE m.conversation_id = c.id
                       ORDER BY m.id DESC
                       LIMIT 1
                   ) AS last_message,
                   (
                       SELECT COUNT(*)
                       FROM messages um
                       WHERE um.conversation_id = c.id
                         AND um.receiver_id = ?
                         AND COALESCE(um.is_read,0)=0
                   ) AS unread_count
            FROM conversations c
            JOIN users v ON v.id = c.visitor_id
            JOIN users w ON w.id = c.worker_id
            WHERE c.visitor_id=? OR c.worker_id=?
            ORDER BY COALESCE(c.last_message_at, c.created_at) DESC, c.id DESC
            """,
            (current_user["id"], current_user["id"], current_user["id"])
        ).fetchall()

    if not conversations:
        messages_html = '<div class="msg">لا توجد محادثات بعد</div>'
    else:
        blocks = []
        for row in conversations:
            if int(row["visitor_id"]) == int(current_user["id"]):
                other_name = row["worker_name"]
                other_profile = row["worker_profile_pic"]
                other_role = "مختص"
            else:
                other_name = row["visitor_name"]
                other_profile = row["visitor_profile_pic"]
                other_role = "زائر"

            last_message = (row["last_message"] or "لا توجد رسائل بعد").strip()
            if len(last_message) > 70:
                last_message = last_message[:70] + "..."

            unread_count = int(row["unread_count"] or 0)
            updated_at = format_chat_datetime(row["last_message_at"] or row["created_at"] or "")
            unread_dot = f"<div class='chat-unread-badge'>{unread_count}</div>" if unread_count > 0 else ""
            row_border = "border-bottom:1px solid rgba(148,163,184,.18);" 
            preview_style = "font-weight:700;color:#0f172a;" if unread_count > 0 else "color:#475569;"
            name_style = "color:#0f172a;font-weight:800;" if unread_count > 0 else "color:#0f172a;font-weight:700;"

            blocks.append(f"""
            <a href="/conversation/{row['id']}" class="chat-list-link">
                <div class="chat-list-row" style="{row_border}">
                    <div class="chat-avatar-wrap">
                        {profile_thumb_html(other_profile, "profile-img")}
                    </div>
                    <div class="chat-main-col">
                        <div class="chat-row-top">
                            <div style="{name_style}">{other_name}</div>
                            <div class="chat-time">{updated_at}</div>
                        </div>
                        <div class="chat-row-bottom">
                            <div class="chat-preview">
                                <span class="small" style="margin-left:6px;">{other_role}</span>
                                <span style="{preview_style}">{last_message}</span>
                            </div>
                            {unread_dot}
                        </div>
                    </div>
                </div>
            </a>
            """)
        messages_html = "".join(blocks)

    title = "محادثاتي" if session.get("role") == "visitor" else "الرسائل الواردة"
    total_unread = sum(int(row["unread_count"] or 0) for row in conversations)

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <style>
            .chat-list-shell {{
                margin-top: 14px;
                background: rgba(255,255,255,.88);
                border: 1px solid rgba(148,163,184,.18);
                border-radius: 18px;
                overflow: hidden;
                box-shadow: 0 12px 28px rgba(15,23,42,.06);
                backdrop-filter: blur(10px);
            }}
            .chat-list-link {{ display:block; text-decoration:none; color:inherit; }}
            .chat-list-row {{
                display:flex; align-items:center; gap:12px; padding:14px 12px;
                transition: background .18s ease, transform .18s ease;
            }}
            .chat-list-link:hover .chat-list-row {{ background: rgba(37,99,235,.05); }}
            .chat-avatar-wrap .profile-img {{ width:54px; height:54px; border-radius:50%; object-fit:cover; }}
            .chat-main-col {{ flex:1; min-width:0; }}
            .chat-row-top, .chat-row-bottom {{
                display:flex; align-items:center; justify-content:space-between; gap:10px;
            }}
            .chat-row-bottom {{ margin-top:6px; }}
            .chat-time {{ font-size:12px; color:#64748b; white-space:nowrap; }}
            .chat-preview {{
                min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
                font-size:14px;
            }}
            .chat-unread-badge {{
                min-width:22px; height:22px; padding:0 7px; border-radius:999px;
                background:#2563eb; color:#fff; display:flex; align-items:center; justify-content:center;
                font-size:12px; font-weight:700; box-shadow:0 6px 14px rgba(37,99,235,.18);
            }}
            .chat-list-header {{
                display:flex; align-items:center; justify-content:space-between; gap:10px;
                margin-bottom:10px; flex-wrap:wrap;
            }}
            .chat-list-chip {{
                display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px;
                background:rgba(37,99,235,.08); color:#1d4ed8; font-size:13px; font-weight:700;
                border:1px solid rgba(37,99,235,.12);
            }}
            @media (max-width: 640px) {{
                .chat-list-row {{ padding:12px 10px; gap:10px; }}
                .chat-avatar-wrap .profile-img {{ width:48px; height:48px; }}
                .chat-preview {{ font-size:13px; }}
            }}
        </style>
        <div class="container">
            <a href="/workers"><button>رجوع</button></a>
            <h2>{title}</h2>
            <div class="chat-list-header">
                <div class="chat-list-chip">💬 غير المقروء: {total_unread}</div>
            </div>
            <div class="chat-list-shell">
                {messages_html}
            </div>
        </div>
        <script>
        setInterval(function() {{
            if (!document.hidden) {{
                window.location.reload();
            }}
        }}, 25000);
        </script>
        </body></html>
        """
    )


@app.route("/api/message_status")
def api_message_status():
    if "user" not in session:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401

    current_user = get_current_session_user()
    if not current_user:
        session.clear()
        return jsonify({"ok": False, "error": "session_expired"}), 401

    return jsonify({
        "ok": True,
        "unread_count": get_unread_message_count(current_user["id"]),
    })


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
        attachment_ref = ""
        attachment_type = ""
        media_file = request.files.get("attachment")

        if media_file and media_file.filename:
            try:
                attachment_ref, attachment_type = save_support_media(media_file)
            except Exception as e:
                return render_template_string(
                    STYLE + (settings_corner() if 'user' in session else '') + f"""
                    <div class="container narrow-container">
                        <div class="msg">تعذر رفع الملف: {str(e)}</div>
                        <a href="/support"><button>رجوع</button></a>
                    </div>
                    </body></html>
                    """
                )

        if not msg and not attachment_ref:
            return render_template_string(
                STYLE + (settings_corner() if 'user' in session else '') + """
                <div class="container narrow-container">
                    <div class="msg">اكتب رسالتك أو ارفع صورة/فيديو أولاً</div>
                    <a href="/support"><button>رجوع</button></a>
                </div>
                </body></html>
                """
            )

        with get_db() as con:
            con.execute(
                "INSERT INTO support_messages (user_id, sender_type, message, attachment, attachment_type, is_read_admin, is_read_user) VALUES (?, 'user', ?, ?, ?, 0, 1)",
                (current_user["id"], msg, attachment_ref, attachment_type)
            )
            con.commit()

        try:
            notify_admin_support_message(current_user, msg, attachment_type)
        except Exception as notify_error:
            print("SUPPORT USER PUSH ERROR:", repr(notify_error))

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
        attachment_html = render_support_attachment((m["attachment"] if m["attachment"] else ""), (m["attachment_type"] if m["attachment_type"] else ""))
        msg_html = f'<div style="white-space:pre-wrap;word-break:break-word;">{m["message"]}</div>' if (m["message"] or "").strip() else ""
        chat_html += f"""
        <div style="display:flex;{align}margin:10px 0;">
            <div style="max-width:78%;background:{bg};color:{color};padding:12px 14px;border-radius:18px;border:1px solid rgba(96,165,250,.18);">
                <div style="font-size:12px;opacity:.85;margin-bottom:5px;">{label}</div>
                {msg_html}
                {attachment_html}
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
            <div class="section-subtitle">هنا تقدر ترسل نص، أو صورة للمشكلة، أو فيديو قصير يوضحها.</div>

            <div class="card" style="padding:14px;max-height:420px;overflow:auto;">
                {chat_html}
            </div>

            <form method="post" enctype="multipart/form-data" style="margin-top:14px;">
                <textarea name="msg" placeholder="اكتب رسالتك للدعم الفني"></textarea>
                <label>إرفاق صورة أو فيديو للمشكلة</label>
                <input type="file" name="attachment" accept="image/*,video/*">
                <div class="notice">مسموح صورة أو فيديو واحد مع الرسالة، وبحد أقصى 20MB.</div>
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
        attachment_ref = ""
        attachment_type = ""
        media_file = request.files.get("attachment")

        if media_file and media_file.filename:
            try:
                attachment_ref, attachment_type = save_support_media(media_file)
            except Exception as e:
                return render_template_string(
                    STYLE + f"""
                    <div class="container narrow-container">
                        <div class="msg">تعذر رفع الملف: {str(e)}</div>
                        <a href="/admin/support?user_id={selected_user_id}"><button>رجوع</button></a>
                    </div>
                    </body></html>
                    """
                )

        if selected_user_id and (msg or attachment_ref):
            try:
                uid = int(selected_user_id)
            except Exception:
                uid = 0

            if uid:
                with get_db() as con:
                    user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                    if user:
                        con.execute(
                            "INSERT INTO support_messages (user_id, sender_type, message, attachment, attachment_type, is_read_admin, is_read_user) VALUES (?, 'admin', ?, ?, ?, 1, 0)",
                            (uid, msg, attachment_ref, attachment_type)
                        )
                        con.commit()
                        log_admin_action("رد دعم فني", user["name"], "تم إرسال رد من الأدمن داخل الدعم الفني")
                        try:
                            notify_user_support_reply(uid, msg, attachment_type)
                        except Exception as notify_error:
                            print("SUPPORT ADMIN REPLY PUSH ERROR:", repr(notify_error))
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
                    attachment_html = render_support_attachment((m["attachment"] if m["attachment"] else ""), (m["attachment_type"] if m["attachment_type"] else ""))
                    msg_html = f'<div style="white-space:pre-wrap;word-break:break-word;">{m["message"]}</div>' if (m["message"] or "").strip() else ""
                    blocks += f"""
                    <div style="display:flex;{align}margin:10px 0;">
                        <div style="max-width:78%;background:{bg};color:{color};padding:12px 14px;border-radius:18px;border:1px solid rgba(96,165,250,.18);">
                            <div style="font-size:12px;opacity:.85;margin-bottom:5px;">{sender}</div>
                            {msg_html}
                            {attachment_html}
                            <div class="small" style="margin-top:6px;color:{small_color};">{m["created_at"]}</div>
                        </div>
                    </div>
                    """
                chat_html = blocks or '<div class="empty-state">لا توجد رسائل</div>'
                reply_form = f"""
                <form method="post" enctype="multipart/form-data" style="margin-top:14px;">
                    <input type="hidden" name="user_id" value="{uid}">
                    <textarea name="msg" placeholder="اكتب ردك هنا"></textarea>
                    <label>إرفاق صورة أو فيديو</label>
                    <input type="file" name="attachment" accept="image/*,video/*">
                    <div class="notice">مسموح صورة أو فيديو واحد مع الرد.</div>
                    <button>إرسال الرد</button>
                </form>
                """

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <a href="/admin/panel"><button class="light-btn">رجوع للوحة الأدمن</button></a>
            <h2>الدعم الفني</h2>
            <div class="section-subtitle">اختر المستخدم من القائمة ثم رد عليه بنص أو صورة أو فيديو.</div>

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
    remembered_user_id = session.get("user_id")
    clear_remember_token(remembered_user_id)
    session.clear()
    if remembered_email:
        session["last_email"] = remembered_email
    resp = redirect(url_for("home"))
    if remembered_email:
        resp.set_cookie("remember_email", remembered_email, max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
    resp.set_cookie("remember_token", "", expires=0, httponly=True, samesite="Lax", secure=APP_ENV == "production")
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

        session.clear()
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
        pending_approval_count = con.execute("SELECT COUNT(*) AS c FROM users WHERE COALESCE(is_verified,0)=0 AND COALESCE(role,'worker')='worker' AND COALESCE(is_blocked,0)=0").fetchone()["c"]

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
        is_worker_account = (u["role"] or "worker") == "worker"
        is_pending_approval = is_worker_account and int((u["is_verified"] if u["is_verified"] is not None else 0) or 0) == 0
        approval_badge = '<span class="badge" style="background:rgba(250,204,21,.20);border:1px solid rgba(250,204,21,.42);">⏳ قيد المراجعة</span>' if is_pending_approval else ''
        approval_actions = ''
        if is_pending_approval:
            approval_actions = f'<a class="link-btn" href="/admin/approve-worker/{u["id"]}">✅ قبول الحساب</a><a class="link-btn link-red" href="/admin/reject-worker/{u["id"]}">رفض الحساب</a>'
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
                {approval_badge}
            </div>
            <div class="small">الهاتف: {u["phone"] or "-"}</div>
            <div class="small">المدينة: {u["city"] or "-"}</div>
            <div class="small">التقييم: ⭐ {avg_rating} / 5 ({rating_count})</div>
            <div class="small">المشاهدات: 👁 {u["views"] or 0}</div>
            <div class="inline" style="margin-top:12px;">
                <a class="link-btn" href="/worker/{u['id']}">فتح الملف</a>
                <a class="link-btn" href="/admin/edit-user/{u['id']}">تعديل البيانات</a>
                {approval_actions}
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
                    <a href="/admin/pending-workers"><button class="light-btn">قيد المراجعة ({pending_approval_count})</button></a>
                    
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
                <div class="admin-stat"><div class="label">قيد المراجعة</div><div class="value">{pending_approval_count}</div></div>
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



@app.route("/admin/pending-workers")
def admin_pending_workers():
    if not admin_required():
        return redirect(url_for("admin_login"))

    with get_db() as con:
        pending_users = con.execute(
            """
            SELECT * FROM users
            WHERE COALESCE(is_verified,0)=0
              AND COALESCE(role,'worker')='worker'
              AND COALESCE(is_blocked,0)=0
            ORDER BY id DESC
            """
        ).fetchall()

    cards = ""
    for u in pending_users:
        profile_html = profile_thumb_html(u["profile_pic"] or "", "profile-img")
        cards += f"""
        <div class="admin-user-card">
            <div class="worker-card">
                <div>{profile_html}</div>
                <div>
                    <div class="inline" style="margin-bottom:10px;">
                        <span class="badge">⏳ قيد مراجعة الإدارة</span>
                        <span class="worker-specialty-badge">{get_specialty_icon(u['section'])} {u['section'] or '-'}</span>
                        <span class="badge">{u['governorate'] or '-'}</span>
                    </div>
                    <h3>{u['name'] or '-'}</h3>
                    <div class="small">{u['email'] or '-'}</div>
                    <div class="detail-grid" style="margin-top:12px;">
                        <div class="detail-box"><strong>الهاتف</strong>{u['phone'] or '-'}</div>
                        <div class="detail-box"><strong>المدينة</strong>{u['city'] or '-'}</div>
                        <div class="detail-box"><strong>الخبرة</strong>{u['exp'] or '-'}</div>
                        <div class="detail-box"><strong>الاختصاص</strong>{u['section'] or '-'}</div>
                    </div>
                    <div class="profile-bio-box">{u['bio'] or 'لا توجد نبذة'}</div>
                    <div class="inline" style="margin-top:12px;">
                        <a class="link-btn" href="/admin/approve-worker/{u['id']}">✅ قبول وإظهار الحساب</a>
                        <a class="link-btn link-red" href="/admin/reject-worker/{u['id']}">رفض وإخفاء الحساب</a>
                        <a class="link-btn secondary" href="/admin/edit-user/{u['id']}">تعديل البيانات</a>
                    </div>
                </div>
            </div>
        </div>
        """

    if not cards:
        cards = '<div class="empty-state">لا توجد حسابات مختصين قيد المراجعة حالياً</div>'

    return render_template_string(
        STYLE + f"""
        <div class="container">
            <div class="topbar">
                <div class="inline">
                    <a href="/admin/panel"><button class="light-btn">رجوع للوحة الأدمن</button></a>
                    <a href="/workers"><button class="light-btn">واجهة التطبيق</button></a>
                </div>
                <span class="badge">مراجعة الحسابات الجديدة</span>
            </div>
            <div class="hero-panel" style="margin-top:14px;margin-bottom:16px;">
                <h2>حسابات المختصين قيد المراجعة</h2>
                <div class="section-subtitle">أي مختص يسجل ويؤكد البريد لا يظهر للزوار إلا بعد ضغط قبول من الإدارة.</div>
            </div>
            <div class="admin-users-grid">{cards}</div>
        </div>
        </body></html>
        """
    )


@app.route("/admin/approve-worker/<int:user_id>")
def admin_approve_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    target_name = ""
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            target_name = user["name"] or ""
            con.execute(
                "UPDATE users SET is_verified=1, hidden_by_admin=0, admin_warning='' WHERE id=?",
                (user_id,)
            )
            con.commit()
    if target_name:
        log_admin_action("قبول حساب مختص", target_name, f"تم قبول الحساب وإظهاره للزوار رقم {user_id}")
        try:
            send_push_to_user(user_id, "تم قبول حسابك", "تمت موافقة الإدارة على حسابك في المسطر، وأصبح ملفك ظاهراً للزوار.", f"/worker/{user_id}")
        except Exception as notify_error:
            print("WORKER APPROVAL PUSH ERROR:", repr(notify_error))
    return redirect(url_for("admin_pending_workers"))


@app.route("/admin/reject-worker/<int:user_id>")
def admin_reject_worker(user_id):
    if not admin_required():
        return redirect(url_for("admin_login"))
    target_name = ""
    with get_db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user:
            target_name = user["name"] or ""
            con.execute(
                "UPDATE users SET is_verified=0, hidden_by_admin=1, admin_warning=? WHERE id=?",
                ("تم رفض الحساب من الإدارة. راجع الدعم الفني لتصحيح البيانات.", user_id)
            )
            con.commit()
    if target_name:
        log_admin_action("رفض حساب مختص", target_name, f"تم رفض وإخفاء الحساب رقم {user_id}")
        try:
            send_push_to_user(user_id, "تم رفض الحساب", "تم رفض حسابك من الإدارة. راجع الدعم الفني لتصحيح البيانات ثم أعد المحاولة.", "/support")
        except Exception as notify_error:
            print("WORKER REJECT PUSH ERROR:", repr(notify_error))
    return redirect(url_for("admin_pending_workers"))


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
        f'<img src="{media_url(user["profile_pic"])}" class="profile-img-large" alt="" onerror="this.outerHTML=\'<div class=&quot;profile-placeholder-large&quot;>👤</div>\'">'
        if user["profile_pic"]
        else '<div class="profile-placeholder-large">👤</div>'
    )

    imgs = [x.strip() for x in (user["work_images"] or "").split(",") if x.strip()]
    work_images_html = ""
    if imgs:
        gallery_refs = quote("||".join(imgs), safe="")
        work_images_html = '<div class="work-grid">' + "".join(
            f'<a class="work-tile" href="{url_for("view_image")}?image={quote(img, safe="")}&images={gallery_refs}&idx={idx}&back=/profile"><img src="{media_url(img)}" alt="work" class="work-thumb"></a>' for idx, img in enumerate(imgs)
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
            <a href="/favorites"><button class="light-btn">المفضلة ❤️</button></a>
            <a href="/support"><button class="light-btn">الدعم الفني</button></a>
            <a href="/workers"><button class="light-btn">تصفح الاختصاصات</button></a>
            <a href="/privacy-policy"><button class="light-btn">سياسة الخصوصية</button></a>
            <a href="/terms-of-use"><button class="light-btn">شروط الاستخدام</button></a>
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
            <a href="/privacy-policy"><button class="light-btn">سياسة الخصوصية</button></a>
            <a href="/terms-of-use"><button class="light-btn">شروط الاستخدام</button></a>
            <a href="/change-password"><button class="light-btn">تغيير كلمة المرور</button></a>
            <a href="/logout"><button>تسجيل الخروج</button></a>
        """

    notification_button = ""
    if ONESIGNAL_APP_ID:
        notification_button = '\n            <button type="button" class="light-btn" onclick="musattarEnableNotifications();return false;">🔔 تفعيل الإشعارات</button>\n            <div class="notice">اضغط مرة واحدة حتى تسمح للتطبيق بإرسال إشعارات مهمة.</div>\n        '

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + f"""
        <div class="container narrow-container">
            <h2>الإعدادات</h2>
            <div class="section-subtitle">اختر الصفحة التي تريدها.</div>

            <div class="card">
                {notification_button}
                {buttons_html}
            </div>
        </div>
        </body></html>
        """
    )


@app.route("/privacy-policy")
def privacy_policy():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + """
        <div class="container narrow-container">
            <h2>سياسة الخصوصية</h2>
            <div class="card" style="text-align:right; line-height:1.9;">
                <p>نحن في تطبيق المسطر نحترم خصوصية المستخدمين ونلتزم بحماية البيانات التي يتم إدخالها داخل التطبيق.</p>
                <p><strong>1. البيانات التي قد نجمعها:</strong><br>
                الاسم، رقم الهاتف، البريد الإلكتروني، الصور المرفوعة، الرسائل داخل التطبيق، وبيانات الملف الشخصي الخاصة بالمستخدم أو صاحب العمل.</p>
                <p><strong>2. استخدام البيانات:</strong><br>
                تُستخدم البيانات لتشغيل خدمات التطبيق، إنشاء الحسابات، عرض الملفات الشخصية والأعمال، تسهيل التواصل بين المستخدمين، وتحسين تجربة الاستخدام.</p>
                <p><strong>3. الصور والملفات:</strong><br>
                الصور التي يرفعها المستخدم أو المختص قد تُعرض داخل ملفه الشخصي أو أعماله بحسب استخدامه داخل التطبيق.</p>
                <p><strong>4. مشاركة البيانات:</strong><br>
                لا نقوم ببيع البيانات الشخصية للمستخدمين. وقد يتم استخدام خدمات خارجية تقنية فقط لتشغيل التطبيق مثل الاستضافة أو تخزين الصور أو إرسال البريد الإلكتروني عند الحاجة.</p>
                <p><strong>5. حماية البيانات:</strong><br>
                نسعى لاتخاذ إجراءات مناسبة لحماية الحسابات والبيانات من الوصول غير المصرح به، لكن لا يمكن ضمان الأمان الكامل بنسبة 100% على الإنترنت.</p>
                <p><strong>6. مسؤولية المستخدم:</strong><br>
                المستخدم مسؤول عن صحة البيانات التي يرفعها، وعن عدم رفع محتوى غير قانوني أو مسيء أو منتهك لحقوق الآخرين.</p>
                <p><strong>7. حذف البيانات:</strong><br>
                يمكن للمستخدم طلب تعديل أو حذف بياناته أو التواصل مع الدعم عند الحاجة، وفق ما يتوفر داخل التطبيق.</p>
                <p><strong>8. التحديثات:</strong><br>
                قد يتم تحديث سياسة الخصوصية مستقبلًا، واستمرار استخدام التطبيق يعني الموافقة على النسخة الأحدث منها.</p>
            </div>
            <a href="/settings"><button class="light-btn">رجوع إلى الإعدادات</button></a>
        </div>
        </body></html>
        """
    )


@app.route("/terms-of-use")
def terms_of_use():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template_string(
        STYLE + (settings_corner() if 'user' in session else '') + """
        <div class="container narrow-container">
            <h2>شروط الاستخدام</h2>
            <div class="card" style="text-align:right; line-height:1.9;">
                <p>باستخدامك تطبيق المسطر، فإنك توافق على الالتزام بالشروط التالية:</p>
                <p><strong>1. الاستخدام المسموح:</strong><br>
                يُسمح باستخدام التطبيق لغرض عرض الأعمال، إنشاء الحسابات، والتواصل بين المستخدمين ضمن الغرض المخصص للتطبيق فقط.</p>
                <p><strong>2. صحة المعلومات:</strong><br>
                المستخدم مسؤول عن صحة المعلومات التي يضيفها في حسابه، وعن تحديثها عند الحاجة.</p>
                <p><strong>3. المحتوى المرفوع:</strong><br>
                يمنع رفع أي صور أو محتوى مسيء أو مخالف للقانون أو ينتهك حقوق الملكية أو الخصوصية الخاصة بالآخرين.</p>
                <p><strong>4. الحسابات:</strong><br>
                يحق لإدارة التطبيق تقييد أو حذف أي حساب يسيء الاستخدام أو ينتحل صفة غيره أو يستخدم التطبيق بشكل ضار.</p>
                <p><strong>5. الرسائل والتواصل:</strong><br>
                التطبيق يوفّر وسيلة للتواصل بين الأطراف، لكن المستخدم يتحمل مسؤولية التعاملات والمحتوى الذي يرسله داخل الرسائل.</p>
                <p><strong>6. حدود المسؤولية:</strong><br>
                التطبيق يعمل كمنصة عرض وتواصل، ولا يتحمل مسؤولية الاتفاقات أو النتائج التي تحصل بين المستخدمين خارج حدود الخدمة التقنية نفسها.</p>
                <p><strong>7. التعديلات على الخدمة:</strong><br>
                يحق لإدارة التطبيق تعديل أو تحسين أو إيقاف بعض الميزات في أي وقت بما يخدم تطوير المنصة.</p>
                <p><strong>8. استمرار الاستخدام:</strong><br>
                استمرارك في استخدام التطبيق بعد أي تحديث على الشروط يعني موافقتك على النسخة المحدثة منها.</p>
            </div>
            <a href="/settings"><button class="light-btn">رجوع إلى الإعدادات</button></a>
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

                try:
                    saved_profile = save_uploaded_file(profile_file)
                except Exception as e:
                    return render_template_string(
                        STYLE + (settings_corner() if 'user' in session else '') + f"""
                        <div class="container">
                            <div class="msg">فشل رفع الصورة: {str(e)}</div>
                            <a href="/edit-profile"><button>رجوع</button></a>
                        </div>
                        </body></html>
                        """
                    )

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
        f'<img src="{media_url(user["profile_pic"])}" class="profile-img-large" alt="" onerror="this.outerHTML=\'<div class=&quot;profile-placeholder-large&quot;>👤</div>\'">'
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
        resp.set_cookie("remember_email", user["email"], max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
        resp.set_cookie("remember_token", store_remember_token(user["id"]), max_age=60*60*24*PERSISTENT_LOGIN_DAYS, httponly=True, samesite="Lax", secure=APP_ENV == "production")
        session.pop("passkey_auth_challenge", None)
        session.pop("passkey_auth_email", None)
        return resp
    except Exception as e:
        return jsonify({"ok": False, "error": "فشل التحقق من البصمة: " + str(e)}), 400


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

# --- compact grid sections variant ---
