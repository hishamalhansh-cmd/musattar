from pathlib import Path


APP_PATH = Path("app.py")

if not APP_PATH.exists():
    raise SystemExit("app.py غير موجود. نزّل ملف app.py من GitHub بنفس هذا المجلد ثم شغّل السكربت.")

text = APP_PATH.read_text(encoding="utf-8")

PRO_THEME = r"""

/* === PROFESSIONAL MUSATTAR FINAL THEME === */
:root{
    --primary:#1d4ed8 !important;
    --primary-2:#3b82f6 !important;
    --primary-soft:#eaf4ff !important;
    --accent:#fbbf24 !important;
    --accent-soft:#fef3c7 !important;
    --surface:#ffffff !important;
    --surface-soft:#f8fbff !important;
    --text:#102a56 !important;
    --muted:#607899 !important;
    --border:rgba(29,78,216,.16) !important;
    --shadow:0 16px 38px rgba(29,78,216,.10) !important;
    --soft-shadow:0 8px 22px rgba(29,78,216,.08) !important;
}
html,body{
    background:
        radial-gradient(circle at top right, rgba(96,165,250,.22), transparent 32%),
        radial-gradient(circle at bottom left, rgba(251,191,36,.18), transparent 34%),
        linear-gradient(180deg,#ffffff 0%,#f6f9ff 55%,#edf5ff 100%) !important;
    color:var(--text) !important;
}
.container,.card,.hero-panel,.search-panel,.settings-group,.settings-profile-wrap,.worker-hero,.comment-card,
.admin-stat,.admin-search-box,.admin-user-card,.admin-log-card,.home-feature-card,.home-stat,.home-cta-box,
.specialty-group-card,.chat-screen,.chat-list-shell,.review-card-pro,.stat-mini-card,.profile-bio-box,.empty-state,.msg,.notice-box{
    background:rgba(255,255,255,.96) !important;
    color:var(--text) !important;
    border:1px solid var(--border) !important;
    box-shadow:var(--soft-shadow) !important;
}
.container{border-radius:26px !important;}
h1,h2,h3,h4,label,.specialty-name,.review-name,.worker-card-title,.category-title,a h3{color:var(--text) !important;}
.small,.section-subtitle,.notice,.footer-note,.rating-text,.chat-time,.chat-user-sub,.stat-mini-label{color:var(--muted) !important;}
input,select,textarea{
    background:#fff !important;
    color:var(--text) !important;
    border:1px solid rgba(29,78,216,.22) !important;
    box-shadow:none !important;
}
input:focus,select:focus,textarea:focus{border-color:var(--primary) !important;box-shadow:0 0 0 4px rgba(29,78,216,.12) !important;}
button,.link-btn,.global-back-btn,.bottom-corner-link,.action-pill,.chat-send-btn{
    background:linear-gradient(180deg,var(--primary-2) 0%,var(--primary) 100%) !important;
    color:#fff !important;
    border:1px solid rgba(29,78,216,.26) !important;
    box-shadow:0 10px 20px rgba(29,78,216,.18) !important;
}
button.light-btn,.link-btn.secondary,.action-pill.secondary,.settings-btn,.message-floating-btn{
    background:#fff !important;
    color:var(--primary) !important;
    border:1px solid rgba(29,78,216,.22) !important;
}
.visitor-big-entry,.badge,.hero-badge,.rating-pill,.chat-status-chip,.chat-list-chip,.worker-specialty-badge,.pinned-badge{
    background:linear-gradient(180deg,#fde68a 0%,var(--accent) 100%) !important;
    color:var(--text) !important;
    border:1px solid rgba(251,191,36,.55) !important;
}
.verified-badge{background:var(--primary-soft) !important;color:var(--primary) !important;border:1px solid rgba(29,78,216,.24) !important;}
.info-chip,.detail-box,.mini-stat{background:var(--surface-soft) !important;color:var(--text) !important;border:1px solid rgba(29,78,216,.12) !important;}
.specialty-group-card::before,.card::before,.worker-hero::before,.settings-group::before,.settings-profile-wrap::before,.hero-panel::before,.search-panel::before{background:linear-gradient(90deg,var(--primary),var(--accent)) !important;}
.specialty-group-card{transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease !important;}
.specialty-group-card:hover,.card:hover{transform:translateY(-2px);box-shadow:var(--shadow) !important;border-color:rgba(29,78,216,.26) !important;}
.specialty-group-card h3{font-size:26px !important;font-weight:900 !important;color:var(--text) !important;}
.specialty-group-card .section-subtitle{font-size:14px !important;color:var(--muted) !important;}
.whatsapp-pill{background:linear-gradient(180deg,#22c55e 0%,#16a34a 100%) !important;color:#fff !important;border-color:rgba(22,163,74,.35) !important;}
.link-red{background:linear-gradient(180deg,#ef4444 0%,#dc2626 100%) !important;color:#fff !important;}
.work-thumb,.work-grid img{box-shadow:0 10px 20px rgba(29,78,216,.10) !important;}
.filter-pro-panel{margin:14px 0;padding:14px;border-radius:18px;background:var(--surface-soft);border:1px solid rgba(29,78,216,.12)}
.filter-pro-panel form{display:grid;grid-template-columns:1.4fr 1fr 1fr auto;gap:10px;align-items:end;margin:0}
.filter-pro-panel button{min-width:92px}
@media(max-width:760px){.filter-pro-panel form{grid-template-columns:1fr}.specialty-group-card h3{font-size:21px !important}}
"""

if "PROFESSIONAL MUSATTAR FINAL THEME" not in text:
    text = text.replace("</style>", PRO_THEME + "\n</style>", 1)

replacements = {
    '''def allowed_file(filename):
    return True
''': '''def allowed_file(filename):
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS
''',
    '''def build_whatsapp_link(phone):
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if digits.startswith("0"):
        digits = "964" + digits[1:]
    return f"https://api.whatsapp.com/send?phone={digits}"
    if digits.startswith("00"):
        digits = digits[2:]
    return f"https://api.whatsapp.com/send?phone={digits}"
''': '''def build_whatsapp_link(phone):
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0"):
        digits = "964" + digits[1:]
    if digits and not digits.startswith("964"):
        digits = "964" + digits
    return f"https://api.whatsapp.com/send?phone={digits}"
''',
}

for old, new in replacements.items():
    text = text.replace(old, new)

old_block = '''def file_size_ok(file_obj):
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
'''

new_block = '''def file_size_ok(file_obj, max_size=MAX_SINGLE_FILE_SIZE):
    try:
        current_pos = file_obj.stream.tell()
        file_obj.stream.seek(0, os.SEEK_END)
        size = file_obj.stream.tell()
        file_obj.stream.seek(current_pos)
        return size <= max_size
    except Exception:
        return True


def detect_real_image_type(file_obj):
    if not PIL_AVAILABLE:
        return "unknown"
    try:
        current_pos = file_obj.stream.tell()
        file_obj.stream.seek(0)
        with Image.open(file_obj.stream) as img:
            fmt = (img.format or "").lower()
            img.verify()
        file_obj.stream.seek(current_pos)
        if fmt == "jpeg":
            fmt = "jpg"
        return fmt if fmt in ALLOWED_EXTENSIONS else None
    except Exception:
        try:
            file_obj.stream.seek(0)
        except Exception:
            pass
        return None


def validate_uploaded_image(file_obj):
    if not file_obj or file_obj.filename == "":
        return False, "لا يوجد ملف"
    if not allowed_file(file_obj.filename):
        return False, "نوع الصورة غير مسموح. استخدم JPG أو PNG أو WEBP"
    if not file_size_ok(file_obj, MAX_SINGLE_FILE_SIZE):
        return False, "حجم الصورة أكبر من المسموح"
    real_type = detect_real_image_type(file_obj)
    if real_type is None:
        return False, "الملف المرفوع ليس صورة صحيحة"
    try:
        file_obj.stream.seek(0)
    except Exception:
        pass
    return True, ""
'''
text = text.replace(old_block, new_block)

text = text.replace(
    'if not file_size_ok(file_obj):\n        return False, "حجم الملف أكبر من المسموح"',
    'if not file_size_ok(file_obj, MAX_SUPPORT_MEDIA_SIZE):\n        return False, "حجم الملف أكبر من المسموح"',
)

text = text.replace(
    '        message_button = ""\n\n        favorite_button = ""',
    '''        message_button = ""
        if not is_self_worker_profile:
            if "user" not in session:
                message_button = '<a class="action-pill secondary" href="/visitor/login">💬 سجّل كزائر للمراسلة</a>'
            elif session.get("role") == "visitor" and int((worker["allow_messages"] if worker["allow_messages"] is not None else 0) or 0):
                message_button = f'<a class="action-pill" href="/message/{worker["id"]}">💬 رسالة</a>'
            elif session.get("role") == "visitor":
                message_button = '<span class="badge">الرسائل معطلة لهذا المختص</span>'

        favorite_button = ""''',
    1,
)

text = text.replace(
    '''            <a href="/change-password"><button class="light-btn">تغيير كلمة المرور</button></a>
            <a href="/logout"><button>تسجيل الخروج</button></a>
        ''',
    '''            <a href="/change-password"><button class="light-btn">تغيير كلمة المرور</button></a>
            <a href="/passkey/setup"><button class="light-btn">تفعيل الدخول بالبصمة</button></a>
            <a href="/logout"><button>تسجيل الخروج</button></a>
        ''',
    1,
)

APP_PATH.write_text(text, encoding="utf-8")
print("تم تطبيق التحديث الاحترافي على app.py بنجاح.")
