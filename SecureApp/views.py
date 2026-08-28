import os
import re
import base64

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.utils.html import escape
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import validate_password
from django.db import IntegrityError
from cryptography.exceptions import InvalidTag

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,50}$")

# Login throttling (per client IP): N failures within the window -> temporary block.
LOGIN_MAX_FAILURES = 5
LOGIN_BLOCK_SECONDS = 300
# A fixed dummy hash so login timing does not reveal whether a username exists.
_DUMMY_PASSWORD_HASH = make_password("timing-equalizer-not-a-real-password")

# Per-user limits.
MAX_FILES_PER_USER = 50
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

from .models import Account, SecureFile
from .crypto_utils import (
    encrypt_file,
    decrypt_file,
    sha256_hex,
    hide,
    show,
    SPACE0,
    SPACE1,
)

# Encrypted files live in a private directory OUTSIDE the web-served static
# tree; they are only returned through the authenticated download view.
FILES_DIR = getattr(settings, "SECURE_FILE_STORE",
                    os.path.join(settings.BASE_DIR, "secure_store"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _current_user(request):
    """Return the logged-in username from the session, or None."""
    return request.session.get("username")


def _safe_component(name):
    """Reduce a value to a single, safe path component (defeats ../ traversal
    on any OS by stripping every separator and rejecting . / ..)."""
    name = str(name).replace("\\", "/").split("/")[-1]
    if name in ("", ".", ".."):
        raise SuspiciousOperation("Invalid path component")
    return name


def _sanitize_filename(name):
    """Reduce an uploaded filename to a single, filesystem-safe component:
    strip path separators, then keep only [A-Za-z0-9._ -]. Prevents OS-invalid
    names, path traversal, and stray markup in stored/displayed filenames."""
    name = str(name).replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip()
    name = name.strip(". ")[:100].strip()
    return name or "file"


def _storage_path(owner, filename):
    """Per-owner on-disk location for a stored (encrypted) file, confined to
    FILES_DIR."""
    safe_owner = _safe_component(owner)
    safe_name = _safe_component(filename)
    owner_dir = os.path.join(FILES_DIR, safe_owner)
    os.makedirs(owner_dir, exist_ok=True)
    final = os.path.join(owner_dir, safe_name)
    # Defence in depth: the resolved path must stay inside FILES_DIR.
    root = os.path.realpath(FILES_DIR)
    if os.path.commonpath([root, os.path.realpath(final)]) != root:
        raise SuspiciousOperation("Path traversal detected")
    return final


def _strip_zero_width(text):
    """Remove the zero-width steganography characters, leaving clean base64."""
    return "".join(ch for ch in text if ch not in (SPACE0, SPACE1))


def _aad(owner, filename):
    """Per-file authenticated context binding a ciphertext to its owner+name."""
    return (str(owner) + "|" + str(filename)).encode("utf-8")


def _client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _login_failures(ip):
    return cache.get("login_fail:" + ip, 0)


def _record_login_failure(ip):
    cache.set("login_fail:" + ip, _login_failures(ip) + 1, LOGIN_BLOCK_SECONDS)


def _reset_login_failures(ip):
    cache.delete("login_fail:" + ip)


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
def index(request):
    return render(request, "index.html", {})


def UserLogin(request):
    return render(request, "UserLogin.html", {})


def Signup(request):
    return render(request, "Signup.html", {})


def Logout(request):
    # State-changing: only act on POST (CSRF-protected form). A GET just returns
    # to the landing page without touching the session.
    if request.method == "POST":
        request.session.flush()
        return render(request, "index.html", {"data": "You have been logged out."})
    return redirect("index")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def SignupAction(request):
    if request.method != "POST":
        return redirect("Signup")

    username = request.POST.get("t1", "").strip()
    password = request.POST.get("t2", "")
    contact = request.POST.get("t3", "").strip()
    gender = request.POST.get("t4", "").strip()
    email = request.POST.get("t5", "").strip()
    address = request.POST.get("t6", "").strip()

    if not username or not password:
        return render(request, "Signup.html", {"data": "Username and password are required"})

    if not USERNAME_RE.match(username):
        return render(request, "Signup.html",
                      {"data": "Username may contain only letters, digits and _ . @ - (max 50 chars)"})

    # Enforce the configured AUTH_PASSWORD_VALIDATORS (length, common, numeric, similarity).
    try:
        validate_password(password)
    except ValidationError as exc:
        return render(request, "Signup.html", {"data": escape(" ".join(exc.messages))})

    if Account.objects.filter(username=username).exists():
        return render(request, "Signup.html", {"data": username + " Username already exists"})

    # Password is stored as a one-way hash (Argon2, per settings.PASSWORD_HASHERS).
    Account.objects.create(
        username=username,
        password=make_password(password),
        contact_no=contact,
        gender=gender,
        email=email,
        address=address,
    )
    return render(request, "Signup.html", {"data": "Signup Process Completed"})


def UserLoginAction(request):
    if request.method != "POST":
        return redirect("UserLogin")

    ip = _client_ip(request)
    if _login_failures(ip) >= LOGIN_MAX_FAILURES:
        return render(request, "UserLogin.html",
                      {"data": "Too many failed attempts. Please try again in a few minutes."})

    username = request.POST.get("t1", "").strip()
    password = request.POST.get("t2", "")

    account = Account.objects.filter(username=username).first()
    # Always run a hash verification (dummy hash when the user is unknown) so the
    # response time does not reveal whether the username exists.
    stored_hash = account.password if account else _DUMMY_PASSWORD_HASH
    password_ok = check_password(password, stored_hash)

    if account and password_ok:
        _reset_login_failures(ip)
        request.session.cycle_key()  # rotate session id -> defeats session fixation
        request.session["username"] = account.username
        return render(request, "UserScreen.html", {"data": "welcome " + account.username})

    _record_login_failure(ip)
    return render(request, "UserLogin.html", {"data": "login failed"})


# ---------------------------------------------------------------------------
# File upload / download / integrity
# ---------------------------------------------------------------------------
def UploadFile(request):
    if not _current_user(request):
        return render(request, "UserLogin.html", {"data": "Please login first"})
    return render(request, "UploadFile.html", {})


def UploadAction(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})
    if request.method != "POST":
        return redirect("UploadFile")

    upload = request.FILES.get("t1")
    if upload is None:
        return render(request, "UploadFile.html", {"data": "Please choose a file to upload."})

    # Cap upload size (streamed file uploads are not bounded by the memory limits).
    if upload.size and upload.size > MAX_UPLOAD_BYTES:
        return render(request, "UploadFile.html", {"data": "File too large (maximum 10 MB)."})

    # Per-user file-count quota (bounds disk usage).
    if SecureFile.objects.filter(owner=uname).count() >= MAX_FILES_PER_USER:
        return render(request, "UploadFile.html",
                      {"data": "Storage quota reached (maximum %d files)." % MAX_FILES_PER_USER})

    file_name = _sanitize_filename(upload.name)
    file_data = upload.read()  # raw bytes -> binary-safe

    # Encrypt: ephemeral-static X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM, with
    # the ciphertext bound to owner|filename via HKDF info + AES-GCM AAD.
    result = encrypt_file(file_data, aad=_aad(uname, file_name))
    encoded_ct = base64.b64encode(result["ciphertext"]).decode()
    # Demonstration of steganography: hide the (public) ephemeral key in the file.
    stored_text = hide(encoded_ct, result["ephemeral_pub"])
    stored_bytes = stored_text.encode("utf-8")
    hashcode = sha256_hex(stored_bytes)

    # Insert metadata first; unique_together(owner, filename) atomically rejects
    # duplicates, eliminating the check-then-write race.
    try:
        SecureFile.objects.create(
            owner=uname,
            filename=file_name,
            ephemeral_pub=result["ephemeral_pub"],
            salt=result["salt"],
            nonce=result["nonce"],
            hashcode=hashcode,
        )
    except IntegrityError:
        return render(request, "UploadFile.html",
                      {"data": "A file named " + escape(file_name) + " already exists for your account."})

    # Write ciphertext atomically (temp -> rename) only after the row commits.
    final = _storage_path(uname, file_name)
    tmp = final + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(stored_bytes)
        os.replace(tmp, final)
    except OSError:
        SecureFile.objects.filter(owner=uname, filename=file_name).delete()
        return render(request, "UploadFile.html", {"data": "Could not store the encrypted file."})

    output = (
        escape(file_name) + " encrypted with X25519 ECDH + AES-256-GCM."
        + "<br/>Ephemeral public key steganographically hidden inside the file."
        + "<br/>SHA-256 integrity hashcode = " + hashcode
    )
    return render(request, "UploadFile.html", {"data": output})


def DownloadFile(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})

    rows = SecureFile.objects.filter(owner=uname).order_by("-upload_date")
    output = '<table class="data-table">'
    headers = ["Filename", "Extracted Hidden Ephemeral Public Key", "SHA-256 Hashcode", "Download"]
    output += "<tr>" + "".join("<th>" + h + "</th>" for h in headers) + "</tr>"

    for row in rows:
        try:
            with open(_storage_path(uname, row.filename), "r", encoding="utf-8") as fh:
                stored_text = fh.read()
            extracted = show(stored_text) or "(none)"
        except OSError:
            extracted = "(file missing)"
        output += "<tr>"
        output += "<td>" + escape(row.filename) + "</td>"
        output += "<td style='word-break:break-all'>" + escape(str(extracted)) + "</td>"
        output += "<td style='word-break:break-all'>" + escape(row.hashcode) + "</td>"
        output += '<td><a href="DownloadFileAction?t1=' + str(row.pk) + '">Click Here</a></td>'
        output += "</tr>"
    output += "</table>"
    return render(request, "UserScreen.html", {"data": output})


def DownloadFileAction(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})

    try:
        file_id = int(request.GET.get("t1", ""))
    except (TypeError, ValueError):
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})

    row = SecureFile.objects.filter(pk=file_id, owner=uname).first()
    if not row:  # ownership enforced: cannot download another user's file
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})

    try:
        with open(_storage_path(uname, row.filename), "r", encoding="utf-8") as fh:
            stored_text = fh.read()
        ciphertext = base64.b64decode(_strip_zero_width(stored_text))
        plaintext = decrypt_file(ciphertext, row.ephemeral_pub, row.salt, row.nonce,
                                 aad=_aad(uname, row.filename))
    except OSError:
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})
    except (InvalidTag, ValueError):  # ValueError covers malformed base64/hex params
        return render(request, "UserScreen.html",
                      {"data": "Decryption failed: the file failed AES-GCM authentication (tampered or corrupted)."})

    response = HttpResponse(plaintext, content_type="application/octet-stream")
    # row.filename is already sanitized to a safe charset (no quotes/CR/LF).
    response["Content-Disposition"] = 'attachment; filename="%s"' % row.filename
    return response


def FileIntegrity(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})

    rows = SecureFile.objects.filter(owner=uname).order_by("-upload_date")
    output = '<table class="data-table">'
    headers = ["Filename", "Stored SHA-256 Hashcode", "Check File Integrity"]
    output += "<tr>" + "".join("<th>" + h + "</th>" for h in headers) + "</tr>"
    for row in rows:
        output += "<tr>"
        output += "<td>" + escape(row.filename) + "</td>"
        output += "<td style='word-break:break-all'>" + escape(row.hashcode) + "</td>"
        output += '<td><a href="FileIntegrityAction?t1=' + str(row.pk) + '">Click Here</a></td>'
        output += "</tr>"
    output += "</table>"
    return render(request, "UserScreen.html", {"data": output})


def FileIntegrityAction(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})

    try:
        file_id = int(request.GET.get("t1", ""))
    except (TypeError, ValueError):
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})

    row = SecureFile.objects.filter(pk=file_id, owner=uname).first()
    if not row:
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})

    try:
        with open(_storage_path(uname, row.filename), "rb") as fh:
            stored_bytes = fh.read()
    except OSError:
        return render(request, "UserScreen.html", {"data": "File Integrity Failed. Stored file is missing."})

    generated = sha256_hex(stored_bytes)
    if generated == row.hashcode:
        output = "File Integrity Successful. No Data Changed (SHA-256 match)."
    else:
        output = "File Integrity Failed. Data Changed (SHA-256 mismatch)."
    return render(request, "UserScreen.html", {"data": output})
