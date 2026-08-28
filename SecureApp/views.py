import os
import base64

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.utils.html import escape
from django.contrib.auth.hashers import make_password, check_password
from cryptography.exceptions import InvalidTag

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

FILES_DIR = os.path.join(settings.BASE_DIR, "SecureApp", "static", "files")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _current_user(request):
    """Return the logged-in username from the session, or None."""
    return request.session.get("username")


def _storage_path(owner, filename):
    """Per-owner on-disk location for a stored (encrypted) file."""
    safe_owner = os.path.basename(owner)
    safe_name = os.path.basename(filename)
    owner_dir = os.path.join(FILES_DIR, safe_owner)
    os.makedirs(owner_dir, exist_ok=True)
    return os.path.join(owner_dir, safe_name)


def _strip_zero_width(text):
    """Remove the zero-width steganography characters, leaving clean base64."""
    return "".join(ch for ch in text if ch not in (SPACE0, SPACE1))


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
    request.session.flush()
    return render(request, "index.html", {"data": "You have been logged out."})


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

    username = request.POST.get("t1", "").strip()
    password = request.POST.get("t2", "")

    account = Account.objects.filter(username=username).first()
    if account and check_password(password, account.password):
        request.session["username"] = account.username
        return render(request, "UserScreen.html", {"data": "welcome " + account.username})

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

    upload = request.FILES["t1"]
    file_name = os.path.basename(upload.name)
    file_data = upload.read()  # raw bytes -> binary-safe

    if SecureFile.objects.filter(owner=uname, filename=file_name).exists():
        return render(request, "UploadFile.html",
                      {"data": "A file named " + escape(file_name) + " already exists for your account."})

    # Encrypt: ephemeral-static X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM.
    result = encrypt_file(file_data)
    encoded_ct = base64.b64encode(result["ciphertext"]).decode()

    # Demonstration of steganography: hide the (public) ephemeral key in the file.
    stored_text = hide(encoded_ct, result["ephemeral_pub"])
    stored_bytes = stored_text.encode("utf-8")

    with open(_storage_path(uname, file_name), "wb") as fh:
        fh.write(stored_bytes)

    hashcode = sha256_hex(stored_bytes)

    SecureFile.objects.create(
        owner=uname,
        filename=file_name,
        ephemeral_pub=result["ephemeral_pub"],
        salt=result["salt"],
        nonce=result["nonce"],
        hashcode=hashcode,
    )

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
    output = '<table border=1 align=center width=100%>'
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

    file_id = request.GET.get("t1")
    row = SecureFile.objects.filter(pk=file_id, owner=uname).first()
    if not row:  # ownership enforced: cannot download another user's file
        return render(request, "UserScreen.html", {"data": "File not found or access denied."})

    with open(_storage_path(uname, row.filename), "r", encoding="utf-8") as fh:
        stored_text = fh.read()
    ciphertext = base64.b64decode(_strip_zero_width(stored_text))

    try:
        plaintext = decrypt_file(ciphertext, row.ephemeral_pub, row.salt, row.nonce)
    except InvalidTag:
        return render(request, "UserScreen.html",
                      {"data": "Decryption failed: the file failed AES-GCM authentication (tampered or corrupted)."})

    response = HttpResponse(plaintext, content_type="application/octet-stream")
    response["Content-Disposition"] = "attachment; filename=%s" % row.filename
    return response


def FileIntegrity(request):
    uname = _current_user(request)
    if not uname:
        return render(request, "UserLogin.html", {"data": "Please login first"})

    rows = SecureFile.objects.filter(owner=uname).order_by("-upload_date")
    output = '<table border=1 align=center width=100%>'
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

    file_id = request.GET.get("t1")
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
