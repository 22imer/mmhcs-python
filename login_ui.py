"""
login_ui.py — Luxury Login Interface wired to passkey backend.
Supports registration, authentication, forced TOTP setup on first login,
and launches Chatify in the browser on success.

Uses the Chatify backend REST API for user signup/login.
"""

import sys
import io
import json
import os
import webbrowser
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import qrcode
import requests
from dotenv import load_dotenv

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QPixmap, QImage
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QStackedWidget,
    QMessageBox,
)

from passkey_server import PasskeyServer
from passkey_client import get_client, is_windows_client_available
import credential_store

# ═══════════════════════════════════════════════════════════════════════
# Load Chatify env
# ═══════════════════════════════════════════════════════════════════════

load_dotenv(Path(__file__).parent / ".env")

_CHATIFY_BACKEND_URL = os.getenv("CHATIFY_BACKEND_URL", "http://localhost:3000")
_CHATIFY_CLIENT_URL = os.getenv("CHATIFY_CLIENT_URL", "http://localhost:5173")

# Hardcoded password — auth is handled by FIDO2 passkey, not password
_HARDCODED_PASSWORD = "xK9#mQ2$vL7@nR4!pW6&jT8*"


# ═══════════════════════════════════════════════════════════════════════
# Chatify Backend API helpers
# ═══════════════════════════════════════════════════════════════════════


def _api_login(email: str, password: str) -> dict:
    """
    Login via POST /api/auth/login.
    Returns {"user": {...}, "token": "..."} on success.
    Raises ValueError on failure.
    """
    resp = requests.post(
        f"{_CHATIFY_BACKEND_URL}/api/auth/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    body = resp.json()

    if resp.status_code != 200:
        raise ValueError(body.get("error", "Login failed"))

    # Extract JWT from the Set-Cookie header
    token = resp.cookies.get("jwt", "")
    return {"user": body, "token": token}


def _api_signup(email: str, fullName: str, password: str) -> dict:
    """
    Signup via POST /api/auth/signup.
    Returns {"user": {...}, "token": "..."} on success.
    Raises ValueError on failure.
    """
    resp = requests.post(
        f"{_CHATIFY_BACKEND_URL}/api/auth/signup",
        json={"email": email, "fullName": fullName, "password": password},
        timeout=10,
    )
    body = resp.json()

    if resp.status_code not in (200, 201):
        raise ValueError(body.get("error", "Signup failed"))

    token = resp.cookies.get("jwt", "")
    return {"user": body, "token": token}


# ═══════════════════════════════════════════════════════════════════════
# Worker Threads
# ═══════════════════════════════════════════════════════════════════════


class RegisterWorker(QThread):
    """Performs the full registration ceremony in a background thread."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, server: PasskeyServer, username: str):
        super().__init__()
        self.server = server
        self.username = username

    def run(self):
        try:
            options, state = self.server.begin_registration(self.username)
            client, info = get_client()
            result = client.make_credential(options["publicKey"])
            summary = self.server.complete_registration(state, result)
            self.finished.emit(summary)
        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")


class AuthenticateWorker(QThread):
    """Performs the full authentication ceremony in a background thread."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, server: PasskeyServer, username: str):
        super().__init__()
        self.server = server
        self.username = username

    def run(self):
        try:
            options, state = self.server.begin_authentication(self.username)
            client, info = get_client()
            response = client.get_assertion(options["publicKey"])
            cred_bytes = credential_store.get_credentials(self.username)
            assertion = response.get_response(0)
            summary = self.server.complete_authentication(
                state, cred_bytes, assertion
            )
            self.finished.emit(summary)
        except Exception as exc:
            self.error.emit(f"{type(exc).__name__}: {exc}")


# ═══════════════════════════════════════════════════════════════════════
# Stylesheet — Pure Black with White Borders
# ═══════════════════════════════════════════════════════════════════════

LOGIN_STYLESHEET = """
QWidget#loginBackground {
    background-color: #000000;
}

QFrame#cardFrame {
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 16px;
}

QLabel#titleLabel {
    color: #ffffff;
    font-size: 28px;
    font-weight: 700;
    letter-spacing: 1px;
}

QLabel#subtitleLabel {
    color: #888888;
    font-size: 12px;
    font-weight: 400;
    letter-spacing: 0.5px;
}

QLabel#fieldLabel {
    color: #aaaaaa;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.5px;
}

QLabel#accentLine {
    background-color: #ffffff;
    max-height: 1px;
    min-height: 1px;
}

QLineEdit#usernameInput, QLineEdit#emailInput, QLineEdit#passwordInput, QLineEdit#totpInput {
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 10px;
    padding: 14px 18px;
    color: #ffffff;
    font-size: 14px;
    font-weight: 400;
    selection-background-color: #333333;
}
QLineEdit#usernameInput:focus, QLineEdit#emailInput:focus, QLineEdit#passwordInput:focus, QLineEdit#totpInput:focus {
    border: 1px solid #ffffff;
    background-color: #0a0a0a;
}

QPushButton#loginBtn, QPushButton#confirmBtn {
    background-color: #ffffff;
    border: none;
    border-radius: 10px;
    padding: 14px 32px;
    color: #000000;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 2px;
}
QPushButton#loginBtn:hover, QPushButton#confirmBtn:hover {
    background-color: #dddddd;
}
QPushButton#loginBtn:pressed, QPushButton#confirmBtn:pressed {
    background-color: #bbbbbb;
}
QPushButton#loginBtn:disabled, QPushButton#confirmBtn:disabled {
    background-color: #333333;
    color: #666666;
}

QPushButton#registerBtn {
    background-color: transparent;
    border: 1px solid #ffffff;
    border-radius: 10px;
    padding: 14px 32px;
    color: #ffffff;
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 2px;
}
QPushButton#registerBtn:hover {
    background-color: #111111;
}
QPushButton#registerBtn:pressed {
    background-color: #1a1a1a;
}
QPushButton#registerBtn:disabled {
    border: 1px solid #333333;
    color: #333333;
}

QLabel#statusLabel {
    color: #888888;
    font-size: 11px;
    letter-spacing: 0.3px;
}

QLabel#footerLabel {
    color: #444444;
    font-size: 10px;
    letter-spacing: 1px;
}

/* ── TOTP Setup Page ──────────────────────── */

QLabel#totpTitle {
    color: #ffffff;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

QLabel#totpSubtitle {
    color: #888888;
    font-size: 11px;
    letter-spacing: 0.3px;
}

QLabel#qrContainer {
    background-color: #ffffff;
    border-radius: 8px;
    padding: 8px;
}

QLabel#secretLabel {
    color: #888888;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    letter-spacing: 1px;
}

/* ── Welcome Page ─────────────────────────── */

QLabel#welcomeIcon {
    color: #ffffff;
    font-size: 48px;
}

QLabel#welcomeTitle {
    color: #ffffff;
    font-size: 26px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

QLabel#welcomeUser {
    color: #cccccc;
    font-size: 18px;
    font-weight: 600;
    letter-spacing: 0.5px;
}

QLabel#welcomeDetail {
    color: #666666;
    font-size: 11px;
    letter-spacing: 0.3px;
}

QLabel#welcomeAccent {
    background-color: #ffffff;
    max-height: 1px;
    min-height: 1px;
}

QPushButton#logoutBtn {
    background-color: transparent;
    border: 1px solid #ffffff;
    border-radius: 10px;
    padding: 12px 32px;
    color: #ffffff;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 2px;
}
QPushButton#logoutBtn:hover {
    background-color: #111111;
}
"""


# ═══════════════════════════════════════════════════════════════════════
# Login Page Widget
# ═══════════════════════════════════════════════════════════════════════


class LoginPage(QWidget):
    """The login/register form card."""

    login_success = pyqtSignal(str, dict)  # username, summary

    def __init__(self):
        super().__init__()
        self.server = PasskeyServer()
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # ── Card ────────────────────────────────────────────────────
        card = QFrame()
        card.setObjectName("cardFrame")
        card.setFixedSize(400, 640)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 36, 40, 30)
        lay.setSpacing(0)

        # Diamond icon
        icon_label = QLabel("◆")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("color: #ffffff; font-size: 20px;")
        lay.addWidget(icon_label)
        lay.addSpacing(10)

        # Title
        title = QLabel("Welcome")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)
        lay.addSpacing(4)

        subtitle = QLabel("Sign in with your Chatify account")
        subtitle.setObjectName("subtitleLabel")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(subtitle)
        lay.addSpacing(10)

        # Accent line
        accent = QLabel()
        accent.setObjectName("accentLine")
        accent.setFixedWidth(200)
        accent_container = QHBoxLayout()
        accent_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        accent_container.addWidget(accent)
        lay.addLayout(accent_container)
        lay.addSpacing(20)

        # Email field
        email_label = QLabel("EMAIL")
        email_label.setObjectName("fieldLabel")
        lay.addWidget(email_label)
        lay.addSpacing(6)

        self.email_input = QLineEdit()
        self.email_input.setObjectName("emailInput")
        self.email_input.setPlaceholderText("you@example.com")
        self.email_input.setMinimumHeight(44)
        lay.addWidget(self.email_input)
        lay.addSpacing(14)

        # Password field (hidden — auth is via FIDO2 passkey)
        self.password_input = QLineEdit()
        self.password_input.setObjectName("passwordInput")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setVisible(False)

        # Full Name field (only used for registration)
        fullname_label = QLabel("FULL NAME  (for signup only)")
        fullname_label.setObjectName("fieldLabel")
        lay.addWidget(fullname_label)
        lay.addSpacing(6)

        self.username_input = QLineEdit()
        self.username_input.setObjectName("usernameInput")
        self.username_input.setPlaceholderText("Enter your full name")
        self.username_input.setMinimumHeight(44)
        lay.addWidget(self.username_input)
        lay.addSpacing(18)

        # Login button
        self.login_btn = QPushButton("LOGIN")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.setMinimumHeight(50)
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._on_login)
        lay.addWidget(self.login_btn)
        lay.addSpacing(10)

        # Register button
        self.register_btn = QPushButton("REGISTER")
        self.register_btn.setObjectName("registerBtn")
        self.register_btn.setMinimumHeight(50)
        self.register_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.register_btn.clicked.connect(self._on_register)
        lay.addWidget(self.register_btn)
        lay.addSpacing(12)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)

        lay.addStretch()

        root.addWidget(card)

    # ── Helpers ────────────────────────────────────────────────────

    def _get_email_password(self) -> tuple[str, str] | None:
        email = self.email_input.text().strip()
        if not email:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("Please enter your email")
            self.email_input.setFocus()
            return None
        return email, _HARDCODED_PASSWORD

    def _get_username(self) -> str | None:
        username = self.username_input.text().strip()
        if not username:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("Please enter your full name")
            self.username_input.setFocus()
            return None
        return username

    def _set_busy(self, busy: bool, message: str = ""):
        self.login_btn.setEnabled(not busy)
        self.register_btn.setEnabled(not busy)
        self.email_input.setEnabled(not busy)
        self.username_input.setEnabled(not busy)
        if message:
            self.status_label.setStyleSheet("color: #ffffff; font-size: 11px;")
            self.status_label.setText(message)

    # ── Login Flow ────────────────────────────────────────────────

    def _on_login(self):
        creds = self._get_email_password()
        if not creds:
            return
        email, password = creds

        self._set_busy(True, "⏳  Logging in via Chatify API…")

        try:
            result = _api_login(email, password)
        except ValueError as e:
            self._set_busy(False)
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"❌  {e}")
            return
        except Exception as e:
            self._set_busy(False)
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"❌  Cannot reach the server: {e}")
            return

        # Store API response for later use
        user = result["user"]
        username = user.get("fullName", email.split("@")[0])
        self._api_token = result["token"]
        self._api_user = user

        # Check if user has passkey credentials registered
        creds_list = credential_store.get_credentials(username)
        if not creds_list:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"No passkey registered for '{username}'. Click REGISTER first.")
            self._set_busy(False)
            return

        self.status_label.setStyleSheet("color: #ffffff; font-size: 11px;")
        self.status_label.setText("⏳  Waiting for authenticator…")
        self._worker = AuthenticateWorker(self.server, username)
        self._worker.finished.connect(self._on_login_done)
        self._worker.error.connect(self._on_login_error)
        self._worker.start()

    def _on_login_done(self, summary: dict):
        self._set_busy(False)
        username = summary.get("username", "")
        # Attach the API token + user to the summary
        summary["_api_token"] = getattr(self, "_api_token", "")
        summary["_api_user"] = getattr(self, "_api_user", {})
        self.status_label.setStyleSheet("color: #64dba0; font-size: 11px;")
        self.status_label.setText(f"✅  Authenticated as '{username}'")
        self.login_success.emit(username, summary)

    def _on_login_error(self, msg: str):
        self._set_busy(False)
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
        self.status_label.setText(f"❌  Passkey failed: {msg.split(chr(10))[0]}")

    # ── Register Flow ─────────────────────────────────────────────

    def _on_register(self):
        creds = self._get_email_password()
        if not creds:
            return
        email, password = creds
        username = self._get_username()
        if not username:
            return

        self._set_busy(True, "⏳  Creating account via Chatify API…")

        # First signup/login via the API
        try:
            # Try to signup first
            try:
                result = _api_signup(email, username, password)
            except ValueError as e:
                # If email already exists, try login instead
                if "already exists" in str(e).lower():
                    result = _api_login(email, password)
                else:
                    raise
        except ValueError as e:
            self._set_busy(False)
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"❌  {e}")
            return
        except Exception as e:
            self._set_busy(False)
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"❌  Cannot reach the server: {e}")
            return

        self._api_token = result["token"]
        self._api_user = result["user"]

        # Now register passkey
        self.status_label.setStyleSheet("color: #ffffff; font-size: 11px;")
        self.status_label.setText("⏳  Waiting for authenticator…")
        self._worker = RegisterWorker(self.server, username)
        self._worker.finished.connect(self._on_register_done)
        self._worker.error.connect(self._on_register_error)
        self._worker.start()

    def _on_register_done(self, summary: dict):
        self._set_busy(False)
        username = summary.get("username", "")
        self.status_label.setStyleSheet("color: #64dba0; font-size: 11px;")
        self.status_label.setText(f"✅  Passkey registered for '{username}'. You can now login.")

    def _on_register_error(self, msg: str):
        self._set_busy(False)
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
        self.status_label.setText(f"❌  Registration failed: {msg.split(chr(10))[0]}")


# ═══════════════════════════════════════════════════════════════════════
# TOTP Setup Page — forced on first login if no TOTP key exists
# ═══════════════════════════════════════════════════════════════════════


class TotpSetupPage(QWidget):
    """Shows a QR code and requires a 6-digit confirmation to save TOTP."""


    totp_confirmed = pyqtSignal(str, dict)  # username, login_summary

    def __init__(self):
        super().__init__()
        self._pending_secret = None
        self._pending_username = None
        self._pending_summary = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("cardFrame")
        card.setFixedSize(400, 580)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 36, 40, 30)
        lay.setSpacing(0)

        # Title
        title = QLabel("Setup 2FA")
        title.setObjectName("totpTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)
        lay.addSpacing(4)

        subtitle = QLabel("Scan the QR code with your authenticator app")
        subtitle.setObjectName("totpSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        lay.addWidget(subtitle)
        lay.addSpacing(16)

        # Accent line
        accent = QLabel()
        accent.setObjectName("accentLine")
        accent.setFixedWidth(200)
        accent_row = QHBoxLayout()
        accent_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        accent_row.addWidget(accent)
        lay.addLayout(accent_row)
        lay.addSpacing(16)

        # QR code
        self.qr_label = QLabel()
        self.qr_label.setObjectName("qrContainer")
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setFixedSize(200, 200)
        qr_row = QHBoxLayout()
        qr_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_row.addWidget(self.qr_label)
        lay.addLayout(qr_row)
        lay.addSpacing(10)

        # Secret key (for manual entry)
        self.secret_label = QLabel("")
        self.secret_label.setObjectName("secretLabel")
        self.secret_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.secret_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        lay.addWidget(self.secret_label)
        lay.addSpacing(16)

        # Code input
        code_label = QLabel("VERIFICATION CODE")
        code_label.setObjectName("fieldLabel")
        lay.addWidget(code_label)
        lay.addSpacing(8)

        self.code_input = QLineEdit()
        self.code_input.setObjectName("totpInput")
        self.code_input.setPlaceholderText("Enter 6-digit code")
        self.code_input.setMaxLength(6)
        self.code_input.setMinimumHeight(48)
        lay.addWidget(self.code_input)
        lay.addSpacing(16)

        # Confirm button
        self.confirm_btn = QPushButton("CONFIRM")
        self.confirm_btn.setObjectName("confirmBtn")
        self.confirm_btn.setMinimumHeight(50)
        self.confirm_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.confirm_btn.clicked.connect(self._on_confirm)
        lay.addWidget(self.confirm_btn)
        lay.addSpacing(10)

        # Status
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)

        lay.addStretch()
        root.addWidget(card)

    def setup_for_user(self, username: str, summary: dict):
        """Generate a TOTP secret and display the QR code."""
        self._pending_username = username
        self._pending_summary = summary
        self._pending_secret = pyotp.random_base32()

        totp = pyotp.TOTP(self._pending_secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name="MMHCS Auth",
        )

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert PIL → QPixmap
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        qimage = QImage()
        qimage.loadFromData(buf.read())
        pixmap = QPixmap.fromImage(qimage)
        self.qr_label.setPixmap(pixmap.scaled(
            184, 184,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        ))

        self.secret_label.setText(self._pending_secret)
        self.code_input.clear()
        self.status_label.setText("")

    def _on_confirm(self):
        code = self.code_input.text().strip()
        if len(code) != 6 or not code.isdigit():
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("Please enter a valid 6-digit code")
            return

        totp = pyotp.TOTP(self._pending_secret)
        if totp.verify(code):
            # Save TOTP secret
            credential_store.save_totp_secret(
                self._pending_username,
                self._pending_secret,
            )
            self.status_label.setStyleSheet("color: #64dba0; font-size: 11px;")
            self.status_label.setText("✅  2FA configured successfully")
            # Proceed to welcome
            self.totp_confirmed.emit(
                self._pending_username,
                self._pending_summary,
            )
        else:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("❌  Invalid code. Try again.")
            self.code_input.clear()
            self.code_input.setFocus()


# ═══════════════════════════════════════════════════════════════════════
# TOTP Verify Page — shown on subsequent logins when TOTP exists
# ═══════════════════════════════════════════════════════════════════════


class TotpVerifyPage(QWidget):
    """Requires 6-digit TOTP code before granting access."""

    totp_verified = pyqtSignal(str, dict)  # username, summary

    def __init__(self):
        super().__init__()
        self._username = None
        self._summary = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("cardFrame")
        card.setFixedSize(400, 400)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 44, 40, 36)
        lay.setSpacing(0)

        # Icon
        icon = QLabel("◆")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("color: #ffffff; font-size: 20px;")
        lay.addWidget(icon)
        lay.addSpacing(12)

        title = QLabel("Verify 2FA")
        title.setObjectName("totpTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)
        lay.addSpacing(4)

        subtitle = QLabel("Enter the code from your authenticator app")
        subtitle.setObjectName("totpSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        lay.addWidget(subtitle)
        lay.addSpacing(20)

        # Accent
        accent = QLabel()
        accent.setObjectName("accentLine")
        accent.setFixedWidth(200)
        accent_row = QHBoxLayout()
        accent_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        accent_row.addWidget(accent)
        lay.addLayout(accent_row)
        lay.addSpacing(24)

        # Code input
        code_label = QLabel("VERIFICATION CODE")
        code_label.setObjectName("fieldLabel")
        lay.addWidget(code_label)
        lay.addSpacing(8)

        self.code_input = QLineEdit()
        self.code_input.setObjectName("totpInput")
        self.code_input.setPlaceholderText("Enter 6-digit code")
        self.code_input.setMaxLength(6)
        self.code_input.setMinimumHeight(48)
        lay.addWidget(self.code_input)
        lay.addSpacing(20)

        # Verify button
        self.verify_btn = QPushButton("VERIFY")
        self.verify_btn.setObjectName("confirmBtn")
        self.verify_btn.setMinimumHeight(50)
        self.verify_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.verify_btn.clicked.connect(self._on_verify)
        lay.addWidget(self.verify_btn)
        lay.addSpacing(10)

        # Status
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)

        lay.addStretch()
        root.addWidget(card)

    def setup_for_user(self, username: str, summary: dict):
        self._username = username
        self._summary = summary
        self.code_input.clear()
        self.status_label.setText("")

    def _on_verify(self):
        code = self.code_input.text().strip()
        if len(code) != 6 or not code.isdigit():
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("Please enter a valid 6-digit code")
            return

        secret = credential_store.get_totp_secret(self._username)
        if not secret:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("❌  No TOTP configured")
            return

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            self.totp_verified.emit(self._username, self._summary)
        else:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("❌  Invalid code. Try again.")
            self.code_input.clear()
            self.code_input.setFocus()


# ═══════════════════════════════════════════════════════════════════════
# Welcome Page Widget
# ═══════════════════════════════════════════════════════════════════════


class WelcomePage(QWidget):
    """Shown after successful login + TOTP verification."""

    logout_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("cardFrame")
        card.setFixedSize(400, 420)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 44, 40, 36)
        lay.setSpacing(0)

        # Checkmark icon
        icon = QLabel("✦")
        icon.setObjectName("welcomeIcon")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(icon)
        lay.addSpacing(16)

        # Welcome title
        self.welcome_title = QLabel("Welcome back")
        self.welcome_title.setObjectName("welcomeTitle")
        self.welcome_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.welcome_title)
        lay.addSpacing(8)

        # Username display
        self.user_label = QLabel("")
        self.user_label.setObjectName("welcomeUser")
        self.user_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.user_label)
        lay.addSpacing(16)

        # Accent line
        accent = QLabel()
        accent.setObjectName("welcomeAccent")
        accent.setFixedWidth(200)
        accent_row = QHBoxLayout()
        accent_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        accent_row.addWidget(accent)
        lay.addLayout(accent_row)
        lay.addSpacing(20)

        # Details
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("welcomeDetail")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_label.setWordWrap(True)
        lay.addWidget(self.detail_label)

        lay.addStretch()

        # Logout button
        logout_btn = QPushButton("SIGN OUT")
        logout_btn.setObjectName("logoutBtn")
        logout_btn.setMinimumHeight(46)
        logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        logout_btn.clicked.connect(self.logout_requested.emit)
        lay.addWidget(logout_btn)

        root.addWidget(card)

    def set_user(self, username: str, summary: dict):
        """Populate the welcome page with user info."""
        self.user_label.setText(username)
        cred_id = summary.get("credential_id", "")
        short_id = cred_id[:16] + "…" if len(cred_id) > 16 else cred_id
        self.detail_label.setText(
            f"Authenticated via passkey + 2FA\nCredential: {short_id}"
        )


# ═══════════════════════════════════════════════════════════════════════
# Main Window — Login → TOTP Setup/Verify → Welcome
# ═══════════════════════════════════════════════════════════════════════


class LuxuryLoginWindow(QWidget):
    """
    Flow:
    1. Login page (passkey auth)
    2. If user has NO TOTP → force TOTP setup (QR + confirm)
       If user HAS TOTP → require TOTP verification
    3. Mint JWT → open Chatify in browser → close window
    """

    def __init__(self):
        super().__init__()
        self.setObjectName("loginBackground")
        self.setWindowTitle("Login")
        self.setFixedSize(520, 700)
        self.setStyleSheet(LOGIN_STYLESHEET)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()
        root.addWidget(self.stack)

        # Page 0: Login
        self.login_page = LoginPage()
        self.login_page.login_success.connect(self._after_passkey_auth)
        self.stack.addWidget(self.login_page)

        # Page 1: TOTP Setup (forced on first login)
        self.totp_setup_page = TotpSetupPage()
        self.totp_setup_page.totp_confirmed.connect(self._launch_chatify)
        self.stack.addWidget(self.totp_setup_page)

        # Page 2: TOTP Verify (subsequent logins)
        self.totp_verify_page = TotpVerifyPage()
        self.totp_verify_page.totp_verified.connect(self._launch_chatify)
        self.stack.addWidget(self.totp_verify_page)

        # Page 3: Welcome / Launching status
        self.welcome_page = WelcomePage()
        self.welcome_page.logout_requested.connect(self._show_login)
        self.stack.addWidget(self.welcome_page)

        self.stack.setCurrentIndex(0)

    def _after_passkey_auth(self, username: str, summary: dict):
        """Called after successful passkey authentication."""
        if credential_store.has_totp(username):
            # User already has TOTP — ask for verification code
            self.totp_verify_page.setup_for_user(username, summary)
            self.stack.setCurrentIndex(2)
            self.setWindowTitle("Verify 2FA")
        else:
            # No TOTP yet — force setup
            self.totp_setup_page.setup_for_user(username, summary)
            self.stack.setCurrentIndex(1)
            self.setWindowTitle("Setup 2FA")

    def _launch_chatify(self, username: str, summary: dict):
        """
        Called after full authentication (passkey + TOTP).
        Uses the JWT from the API login to open Chatify in the browser.
        """
        self.setWindowTitle("Launching Chatify…")

        # Show launching status on the welcome page
        self.welcome_page.set_user(username, summary)
        self.welcome_page.welcome_title.setText("Launching Chatify…")
        self.welcome_page.detail_label.setText("Opening browser…")
        self.stack.setCurrentIndex(3)

        try:
            # Use the JWT token obtained from the API login
            token = summary.get("_api_token", "")
            if not token:
                raise ValueError("No API token available — login may have failed")

            # Open browser to the fido-callback endpoint which sets the cookie.
            # IMPORTANT: route this through the Vite frontend proxy (HTTPS), NOT
            # directly to the backend (HTTP).  Browsers silently discard cookies
            # with secure=True that arrive over plain HTTP on non-localhost IPs.
            # Vite proxies /api/* to the backend transparently, so the cookie is
            # set from an HTTPS origin and is accepted by the browser.
            callback_url = f"{_CHATIFY_CLIENT_URL}/api/auth/fido-callback?token={token}"
            webbrowser.open(callback_url)

            self.welcome_page.welcome_title.setText("✓ Launched!")
            self.welcome_page.detail_label.setText(
                f"Authenticated as '{username}'\nChatify is open in your browser."
            )

            # Close the desktop window after 3 seconds
            QTimer.singleShot(4000, self.close)

        except Exception as exc:
            self.welcome_page.welcome_title.setText("Launch Failed")
            self.welcome_page.detail_label.setText(f"Error: {exc}")

    def _show_login(self):
        self.login_page.email_input.clear()
        self.login_page.username_input.clear()
        self.login_page.status_label.setText("")
        self.stack.setCurrentIndex(0)
        self.setWindowTitle("Login")


# ═══════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(10, 10, 10))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(228, 228, 228))
    app.setPalette(palette)

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = LuxuryLoginWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
