"""
login_ui.py — Luxury Login Interface wired to passkey backend.
Supports registration, authentication, forced TOTP setup on first login,
and a welcome view on success.
"""

import sys
import io
import json
import traceback

import pyotp
import qrcode

from PyQt6.QtCore import Qt, QThread, pyqtSignal
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

QLineEdit#usernameInput, QLineEdit#totpInput {
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 10px;
    padding: 14px 18px;
    color: #ffffff;
    font-size: 14px;
    font-weight: 400;
    selection-background-color: #333333;
}
QLineEdit#usernameInput:focus, QLineEdit#totpInput:focus {
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
        card.setFixedSize(400, 520)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 44, 40, 36)
        lay.setSpacing(0)

        # Diamond icon
        icon_label = QLabel("◆")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("color: #ffffff; font-size: 20px;")
        lay.addWidget(icon_label)
        lay.addSpacing(12)

        # Title
        title = QLabel("Welcome")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)
        lay.addSpacing(4)

        subtitle = QLabel("Authenticate with your passkey")
        subtitle.setObjectName("subtitleLabel")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(subtitle)
        lay.addSpacing(12)

        # Accent line
        accent = QLabel()
        accent.setObjectName("accentLine")
        accent.setFixedWidth(200)
        accent_container = QHBoxLayout()
        accent_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        accent_container.addWidget(accent)
        lay.addLayout(accent_container)
        lay.addSpacing(28)

        # Username field
        field_label = QLabel("USERNAME")
        field_label.setObjectName("fieldLabel")
        lay.addWidget(field_label)
        lay.addSpacing(8)

        self.username_input = QLineEdit()
        self.username_input.setObjectName("usernameInput")
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setMinimumHeight(48)
        lay.addWidget(self.username_input)
        lay.addSpacing(24)

        # Login button
        self.login_btn = QPushButton("LOGIN")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.setMinimumHeight(50)
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._on_login)
        lay.addWidget(self.login_btn)
        lay.addSpacing(12)

        # Register button
        self.register_btn = QPushButton("REGISTER")
        self.register_btn.setObjectName("registerBtn")
        self.register_btn.setMinimumHeight(50)
        self.register_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.register_btn.clicked.connect(self._on_register)
        lay.addWidget(self.register_btn)
        lay.addSpacing(16)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)

        lay.addStretch()

        root.addWidget(card)

    # ── Helpers ────────────────────────────────────────────────────

    def _get_username(self) -> str | None:
        username = self.username_input.text().strip()
        if not username:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText("Please enter a username")
            self.username_input.setFocus()
            return None
        return username

    def _set_busy(self, busy: bool, message: str = ""):
        self.login_btn.setEnabled(not busy)
        self.register_btn.setEnabled(not busy)
        self.username_input.setEnabled(not busy)
        if message:
            self.status_label.setStyleSheet("color: #ffffff; font-size: 11px;")
            self.status_label.setText(message)

    # ── Login Flow ────────────────────────────────────────────────

    def _on_login(self):
        username = self._get_username()
        if not username:
            return

        # Check if user has credentials
        creds = credential_store.get_credentials(username)
        if not creds:
            self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
            self.status_label.setText(f"No passkey registered for '{username}'. Register first.")
            return

        self._set_busy(True, "⏳  Waiting for authenticator…")
        self._worker = AuthenticateWorker(self.server, username)
        self._worker.finished.connect(self._on_login_done)
        self._worker.error.connect(self._on_login_error)
        self._worker.start()

    def _on_login_done(self, summary: dict):
        self._set_busy(False)
        username = summary.get("username", "")
        self.status_label.setStyleSheet("color: #64dba0; font-size: 11px;")
        self.status_label.setText(f"✅  Authenticated as '{username}'")
        self.login_success.emit(username, summary)

    def _on_login_error(self, msg: str):
        self._set_busy(False)
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 11px;")
        self.status_label.setText(f"❌  Login failed: {msg.split(chr(10))[0]}")

    # ── Register Flow ─────────────────────────────────────────────

    def _on_register(self):
        username = self._get_username()
        if not username:
            return

        self._set_busy(True, "⏳  Waiting for authenticator…")
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
    3. Welcome page
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
        self.totp_setup_page.totp_confirmed.connect(self._show_welcome)
        self.stack.addWidget(self.totp_setup_page)

        # Page 2: TOTP Verify (subsequent logins)
        self.totp_verify_page = TotpVerifyPage()
        self.totp_verify_page.totp_verified.connect(self._show_welcome)
        self.stack.addWidget(self.totp_verify_page)

        # Page 3: Welcome
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

    def _show_welcome(self, username: str, summary: dict):
        self.welcome_page.set_user(username, summary)
        self.stack.setCurrentIndex(3)
        self.setWindowTitle(f"Welcome — {username}")

    def _show_login(self):
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
