"""
passkey_client.py — FIDO2 client wrapper for desktop use.

Auto-detects the environment:
- On Windows 10+ (non-admin): uses WindowsClient (webauthn.dll / Windows Hello)
- Otherwise: enumerates USB HID FIDO2 devices
"""

import ctypes
import sys

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice

# Force YubiKey (USB HID) mode — set to True to use Windows Hello instead
USE_YUBIKEY = False

# Try to import WindowsClient (only available on Windows)
try:
    from fido2.client.windows import WindowsClient

    _use_winclient = (
        not USE_YUBIKEY
        and WindowsClient.is_available()
        and not ctypes.windll.shell32.IsUserAnAdmin()
    )
except (ImportError, AttributeError):
    _use_winclient = False
    WindowsClient = None


# The origin must match the RP ID used by the server.
# For local testing we use "https://localhost".
# For production, set to your auth subdomain: ORIGIN = "https://auth.domain.com"
ORIGIN = "https://localhost"


class CliInteraction(UserInteraction):
    """Fallback CLI-based user interaction for non-Windows or admin scenarios."""

    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        from getpass import getpass
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def _enumerate_devices():
    """Enumerate USB HID FIDO2 devices."""
    for dev in CtapHidDevice.list_devices():
        yield dev


def get_client(user_interaction=None):
    """
    Locate a suitable FIDO2 client.

    Returns:
        (client, info) tuple. info may be None when using WindowsClient.

    Raises:
        RuntimeError: If no suitable authenticator is found.
    """
    client_data_collector = DefaultClientDataCollector(ORIGIN)

    # Prefer Windows WebAuthn API when available and not running as admin
    if _use_winclient and WindowsClient is not None:
        return WindowsClient(client_data_collector), None

    # Fall back to USB device enumeration
    interaction = user_interaction or CliInteraction()

    for dev in _enumerate_devices():
        client = Fido2Client(
            dev,
            client_data_collector=client_data_collector,
            user_interaction=interaction,
        )
        return client, client.info

    raise RuntimeError(
        "No FIDO2 authenticator found!\n"
        "Please connect a security key or ensure Windows Hello is available."
    )


def is_windows_client_available() -> bool:
    """Check whether the Windows WebAuthn API is available."""
    return _use_winclient
