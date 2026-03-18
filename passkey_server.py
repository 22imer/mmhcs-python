"""
passkey_server.py — Local Relying Party (RP) server using fido2.server.Fido2Server.

Handles both registration (attestation) and authentication (assertion) flows.
All operations happen locally — no network server required.
"""

import os
import base64

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData

import credential_store


# Relying Party configuration
# For production, set to your domain: RP_ID = "domain.com"
RP_ID = "localhost"
RP_NAME = "MMHCS Auth"


class PasskeyServer:
    """Wraps Fido2Server with credential store integration."""

    def __init__(self):
        self.server = Fido2Server(
            {"id": RP_ID, "name": RP_NAME},
            attestation="direct",
        )

    # ── Registration (Attestation) ─────────────────────────────────────

    def begin_registration(self, username: str):
        """
        Start the registration ceremony.

        Returns:
            (options, state) tuple.
        """
        # Build the user entity
        existing_user_id = credential_store.get_user_id(username)
        user_id = existing_user_id or os.urandom(32)

        user = {"id": user_id, "name": username, "display_name": username}

        # Load existing credentials so we can set excludeCredentials
        existing_cred_bytes = credential_store.get_credentials(username)
        existing_creds = [
            AttestedCredentialData(c) for c in existing_cred_bytes
        ]

        options, state = self.server.register_begin(
            user,
            credentials=existing_creds,
            user_verification="preferred",
            resident_key_requirement="required",  # Store credential ON the key
        )

        # Stash our own data in state (fido2 state only has challenge + uv)
        state["_username"] = username
        state["_user_id"] = base64.urlsafe_b64encode(user_id).decode("ascii")

        return options, state

    def complete_registration(self, state: dict, result) -> dict:
        """
        Finish the registration ceremony.

        Args:
            state: The state dict returned by begin_registration.
            result: The RegistrationResponse from the client.

        Returns:
            dict with summary info about the registered credential.
        """
        # register_complete returns AuthenticatorData
        auth_data = self.server.register_complete(state, result)

        # auth_data.credential_data is AttestedCredentialData (bytes subclass)
        cred = auth_data.credential_data

        # Recover our stashed user info
        username = state.get("_username", "unknown")
        user_id = base64.urlsafe_b64decode(state["_user_id"])

        # Persist the credential
        credential_store.save_credential(
            username,
            bytes(cred),
            user_id,
        )

        # Build a human-readable summary
        cred_id_b64 = base64.urlsafe_b64encode(cred.credential_id).decode()
        return {
            "status": "ok",
            "username": username,
            "credential_id": cred_id_b64,
            "public_key_alg": str(cred.public_key),
            "aaguid": str(cred.aaguid),
        }

    # ── Authentication (Assertion) ─────────────────────────────────────

    def begin_authentication(self, username: str):
        """
        Start the authentication ceremony.

        Raises:
            ValueError: If no credentials are registered for the user.
        """
        cred_bytes = credential_store.get_credentials(username)
        if not cred_bytes:
            raise ValueError(f"No credentials registered for '{username}'")

        credentials = [AttestedCredentialData(c) for c in cred_bytes]

        options, state = self.server.authenticate_begin(
            credentials,
            user_verification="preferred",
        )

        # Stash username for complete step
        state["_username"] = username

        return options, state

    def complete_authentication(self, state: dict, credentials_bytes: list[bytes], response) -> dict:
        """
        Finish the authentication ceremony.

        Args:
            state: The state dict from begin_authentication.
            credentials_bytes: The raw credential data bytes for the user.
            response: The full AuthenticationResponse from the client.

        Returns:
            dict with summary info about the authentication.
        """
        credentials = [AttestedCredentialData(c) for c in credentials_bytes]

        # authenticate_complete expects (state, credentials, response)
        # where response is the full AuthenticationResponse
        cred = self.server.authenticate_complete(state, credentials, response)

        return {
            "status": "ok",
            "username": state.get("_username", "unknown"),
            "credential_id": base64.urlsafe_b64encode(
                cred.credential_id
            ).decode(),
        }
