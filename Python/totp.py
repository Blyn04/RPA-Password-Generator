"""TOTP (Time-based One-Time Password) module for RPA Password Generator.

Pure-Python implementation of HOTP (RFC 4226) and TOTP (RFC 6238) with
account management and otpauth URI parsing.  Uses only Python standard
library modules — no external dependencies required.
"""

import hmac
import hashlib
import struct
import time
import base64
import uuid
import json
import os
import urllib.parse
from datetime import datetime
from typing import Optional, List


# ---------------------------------------------------------------------------
# Core OTP helpers
# ---------------------------------------------------------------------------

def hotp(
    secret_bytes: bytes,
    counter: int,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """Compute an HOTP code per RFC 4226.

    Parameters
    ----------
    secret_bytes:
        The shared secret as raw bytes.
    counter:
        Moving factor (8-byte big-endian unsigned integer).
    digits:
        Number of digits in the returned code (typically 6 or 8).
    algorithm:
        Hash algorithm name accepted by :mod:`hashlib`
        (``'sha1'``, ``'sha256'``, ``'sha512'``).

    Returns
    -------
    str
        Zero-padded OTP string of length *digits*.
    """
    counter_bytes = struct.pack(">Q", counter)
    hmac_digest = hmac.new(secret_bytes, counter_bytes, algorithm).digest()

    # Dynamic truncation (RFC 4226 §5.4)
    offset = hmac_digest[-1] & 0x0F
    truncated = (
        ((hmac_digest[offset] & 0x7F) << 24)
        | ((hmac_digest[offset + 1] & 0xFF) << 16)
        | ((hmac_digest[offset + 2] & 0xFF) << 8)
        | (hmac_digest[offset + 3] & 0xFF)
    )
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


def totp(
    secret_bytes: bytes,
    time_step: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    current_time: float = None,
) -> str:
    """Compute a TOTP code per RFC 6238.

    Parameters
    ----------
    secret_bytes:
        The shared secret as raw bytes.
    time_step:
        Time step in seconds (default 30).
    digits:
        Number of digits in the returned code.
    algorithm:
        Hash algorithm name (``'sha1'``, ``'sha256'``, ``'sha512'``).
    current_time:
        Unix timestamp to use; defaults to :func:`time.time`.

    Returns
    -------
    str
        Zero-padded OTP string of length *digits*.
    """
    if current_time is None:
        current_time = time.time()
    counter = int(current_time) // time_step
    return hotp(secret_bytes, counter, digits, algorithm)


def time_remaining(time_step: int = 30, current_time: float = None) -> int:
    """Return seconds remaining until the next TOTP code rotates.

    Parameters
    ----------
    time_step:
        Time step in seconds (default 30).
    current_time:
        Unix timestamp to use; defaults to :func:`time.time`.

    Returns
    -------
    int
        Seconds until the current TOTP window expires.
    """
    if current_time is None:
        current_time = time.time()
    return time_step - (int(current_time) % time_step)


# ---------------------------------------------------------------------------
# Encoding / URI helpers
# ---------------------------------------------------------------------------

def base32_decode(secret: str) -> bytes:
    """Decode a Base32-encoded secret, tolerating missing padding and spaces.

    Parameters
    ----------
    secret:
        Base32 string (spaces and lowercase are accepted).

    Returns
    -------
    bytes
        Decoded secret bytes.
    """
    cleaned = secret.replace(" ", "").upper()
    padding_needed = (8 - len(cleaned) % 8) % 8
    padded = cleaned + "=" * padding_needed
    return base64.b32decode(padded)


def parse_otpauth_uri(uri: str) -> dict:
    """Parse an ``otpauth://`` URI into its component parts.

    Supports URIs of the form::

        otpauth://totp/Label?secret=XXX&issuer=YYY&algorithm=ZZZ&digits=N&period=P

    Parameters
    ----------
    uri:
        Full otpauth URI string.

    Returns
    -------
    dict
        Dictionary with keys ``type``, ``label``, ``secret``, ``issuer``,
        ``algorithm``, ``digits``, and ``period``.

    Raises
    ------
    ValueError
        If the URI scheme is not ``otpauth`` or the required ``secret``
        parameter is missing.
    """
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError(f"Invalid URI scheme: {parsed.scheme!r} (expected 'otpauth')")

    otp_type = parsed.hostname or parsed.netloc  # e.g. "totp"
    label = urllib.parse.unquote(parsed.path.lstrip("/"))

    params = urllib.parse.parse_qs(parsed.query)

    secret_values = params.get("secret")
    if not secret_values:
        raise ValueError("URI is missing the required 'secret' parameter")

    return {
        "type": otp_type,
        "label": label,
        "secret": secret_values[0],
        "issuer": params.get("issuer", [""])[0],
        "algorithm": params.get("algorithm", ["sha1"])[0].lower(),
        "digits": int(params.get("digits", ["6"])[0]),
        "period": int(params.get("period", ["30"])[0]),
    }


# ---------------------------------------------------------------------------
# Account manager
# ---------------------------------------------------------------------------

class TOTPManager:
    """Manage multiple TOTP accounts with optional JSON-file persistence.

    Parameters
    ----------
    storage_path:
        Path to a JSON file used for persistence.  If ``None``, accounts
        are kept in memory only and lost when the object is garbage-collected.
    """

    def __init__(self, storage_path: str = None) -> None:
        self._storage_path: Optional[str] = storage_path
        self._accounts: List[dict] = []
        if self._storage_path is not None:
            self._load()

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        """Load accounts from the JSON storage file (if it exists)."""
        if self._storage_path and os.path.isfile(self._storage_path):
            with open(self._storage_path, "r", encoding="utf-8") as fh:
                self._accounts = json.load(fh)

    def _save(self) -> None:
        """Save accounts to the JSON storage file."""
        if self._storage_path is not None:
            directory = os.path.dirname(self._storage_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(self._storage_path, "w", encoding="utf-8") as fh:
                json.dump(self._accounts, fh, indent=2, ensure_ascii=False)

    # -- account management -------------------------------------------------

    def add_account(
        self,
        label: str,
        secret: str,
        issuer: str = "",
        algorithm: str = "sha1",
        digits: int = 6,
        period: int = 30,
    ) -> str:
        """Add a new TOTP account.

        Parameters
        ----------
        label:
            Human-readable account label (e.g. ``"user@example.com"``).
        secret:
            Base32-encoded shared secret.
        issuer:
            Service or organisation name.
        algorithm:
            Hash algorithm (``'sha1'``, ``'sha256'``, ``'sha512'``).
        digits:
            Number of OTP digits.
        period:
            TOTP time step in seconds.

        Returns
        -------
        str
            Unique account identifier (UUID4).

        Raises
        ------
        ValueError
            If *secret* cannot be Base32-decoded.
        """
        # Validate that the secret is decodable.
        try:
            base32_decode(secret)
        except Exception as exc:
            raise ValueError(f"Invalid Base32 secret: {exc}") from exc

        account_id = str(uuid.uuid4())
        account: dict = {
            "id": account_id,
            "label": label,
            "secret": secret,
            "issuer": issuer,
            "algorithm": algorithm.lower(),
            "digits": digits,
            "period": period,
            "added_at": datetime.now().isoformat(),
        }
        self._accounts.append(account)
        self._save()
        return account_id

    def add_from_uri(self, uri: str) -> str:
        """Parse an ``otpauth://`` URI and add the account.

        Parameters
        ----------
        uri:
            Full otpauth URI string.

        Returns
        -------
        str
            Unique account identifier (UUID4).
        """
        info = parse_otpauth_uri(uri)
        return self.add_account(
            label=info["label"],
            secret=info["secret"],
            issuer=info["issuer"],
            algorithm=info["algorithm"],
            digits=info["digits"],
            period=info["period"],
        )

    def remove_account(self, account_id: str) -> None:
        """Remove an account by its identifier.

        Raises
        ------
        KeyError
            If no account with *account_id* exists.
        """
        for idx, acct in enumerate(self._accounts):
            if acct["id"] == account_id:
                del self._accounts[idx]
                self._save()
                return
        raise KeyError(f"Account not found: {account_id!r}")

    # -- code generation ----------------------------------------------------

    def _find_account(self, account_id: str) -> dict:
        """Return the account dict for *account_id* or raise :exc:`KeyError`."""
        for acct in self._accounts:
            if acct["id"] == account_id:
                return acct
        raise KeyError(f"Account not found: {account_id!r}")

    def get_code(self, account_id: str, current_time: float = None) -> dict:
        """Generate the current TOTP code for an account.

        Parameters
        ----------
        account_id:
            Unique account identifier.
        current_time:
            Unix timestamp override; defaults to :func:`time.time`.

        Returns
        -------
        dict
            ``{'code', 'remaining_seconds', 'account_label', 'issuer'}``
        """
        acct = self._find_account(account_id)
        secret_bytes = base32_decode(acct["secret"])
        code = totp(
            secret_bytes,
            time_step=acct["period"],
            digits=acct["digits"],
            algorithm=acct["algorithm"],
            current_time=current_time,
        )
        remaining = time_remaining(
            time_step=acct["period"],
            current_time=current_time,
        )
        return {
            "code": code,
            "remaining_seconds": remaining,
            "account_label": acct["label"],
            "issuer": acct["issuer"],
        }

    def get_all_codes(self, current_time: float = None) -> list:
        """Generate TOTP codes for every registered account.

        Returns
        -------
        list[dict]
            One dict per account (same shape as :meth:`get_code` output).
        """
        return [
            self.get_code(acct["id"], current_time=current_time)
            for acct in self._accounts
        ]

    def list_accounts(self) -> list:
        """Return account metadata for all accounts, **excluding secrets**.

        Returns
        -------
        list[dict]
            Each dict contains ``id``, ``label``, ``issuer``, ``algorithm``,
            ``digits``, ``period``, and ``added_at``.
        """
        return [
            {k: v for k, v in acct.items() if k != "secret"}
            for acct in self._accounts
        ]
