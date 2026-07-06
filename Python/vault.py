"""Encrypted password vault module for the RPA Password Generator project.

This module provides a secure, file-based password vault that encrypts all
stored credentials using Fernet symmetric encryption. The encryption key is
derived from a user-supplied master password via PBKDF2-HMAC-SHA256 with a
random salt. The vault supports creating, reading, updating, and deleting
password entries, as well as searching, filtering by category, and exporting
data. An auto-lock mechanism clears sensitive material from memory after a
configurable period of inactivity.
"""

import os
import json
import time
import uuid
import csv
import io
import base64
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class PasswordVault:
    """A Fernet-encrypted, file-backed password vault with auto-lock.

    Attributes:
        vault_path: Filesystem path to the encrypted vault JSON file.
        auto_lock_seconds: Seconds of inactivity before the vault locks itself.
    """

    def __init__(self, vault_path: str, auto_lock_seconds: int = 300) -> None:
        """Initialise the vault instance.

        Args:
            vault_path: Path where the vault file will be stored.
            auto_lock_seconds: Idle time (in seconds) before auto-lock.
        """
        self.vault_path: str = vault_path
        self.auto_lock_seconds: int = auto_lock_seconds
        self._entries: list = []
        self._key: bytes = None
        self._salt: bytes = None
        self._master_password: str = None
        self._last_access: float = None

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive a Fernet-compatible key from a master password and salt.

        Uses PBKDF2-HMAC-SHA256 with 480 000 iterations to produce a 32-byte
        key, then Base64-url-encodes it so it can be used with
        :class:`~cryptography.fernet.Fernet`.

        Args:
            master_password: The plaintext master password.
            salt: A 16-byte random salt.

        Returns:
            A 44-byte URL-safe Base64-encoded key suitable for Fernet.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        raw_key = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    # ------------------------------------------------------------------
    # Lock helpers
    # ------------------------------------------------------------------

    def _check_lock(self) -> None:
        """Raise :class:`RuntimeError` if the vault is locked or timed out.

        If the vault has been idle longer than *auto_lock_seconds*, it is
        locked automatically before the error is raised.

        Raises:
            RuntimeError: If the vault is not currently unlocked.
        """
        if self._key is None:
            raise RuntimeError("Vault is locked. Call unlock() first.")
        if time.time() - self._last_access > self.auto_lock_seconds:
            self.lock()
            raise RuntimeError(
                "Vault auto-locked due to inactivity. Call unlock() again."
            )

    def is_unlocked(self) -> bool:
        """Return ``True`` if the vault is unlocked and has not timed out."""
        if self._key is None:
            return False
        if time.time() - self._last_access > self.auto_lock_seconds:
            self.lock()
            return False
        return True

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------

    def create(self, master_password: str) -> None:
        """Create a new, empty vault file encrypted with *master_password*.

        Args:
            master_password: The master password to protect the vault.

        Raises:
            FileExistsError: If *vault_path* already exists.
        """
        if os.path.exists(self.vault_path):
            raise FileExistsError(
                f"Vault file already exists: {self.vault_path}"
            )

        salt = os.urandom(16)
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)

        encrypted_data = fernet.encrypt(json.dumps([]).encode("utf-8"))

        vault_content = {
            "salt": salt.hex(),
            "data": encrypted_data.decode("utf-8"),
        }

        os.makedirs(os.path.dirname(self.vault_path) or ".", exist_ok=True)
        with open(self.vault_path, "w", encoding="utf-8") as fh:
            json.dump(vault_content, fh)

    def unlock(self, master_password: str) -> None:
        """Decrypt and load the vault into memory.

        Args:
            master_password: The master password used when the vault was
                created (or last changed).

        Raises:
            FileNotFoundError: If the vault file does not exist.
            ValueError: If the master password is incorrect.
        """
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError(
                f"Vault file not found: {self.vault_path}"
            )

        with open(self.vault_path, "r", encoding="utf-8") as fh:
            vault_content = json.load(fh)

        salt = bytes.fromhex(vault_content["salt"])
        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(
                vault_content["data"].encode("utf-8")
            )
        except InvalidToken:
            raise ValueError("Incorrect master password.")

        self._entries = json.loads(decrypted.decode("utf-8"))
        self._key = key
        self._salt = salt
        self._master_password = master_password
        self._last_access = time.time()

    def lock(self) -> None:
        """Clear all sensitive data from memory, locking the vault."""
        self._entries = []
        self._key = None
        self._salt = None
        self._master_password = None
        self._last_access = None

    # ------------------------------------------------------------------
    # CRUD operations
    # ------------------------------------------------------------------

    def add_entry(
        self,
        site: str,
        username: str,
        password: str,
        category: str = "",
        notes: str = "",
    ) -> str:
        """Add a new credential entry to the vault.

        Args:
            site: Website or service name.
            username: Login username or e-mail.
            password: The password to store.
            category: Optional grouping category.
            notes: Optional free-text notes.

        Returns:
            The UUID string of the newly created entry.

        Raises:
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        entry_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        entry = {
            "id": entry_id,
            "site": site,
            "username": username,
            "password": password,
            "category": category,
            "notes": notes,
            "created_at": now,
            "updated_at": now,
        }

        self._entries.append(entry)
        self._save()
        return entry_id

    def get_entry(self, entry_id: str) -> dict:
        """Return the entry matching *entry_id*.

        Args:
            entry_id: UUID string of the entry.

        Returns:
            A copy of the entry dict.

        Raises:
            KeyError: If no entry with *entry_id* exists.
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        for entry in self._entries:
            if entry["id"] == entry_id:
                return dict(entry)
        raise KeyError(f"No entry found with id: {entry_id}")

    def update_entry(self, entry_id: str, **kwargs) -> None:
        """Update one or more fields on an existing entry.

        Only the keys ``site``, ``username``, ``password``, ``category``, and
        ``notes`` may be updated.  The ``updated_at`` timestamp is refreshed
        automatically.

        Args:
            entry_id: UUID string of the entry to update.
            **kwargs: Field names and their new values.

        Raises:
            KeyError: If no entry with *entry_id* exists.
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        for entry in self._entries:
            if entry["id"] == entry_id:
                for key, value in kwargs.items():
                    if key in ("site", "username", "password", "category", "notes"):
                        entry[key] = value
                entry["updated_at"] = datetime.now().isoformat()
                self._save()
                return
        raise KeyError(f"No entry found with id: {entry_id}")

    def delete_entry(self, entry_id: str) -> None:
        """Delete an entry from the vault.

        Args:
            entry_id: UUID string of the entry to delete.

        Raises:
            KeyError: If no entry with *entry_id* exists.
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        for i, entry in enumerate(self._entries):
            if entry["id"] == entry_id:
                self._entries.pop(i)
                self._save()
                return
        raise KeyError(f"No entry found with id: {entry_id}")

    def list_entries(self, category: str = None) -> list:
        """Return all entries, optionally filtered by *category*.

        Args:
            category: If supplied, only entries whose ``category`` matches
                (exact, case-sensitive) are returned.

        Returns:
            A list of entry dicts (copies).

        Raises:
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        if category is not None:
            return [
                dict(e) for e in self._entries if e["category"] == category
            ]
        return [dict(e) for e in self._entries]

    def search_entries(self, query: str) -> list:
        """Search entries by site, username, or notes (case-insensitive).

        Args:
            query: The search string.

        Returns:
            A list of matching entry dicts (copies).

        Raises:
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        query_lower = query.lower()
        results = []
        for entry in self._entries:
            if (
                query_lower in entry["site"].lower()
                or query_lower in entry["username"].lower()
                or query_lower in entry["notes"].lower()
            ):
                results.append(dict(entry))
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """Encrypt the current entries and write them to the vault file.

        Raises:
            RuntimeError: If the vault is locked (no key available).
        """
        fernet = Fernet(self._key)
        plaintext = json.dumps(self._entries).encode("utf-8")
        encrypted_data = fernet.encrypt(plaintext)

        vault_content = {
            "salt": self._salt.hex(),
            "data": encrypted_data.decode("utf-8"),
        }

        with open(self.vault_path, "w", encoding="utf-8") as fh:
            json.dump(vault_content, fh)

    # ------------------------------------------------------------------
    # Master password management
    # ------------------------------------------------------------------

    def change_master_password(
        self, old_password: str, new_password: str
    ) -> None:
        """Re-encrypt the vault with a new master password.

        The caller must supply the current (*old_password*) for verification.
        The vault is then re-encrypted with *new_password* using a fresh salt.

        Args:
            old_password: The current master password.
            new_password: The desired new master password.

        Raises:
            ValueError: If *old_password* does not match the stored master
                password.
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        if old_password != self._master_password:
            raise ValueError("Old master password is incorrect.")

        new_salt = os.urandom(16)
        new_key = self._derive_key(new_password, new_salt)

        self._key = new_key
        self._salt = new_salt
        self._master_password = new_password
        self._save()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_entries(self, format: str = "json") -> str:
        """Export all entries as a JSON or CSV string.

        Passwords are included in plaintext (not masked).

        Args:
            format: ``'json'`` (default) or ``'csv'``.

        Returns:
            A string containing all entries in the requested format.

        Raises:
            ValueError: If *format* is not ``'json'`` or ``'csv'``.
            RuntimeError: If the vault is locked.
        """
        self._check_lock()
        self._last_access = time.time()

        if format == "json":
            return json.dumps(self._entries, indent=2)

        if format == "csv":
            if not self._entries:
                return ""
            fieldnames = [
                "id",
                "site",
                "username",
                "password",
                "category",
                "notes",
                "created_at",
                "updated_at",
            ]
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self._entries)
            return output.getvalue()

        raise ValueError(
            f"Unsupported export format: {format!r}. Use 'json' or 'csv'."
        )
