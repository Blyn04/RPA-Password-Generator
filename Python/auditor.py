"""
Password Auditor Module
========================

Provides password policy checking, auditing (single and batch), similarity
detection via Levenshtein distance, and report generation for the
RPA Password Generator project.
"""

import string
import json
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Tuple, Optional

from security import calculate_entropy, evaluate_strength, is_common_password


# ---------------------------------------------------------------------------
# Levenshtein distance – pure Python, 2-row DP optimisation
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Return the Levenshtein (edit) distance between two strings.

    Uses a space-optimised dynamic-programming approach that keeps only
    two rows of the DP matrix in memory at any time.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        The minimum number of single-character edits (insertions,
        deletions, or substitutions) required to transform *s1* into *s2*.
    """
    if s1 == s2:
        return 0

    len1, len2 = len(s1), len(s2)

    # Ensure s1 is the shorter string so the row length is minimal.
    if len1 > len2:
        s1, s2 = s2, s1
        len1, len2 = len2, len1

    # previous_row and current_row only need (len1 + 1) entries.
    previous_row: List[int] = list(range(len1 + 1))
    current_row: List[int] = [0] * (len1 + 1)

    for j in range(1, len2 + 1):
        current_row[0] = j
        for i in range(1, len1 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            current_row[i] = min(
                current_row[i - 1] + 1,      # insertion
                previous_row[i] + 1,          # deletion
                previous_row[i - 1] + cost,   # substitution
            )
        previous_row, current_row = current_row, previous_row

    # After the swap the result sits in previous_row.
    return previous_row[len1]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PasswordPolicy:
    """Defines the rules a password must satisfy."""

    min_length: int = 8
    max_length: int = 128
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True
    min_entropy: float = 60.0
    max_age_days: int = 90
    disallow_common: bool = True


@dataclass
class PolicyViolation:
    """Represents a single policy violation detected during auditing.

    Attributes:
        field: The policy field that was violated.
        message: A human-readable description of the violation.
        severity: One of ``'critical'``, ``'warning'``, or ``'info'``.
    """

    field: str
    message: str
    severity: str  # 'critical' | 'warning' | 'info'


@dataclass
class AuditResult:
    """Holds the full audit outcome for a single password.

    Attributes:
        password: The original password that was audited.
        length: Length of the password in characters.
        entropy: Shannon entropy in bits.
        strength: Strength label returned by ``evaluate_strength``.
        is_compromised: Whether the password appears in the common list.
        violations: List of :class:`PolicyViolation` objects.
        duplicate_of: Indices of other passwords in the batch that are
            identical to this one.
        similar_to: List of ``(index, distance)`` tuples for passwords
            within the similarity threshold.
    """

    password: str
    length: int
    entropy: float
    strength: str
    is_compromised: bool
    violations: list = field(default_factory=list)
    duplicate_of: list = field(default_factory=list)
    similar_to: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy checking
# ---------------------------------------------------------------------------

def check_policy(
    password: str,
    policy: Optional[PasswordPolicy] = None,
    created_date: Optional[datetime] = None,
) -> List[PolicyViolation]:
    """Evaluate *password* against a :class:`PasswordPolicy`.

    Args:
        password: The password to check.
        policy: Policy to enforce.  Uses ``PasswordPolicy()`` defaults
            when *None*.
        created_date: Optional creation timestamp used for age checking.

    Returns:
        A list of :class:`PolicyViolation` instances (may be empty).
    """
    if policy is None:
        policy = PasswordPolicy()

    violations: List[PolicyViolation] = []

    # ---- Length constraints (critical) ------------------------------------
    if len(password) < policy.min_length:
        violations.append(PolicyViolation(
            field="min_length",
            message=f"Password length ({len(password)}) is below the minimum ({policy.min_length}).",
            severity="critical",
        ))

    if len(password) > policy.max_length:
        violations.append(PolicyViolation(
            field="max_length",
            message=f"Password length ({len(password)}) exceeds the maximum ({policy.max_length}).",
            severity="critical",
        ))

    # ---- Character class requirements (warning) --------------------------
    if policy.require_upper and not any(c in string.ascii_uppercase for c in password):
        violations.append(PolicyViolation(
            field="require_upper",
            message="Password must contain at least one uppercase letter.",
            severity="warning",
        ))

    if policy.require_lower and not any(c in string.ascii_lowercase for c in password):
        violations.append(PolicyViolation(
            field="require_lower",
            message="Password must contain at least one lowercase letter.",
            severity="warning",
        ))

    if policy.require_digit and not any(c in string.digits for c in password):
        violations.append(PolicyViolation(
            field="require_digit",
            message="Password must contain at least one digit.",
            severity="warning",
        ))

    if policy.require_special and not any(c in string.punctuation for c in password):
        violations.append(PolicyViolation(
            field="require_special",
            message="Password must contain at least one special character.",
            severity="warning",
        ))

    # ---- Entropy (warning) ------------------------------------------------
    entropy = calculate_entropy(password)
    if entropy < policy.min_entropy:
        violations.append(PolicyViolation(
            field="min_entropy",
            message=f"Password entropy ({entropy:.2f} bits) is below the minimum ({policy.min_entropy:.2f} bits).",
            severity="warning",
        ))

    # ---- Age check (info) -------------------------------------------------
    if created_date is not None:
        age_days = (datetime.now() - created_date).days
        if age_days > policy.max_age_days:
            violations.append(PolicyViolation(
                field="max_age_days",
                message=f"Password age ({age_days} days) exceeds the maximum ({policy.max_age_days} days).",
                severity="info",
            ))

    # ---- Common password (critical) ---------------------------------------
    if policy.disallow_common and is_common_password(password):
        violations.append(PolicyViolation(
            field="disallow_common",
            message="Password is on the list of commonly compromised passwords.",
            severity="critical",
        ))

    return violations


# ---------------------------------------------------------------------------
# Auditor class
# ---------------------------------------------------------------------------

class PasswordAuditor:
    """Audits passwords individually or in batches and generates reports.

    Args:
        policy: The :class:`PasswordPolicy` to enforce.  Defaults to
            ``PasswordPolicy()``.
        similarity_threshold: Maximum Levenshtein distance at which two
            passwords are considered "similar".
    """

    def __init__(
        self,
        policy: Optional[PasswordPolicy] = None,
        similarity_threshold: int = 3,
    ) -> None:
        self.policy = policy if policy is not None else PasswordPolicy()
        self.similarity_threshold = similarity_threshold

    # ---- Single-password audit -------------------------------------------

    def audit_single(
        self,
        password: str,
        created_date: Optional[datetime] = None,
    ) -> AuditResult:
        """Audit a single password against the stored policy.

        Args:
            password: The password to audit.
            created_date: Optional creation date for age checking.

        Returns:
            An :class:`AuditResult` with ``duplicate_of`` and
            ``similar_to`` left empty.
        """
        entropy = calculate_entropy(password)
        strength_label, _ = evaluate_strength(password, entropy=entropy)
        compromised = is_common_password(password)
        violations = check_policy(password, self.policy, created_date)

        return AuditResult(
            password=password,
            length=len(password),
            entropy=entropy,
            strength=strength_label,
            is_compromised=compromised,
            violations=violations,
            duplicate_of=[],
            similar_to=[],
        )

    # ---- Batch audit -----------------------------------------------------

    def audit_batch(
        self,
        passwords: list,
        created_dates: Optional[list] = None,
    ) -> List[AuditResult]:
        """Audit a list of passwords, detecting duplicates and similarities.

        Args:
            passwords: List of password strings.
            created_dates: Optional parallel list of :class:`datetime`
                objects for age checking.  Must be the same length as
                *passwords* when provided.

        Returns:
            A list of :class:`AuditResult` objects, one per password.
        """
        results: List[AuditResult] = []

        for idx, pwd in enumerate(passwords):
            created = created_dates[idx] if created_dates else None
            result = self.audit_single(pwd, created)
            results.append(result)

        # --- Duplicate and similarity detection ---------------------------
        count = len(passwords)
        for i in range(count):
            for j in range(count):
                if i == j:
                    continue

                # Exact duplicates
                if passwords[i] == passwords[j]:
                    if j not in results[i].duplicate_of:
                        results[i].duplicate_of.append(j)
                else:
                    # Similarity (only for non-duplicates)
                    dist = levenshtein_distance(passwords[i], passwords[j])
                    if dist <= self.similarity_threshold:
                        pair = (j, dist)
                        if pair not in results[i].similar_to:
                            results[i].similar_to.append(pair)

        return results

    # ---- Report generation -----------------------------------------------

    def generate_report(
        self,
        results: List[AuditResult],
        format: str = "text",
    ) -> str:
        """Generate a human-readable or JSON audit report.

        Args:
            results: List of :class:`AuditResult` objects (from
                :meth:`audit_single` or :meth:`audit_batch`).
            format: ``'text'`` for a formatted plain-text report or
                ``'json'`` for a machine-readable JSON string.

        Returns:
            The report as a string.
        """
        if format == "json":
            return self._generate_json(results)
        return self._generate_text(results)

    # ---- Private helpers -------------------------------------------------

    @staticmethod
    def _password_preview(password: str) -> str:
        """Return a truncated preview: first 3 characters + '***'."""
        if len(password) <= 3:
            return password + "***"
        return password[:3] + "***"

    def _generate_text(self, results: List[AuditResult]) -> str:
        """Produce the plain-text report."""
        lines: List[str] = []
        separator = "=" * 70

        lines.append(separator)
        lines.append("PASSWORD AUDIT REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(separator)
        lines.append("")

        # Per-password summaries
        for idx, r in enumerate(results):
            preview = self._password_preview(r.password)
            lines.append(f"[{idx}] {preview}")
            lines.append(f"     Strength : {r.strength}")
            lines.append(f"     Entropy  : {r.entropy:.2f} bits")
            lines.append(f"     Violations: {len(r.violations)}")
            if r.duplicate_of:
                lines.append(f"     Duplicates: {r.duplicate_of}")
            if r.similar_to:
                similar_info = ", ".join(
                    f"#{i}(d={d})" for i, d in r.similar_to
                )
                lines.append(f"     Similar  : {similar_info}")
            lines.append("")

        # Summary section
        lines.append(separator)
        lines.append("SUMMARY")
        lines.append(separator)
        lines.append(f"Total passwords audited: {len(results)}")

        # Strength breakdown
        strength_counts: dict = {}
        for r in results:
            strength_counts[r.strength] = strength_counts.get(r.strength, 0) + 1
        lines.append("Strength breakdown:")
        for label, count in strength_counts.items():
            lines.append(f"  {label}: {count}")

        total_violations = sum(len(r.violations) for r in results)
        lines.append(f"Total violations: {total_violations}")

        total_duplicates = sum(1 for r in results if r.duplicate_of)
        lines.append(f"Passwords with duplicates: {total_duplicates}")

        total_similar = sum(1 for r in results if r.similar_to)
        lines.append(f"Passwords with similar matches: {total_similar}")

        lines.append(separator)

        return "\n".join(lines)

    def _generate_json(self, results: List[AuditResult]) -> str:
        """Produce the JSON report."""
        records: List[dict] = []
        for idx, r in enumerate(results):
            records.append({
                "index": idx,
                "password_preview": self._password_preview(r.password),
                "length": r.length,
                "entropy": r.entropy,
                "strength": r.strength,
                "is_compromised": r.is_compromised,
                "violations": [
                    {"field": v.field, "message": v.message, "severity": v.severity}
                    for v in r.violations
                ],
                "duplicate_indices": r.duplicate_of,
                "similar_indices": r.similar_to,
            })
        return json.dumps(records, indent=2)


# ---------------------------------------------------------------------------
# Standalone file auditing
# ---------------------------------------------------------------------------

def audit_file(
    file_path: str,
    policy: Optional[PasswordPolicy] = None,
    similarity_threshold: int = 3,
) -> str:
    """Read passwords from a file and return a text audit report.

    Each line in the file is treated as one password.  Empty lines are
    skipped and leading/trailing whitespace is stripped.  If a line
    contains the marker ``'] '``, only the portion *after* that marker
    is used as the password.

    Args:
        file_path: Path to a text file containing passwords (one per
            line).
        policy: Optional :class:`PasswordPolicy` to enforce.
        similarity_threshold: Levenshtein distance threshold for
            similarity detection.

    Returns:
        A formatted plain-text audit report.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        IOError: If the file cannot be read.
    """
    passwords: List[str] = []

    with open(file_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if "] " in line:
                line = line.split("] ", 1)[1]
            passwords.append(line)

    auditor = PasswordAuditor(policy=policy, similarity_threshold=similarity_threshold)
    results = auditor.audit_batch(passwords)
    return auditor.generate_report(results, format="text")
