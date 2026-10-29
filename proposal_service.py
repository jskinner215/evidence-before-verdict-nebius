"""Async UI binding. No provider, key lookup, file creation or client at import.

The optional SQLite store is private local attempt persistence, not a shared
Lambda/DynamoDB quota store. A future cloud handler must inject its reviewed
durable store and reserve its separate account-wide allowance before transport.
"""
import json
from copy import deepcopy
from contextlib import closing
from pathlib import Path
import re
import sqlite3

from nebius_adapter import initial_result, propose_async
from triage import InputError, canonical, case_by_id, digest

REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")
MAX_RECEIPT_BYTES = 16384


def validate_packet(packet):
    if not isinstance(packet, dict) or set(packet) != {"case_id", "source_sha256", "request_id"}:
        raise InputError("Send only case_id, source_sha256 and request_id.")
    case_id, source_hash, request_id = packet["case_id"], packet["source_sha256"], packet["request_id"]
    source = case_by_id(case_id)
    if source_hash != source["source_sha256"]:
        raise InputError("Source changed. Reload the authored case before requesting a candidate.")
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise InputError("Use one bounded request ID.")
    return case_id, source_hash, request_id


def disconnected_response(packet):
    case_id, _, request_id = validate_packet(packet)
    return {"request_id": request_id, "mode": "disconnected", "proposal": initial_result(case_id)}


class AttemptStoreError(RuntimeError):
    pass


class SQLiteAttemptStore:
    """Explicitly constructed local-only durable no-repeat ledger.

    A pending row after process termination remains uncertain and is not retried.
    No rows are evicted to make space: old request IDs must not regain authority.
    The caller chooses a private path; there is no default database or auth read.
    """
    def __init__(self, path, *, maximum_records=256):
        if not isinstance(path, (str, Path)) or str(path) == ":memory:":
            raise ValueError("Choose an explicit private filesystem database.")
        if type(maximum_records) is not int or not 1 <= maximum_records <= 2048:
            raise ValueError("Choose a bounded private attempt capacity.")
        self.path, self.maximum_records = Path(path), maximum_records
        with closing(self._connect()) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS attempts (request_id TEXT PRIMARY KEY, source_key TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT, receipt_sha256 TEXT)")
            connection.execute("CREATE TABLE IF NOT EXISTS source_locks (source_key TEXT PRIMARY KEY, request_id TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=1, isolation_level=None)

    def claim(self, request_id, source_key):
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT source_key,state,receipt,receipt_sha256 FROM attempts WHERE request_id=?", (request_id,)).fetchone()
                if row:
                    connection.commit()
                    if row[0] != source_key:
                        return "conflict", None
                    if row[1] != "complete":
                        return "pending", None
                    receipt = json.loads(row[2])
                    case_id, source_hash, mode = source_key.split(":")
                    proposal = receipt.get("proposal", {}) if isinstance(receipt, dict) else {}
                    if (digest(receipt) != row[3] or receipt.get("request_id") != request_id
                            or receipt.get("mode") != mode or proposal.get("case_id") != case_id
                            or proposal.get("source_sha256") != source_hash
                            or proposal.get("provider", {}).get("execution_verified") is not False):
                        raise AttemptStoreError("Stored receipt failed source/integrity validation; no new attempt allowed.")
                    return "complete", receipt
                lock = connection.execute("SELECT request_id FROM source_locks WHERE source_key=?", (source_key,)).fetchone()
                if lock:
                    connection.commit()
                    return "source_pending", lock[0]
                count = connection.execute("SELECT count(*) FROM attempts").fetchone()[0]
                if count >= self.maximum_records:
                    connection.commit()
                    return "capacity", None
                connection.execute("INSERT INTO attempts VALUES (?,?,'pending',NULL,NULL)", (request_id, source_key))
                connection.execute("INSERT INTO source_locks VALUES (?,?)", (source_key, request_id))
                connection.commit()
                return "claimed", None
        except (sqlite3.Error, ValueError, TypeError, AttributeError):
            raise AttemptStoreError("Private attempt store unavailable; no new attempt is allowed.") from None

    def finish(self, request_id, source_key, receipt):
        text = canonical(receipt)
        if len(text.encode("utf-8")) > MAX_RECEIPT_BYTES:
            raise AttemptStoreError("Private receipt exceeded its bound.")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("UPDATE attempts SET state='complete',receipt=?,receipt_sha256=? WHERE request_id=? AND source_key=? AND state='pending'", (text, digest(receipt), request_id, source_key))
                if cursor.rowcount != 1:
                    raise AttemptStoreError("Private attempt receipt changed; do not repeat the request.")
                if receipt.get("proposal", {}).get("outcome") != "request_uncertain":
                    connection.execute("DELETE FROM source_locks WHERE source_key=? AND request_id=?", (source_key, request_id))
                connection.commit()
        except sqlite3.Error:
            raise AttemptStoreError("Private receipt could not be saved; the pending attempt must not be repeated.") from None


class ProposalService:
    def __init__(self, *, transport=None, api_key=None, mode="disconnected", attempt_store=None,
                 dispatch_count=None):
        if mode not in ("disconnected", "mock", "configured_unverified"):
            raise ValueError("Unknown proposal mode.")
        if mode == "disconnected":
            if transport is not None or api_key is not None or attempt_store is not None or dispatch_count is not None:
                raise ValueError("Disconnected mode accepts no transport, key or persistence.")
        elif not callable(transport) or not isinstance(api_key, str) or not api_key or attempt_store is None or not callable(dispatch_count):
            raise ValueError("An enabled binding needs explicit transport, key, attempt store and server dispatch counter.")
        if dispatch_count is not None and not callable(dispatch_count):
            raise ValueError("Dispatch observation must be an explicit server callback.")
        self._transport, self._api_key = transport, api_key
        self._mode, self._store = mode, attempt_store
        self._dispatch_count = dispatch_count

    def status(self):
        return self.describe(self._mode)

    @staticmethod
    def describe(mode):
        """Pure metadata; does not construct an enabled execution binding."""
        if mode not in ("disconnected", "mock", "configured_unverified"):
            raise ValueError("Unknown proposal mode.")
        return {"provider": {"name": "Nebius Token Factory", "status":
                "mock_transport" if mode == "mock" else mode,
                "execution_verified": False}, "mode": mode,
                "proposal_available": mode != "disconnected"}

    def _wrap(self, request_id, result):
        # Envelope decoration must not rewrite adapter evidence or mutate an
        # object later consulted by persistence/recovery classification.
        result = deepcopy(result)
        if self._mode == "mock":
            result["provider"]["status"] = "mock_transport"
            result["qualification"] = "Mock adapter candidate only. No Nebius request, real model quality, entitlement or paid usage was verified. " + result["qualification"]
        elif self._mode == "configured_unverified":
            result["provider"]["status"] = "configured_unverified"
        result["provider"]["execution_verified"] = False
        return {"request_id": request_id, "mode": self._mode, "proposal": result}

    def _uncertain(self, case_id, message):
        result = initial_result(case_id)
        result.update(outcome="request_uncertain", attempts=1, execution_may_have_occurred=True,
                      error=message)
        return result

    async def propose(self, packet):
        case_id, source_hash, request_id = validate_packet(packet)
        if self._mode == "disconnected":
            return self._wrap(request_id, initial_result(case_id))
        source_key = case_id + ":" + source_hash + ":" + self._mode
        try:
            claim, receipt = self._store.claim(request_id, source_key)
        except AttemptStoreError:
            # No new dispatch occurred here, but a prior invocation under this
            # identity may have dispatched. Unreadable history is not a local-
            # only proof and must retain the original recovery handle.
            result = self._uncertain(case_id, "Attempt persistence unavailable. No new dispatch started in this invocation; "
                                     "the original reservation and prior execution history remain unverified. "
                                     "Inspect that original identity before any replacement attempt.")
            result.update(attempts=0, original_request_id=request_id)
            return self._wrap(request_id, result)
        if claim == "conflict":
            raise InputError("Request ID belongs to a different source. No new attempt started.")
        if claim == "complete":
            return receipt
        if claim == "pending":
            return self._wrap(request_id, self._uncertain(case_id, "This request is pending or uncertain. Do not repeat it; inspect the original receipt before any new attempt."))
        if claim == "source_pending":
            result = self._uncertain(case_id, "This source has an unresolved attempt. A fresh request ID cannot start another call; inspect the original receipt.")
            result.update(attempts=0, original_request_id=receipt)
            return self._wrap(request_id, result)
        if claim != "claimed":
            result = initial_result(case_id)
            result.update(outcome="configuration_error", error="Private attempt capacity exhausted. No new model attempt started.")
            return self._wrap(request_id, result)
        import asyncio
        try:
            result = await propose_async(case_id, transport=self._transport, api_key=self._api_key,
                                         dispatch_count=self._dispatch_count)
            if case_by_id(case_id)["source_sha256"] != source_hash:
                result = self._uncertain(case_id, "Source changed during the attempt. Candidate withheld; no retry occurred.")
        except asyncio.CancelledError:
            # Never perform blocking paced storage from a cancellation handler.
            # The durable pending row/source barrier already fences all new IDs.
            # UI abort/process death do not prove this path ran or that a remote
            # provider stopped. Read the original pending attempt later.
            raise
        adapter_snapshot = deepcopy(result)
        no_dispatch = (adapter_snapshot.get("outcome") == "configuration_error"
                       and type(adapter_snapshot.get("attempts")) is int and adapter_snapshot["attempts"] == 0
                       and adapter_snapshot.get("execution_may_have_occurred") is False)
        receipt = self._wrap(request_id, adapter_snapshot)
        try:
            self._store.finish(request_id, source_key, receipt)
        except AttemptStoreError:
            if no_dispatch:
                # This invocation knows no dispatch occurred, but that fact and
                # lock release were not durably confirmed. Do not relabel it as
                # a provider attempt, and never release/retry from client data.
                failure = deepcopy(adapter_snapshot)
                failure["error"] = ("No provider dispatch occurred in this invocation. The local completion/release "
                                   "could not be confirmed; the original reservation may remain pending. "
                                   "Inspect its durable state before any new attempt. No retry occurred.")
                failure["original_request_id"] = request_id
                return self._wrap(request_id, failure)
            return self._wrap(request_id, self._uncertain(case_id, "Attempt receipt could not be saved. Candidate withheld; the pending request must not be repeated."))
        return receipt
