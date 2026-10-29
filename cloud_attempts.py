"""Bounded low-level DynamoDB attempt protocol; no SDK/client/key defaults.

Fixed authored-source locks share the actual quota control CAS row. Each claim
or finish writes that control row plus one immutable-identity attempt row. Old
v2 control schemas are refused, never upgraded or reset implicitly.
"""
from copy import deepcopy
from datetime import date, datetime, timezone
import hashlib
import json
import math
import re
import zlib

from global_quota_v2 import DynamoQuotaStore, QuotaError, QuotaPolicy, flat_item_size
from nebius_adapter import initial_result, TIMEOUT_SECONDS
from proposal_service import AttemptStoreError, MAX_RECEIPT_BYTES, REQUEST_ID
from triage import CASES, canonical, case_by_id, digest, sample, strict_json, validate

MAX_ITEM_BYTES = 1024
MAX_LOGICAL_BYTES = MAX_RECEIPT_BYTES + 1024
MAX_ATTEMPTS = 256
MAGIC = b"NA4"
CONTROL_KEY = "quota#v2#control"
SOURCES = tuple((c["id"], case_by_id(c["id"])["source_sha256"]) for c in CASES)
if len(SOURCES) != 3 or len(set(SOURCES)) != 3:
    raise ValueError("Review a new bounded layout before changing the three authored sources")
# A fixed lossless dictionary uses only the already-public-in-the-app authored
# cases/templates. No provider input/response or credential trains this codec.
# Arbitrary novel incompressible receipts can still fail the 1-KiB item limit.
DICTIONARY = canonical({"cases": [case_by_id(i) for i, _ in SOURCES],
                        "templates": [initial_result(i) for i, _ in SOURCES],
                        "reports": [validate(i, sample(case_by_id(i))) for i, _ in SOURCES]}).encode()[-32768:]
CODEC = hashlib.sha256(DICTIONARY).hexdigest()
BASE_FIELDS = {"PK", "SK", "expireAt", "revision", "day", "postsDay", "postsLifetime", "rawDay", "rawLifetime", "nextAllowedMs"}
CONTROL_FIELDS = BASE_FIELDS | {"schema", "layout", "mode", "occupied", "locks", "attemptCount"}


def _binding_policy(policy, mode):
    if (type(policy) is not QuotaPolicy or policy.app_id != "nebius"
            or mode not in {"mock", "configured_unverified"}
            or policy.retention_until < policy.expires_at + 86400
            or policy.pacing_ms != 2000):
        raise ValueError("Nebius requires its exact policy/mode, reviewed 2000 ms pacing, and retained history")


def initial_control_candidate(*, policy, mode, now_ms):
    """Pure operator preparation only; never reads or writes a store.

    This candidate grants no permission to initialize a live table. A separate
    operator must establish a clean namespace and perform an independently
    approved conditional bootstrap. Runtime paths never call this helper.
    The persisted v4 schema remains compatible; history is never reset here.
    """
    _binding_policy(policy, mode)
    if type(now_ms) is not int or not 0 <= now_ms < min(policy.expires_at * 1000, 9999999999999):
        raise ValueError("An exact pre-expiry operator timestamp is required")
    day = datetime.fromtimestamp(now_ms / 1000, timezone.utc).date().isoformat()
    return {"PK": {"S": "nebius"}, "SK": {"S": CONTROL_KEY},
            "expireAt": {"N": str(policy.retention_until)}, "revision": {"N": "1"},
            "day": {"S": day}, "postsDay": {"N": "0"}, "postsLifetime": {"N": "0"},
            "rawDay": {"N": "0"}, "rawLifetime": {"N": "0"},
            "nextAllowedMs": {"N": str(now_ms + policy.pacing_ms)},
            "schema": {"S": "nebius-attempts-v4"},
            "layout": {"S": digest({"schema": "nebius-attempts-v4", "sources": SOURCES, "mode": mode, "codec": CODEC})},
            "mode": {"S": mode}, "occupied": {"N": "0"}, "locks": {"B": b"\0" * 96},
            "attemptCount": {"N": "0"}}


def request_hash(request_id):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise AttemptStoreError("Invalid bounded attempt identity")
    value = hashlib.sha256(request_id.encode()).hexdigest()
    if value == "0" * 64:
        raise AttemptStoreError("Reserved attempt identity")
    return value


def source_index(source_key, mode):
    if not isinstance(source_key, str):
        raise AttemptStoreError("Invalid authored source identity")
    for index, (case_id, source_hash) in enumerate(SOURCES):
        if source_key == case_id + ":" + source_hash + ":" + mode:
            return index
    raise AttemptStoreError("Source or provider mode changed")


def _number(value, *, minimum=0, maximum=9999999999999):
    if (not isinstance(value, dict) or set(value) != {"N"}
            or not isinstance(value["N"], str) or not re.fullmatch(r"0|[1-9][0-9]{0,12}", value["N"])
            or not minimum <= int(value["N"]) <= maximum):
        raise ValueError("Invalid bounded number")
    return int(value["N"])


def receipt_checked(receipt, request_id, source_key, mode):
    index = source_index(source_key, mode)
    case_id, source_hash = SOURCES[index]
    if (not isinstance(receipt, dict) or set(receipt) != {"request_id", "mode", "proposal"}
            or receipt["request_id"] != request_id or receipt["mode"] != mode):
        raise AttemptStoreError("Receipt identity changed")
    proposal = receipt["proposal"]
    expected_provider = "mock_transport" if mode == "mock" else "configured_unverified"
    required = set(initial_result(case_id))
    allowed = required | {"request", "http_status", "response_body_sha256", "original_request_id"}
    if (not isinstance(proposal, dict) or not required <= set(proposal) <= allowed or proposal.get("case_id") != case_id
            or proposal.get("source_sha256") != source_hash
            or proposal.get("provider", {}).get("execution_verified") is not False
            or proposal.get("provider", {}).get("status") != expected_provider
            or proposal.get("billing_verified") is not False
            or proposal.get("automatic_retries") != 0
            or type(proposal.get("attempts")) is not int or proposal["attempts"] not in (0, 1)
            or proposal.get("outcome") not in {"disconnected", "configuration_error", "request_uncertain", "invalid_response", "provider_rejected", "candidate_checked", "candidate_rejected"}):
        raise AttemptStoreError("Receipt source or unverified-provider boundary changed")
    report = proposal.get("report")
    if report is not None:
        if (not isinstance(report, dict) or report.get("case_id") != case_id
                or report.get("source_sha256") != source_hash
                or report.get("provider", {}).get("status") != "disconnected"
                or report.get("verdict") not in {"supported", "unsupported", "abstain"}
                or report.get("report_sha256") != digest({k: v for k, v in report.items() if k != "report_sha256"})):
            raise AttemptStoreError("Stored report failed identity/integrity checks")
    try:
        encoded = canonical(receipt).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        raise AttemptStoreError("Receipt is not bounded canonical data") from None
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise AttemptStoreError("Complete receipt exceeds its logical bound")
    return deepcopy(receipt)


def encode_item(key, revision, retention, data):
    raw = canonical(data).encode("utf-8")
    if len(raw) > MAX_LOGICAL_BYTES:
        raise AttemptStoreError("Complete attempt exceeds its logical bound")
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS, zdict=DICTIONARY)
    packed = MAGIC + len(raw).to_bytes(4, "big") + hashlib.sha256(raw).digest() + compressor.compress(raw) + compressor.flush()
    item = {**key, "revision": {"N": str(revision)}, "expireAt": {"N": str(retention)}, "payload": {"B": packed}}
    if flat_item_size(item) > MAX_ITEM_BYTES:
        raise AttemptStoreError("Complete lossless receipt does not fit the one-KiB item; no fields were dropped")
    return item


def decode_item(item, key, retention):
    try:
        if (not isinstance(item, dict) or set(item) != {"PK", "SK", "revision", "expireAt", "payload"}
                or item["PK"] != key["PK"] or item["SK"] != key["SK"]
                or item["expireAt"] != {"N": str(retention)} or flat_item_size(item) > MAX_ITEM_BYTES
                or not isinstance(item["payload"], dict) or set(item["payload"]) != {"B"}):
            raise ValueError()
        _number(item["revision"], minimum=1)
        packed = item["payload"]["B"]
        if not isinstance(packed, bytes) or len(packed) < 40 or packed[:3] != MAGIC:
            raise ValueError()
        length = int.from_bytes(packed[3:7], "big")
        if not 0 < length <= MAX_LOGICAL_BYTES:
            raise ValueError()
        decoder = zlib.decompressobj(zdict=DICTIONARY)
        raw = decoder.decompress(packed[39:], MAX_LOGICAL_BYTES + 1)
        if (len(raw) != length or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data
                or hashlib.sha256(raw).digest() != packed[7:39]):
            raise ValueError()
        data = strict_json(raw.decode("utf-8"), max_bytes=MAX_LOGICAL_BYTES)
        if canonical(data).encode() != raw:
            raise ValueError()
        return data
    except (ValueError, TypeError, KeyError, UnicodeError, zlib.error, OverflowError):
        raise AttemptStoreError("Stored attempt failed bounded integrity checks") from None


class SourceBusy(Exception):
    def __init__(self, owner):
        self.owner = owner


class NebiusAttemptQuota(DynamoQuotaStore):
    """One control CAS for admissions, fixed-source locks and attempt transitions."""
    def __init__(self, client, *, table_name, policy, mode, clock_ms, allow_fresh_namespace=False,
                 remaining_seconds=None):
        _binding_policy(policy, mode)
        if allow_fresh_namespace is not False or remaining_seconds is not None and not callable(remaining_seconds):
            raise ValueError("Runtime initialization is refused; bind only an optional trusted deadline")
        super().__init__(client, table_name=table_name, policy=policy, clock_ms=clock_ms)
        self.mode, self.remaining_seconds = mode, remaining_seconds
        self.layout = digest({"schema": "nebius-attempts-v4", "sources": SOURCES, "mode": mode, "codec": CODEC})

    def require_budget(self, seconds):
        if self.remaining_seconds is not None:
            try:
                value = self.remaining_seconds()
                if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 25 or value < seconds:
                    raise ValueError()
            except Exception:
                raise AttemptStoreError("Insufficient or invalid trusted invocation time; no new operation may start") from None

    @staticmethod
    def _bounded(item):
        if flat_item_size(item) > MAX_ITEM_BYTES:
            raise ValueError("Actual flat item exceeds one KiB")

    def _read(self, sk, control=False):
        if not control:
            return super()._read(sk, control=False)
        try:
            response = self.client.get_item(TableName=self.table_name, Key=self._key(sk), ConsistentRead=True)
            if not isinstance(response, dict):
                raise ValueError()
            item = response.get("Item")
            if item is None:
                raise ValueError("Control history is absent")
            if (not isinstance(item, dict) or set(item) != CONTROL_FIELDS
                    or item["PK"] != {"S": "nebius"} or item["SK"] != {"S": CONTROL_KEY}
                    or item["schema"] != {"S": "nebius-attempts-v4"}
                    or item["layout"] != {"S": self.layout} or item["mode"] != {"S": self.mode}
                    or item["expireAt"] != {"N": str(self.policy.retention_until)}):
                raise ValueError()
            for field in ("revision", "postsDay", "postsLifetime", "rawDay", "rawLifetime", "nextAllowedMs"):
                _number(item[field], minimum=1 if field == "revision" else 0)
            if not isinstance(item["day"], dict) or set(item["day"]) != {"S"} or date.fromisoformat(item["day"]["S"]).isoformat() != item["day"]["S"]:
                raise ValueError()
            mask = _number(item["occupied"], maximum=7)
            count = _number(item["attemptCount"], maximum=MAX_ATTEMPTS)
            if count < mask.bit_count():
                raise ValueError()
            if not isinstance(item["locks"], dict) or set(item["locks"]) != {"B"} or not isinstance(item["locks"]["B"], bytes) or len(item["locks"]["B"]) != 96:
                raise ValueError()
            for index in range(3):
                locked = item["locks"]["B"][index * 32:(index + 1) * 32]
                if bool(mask & (1 << index)) != (locked != b"\0" * 32):
                    raise ValueError()
            self._bounded(item)
            return item
        except Exception:
            raise QuotaError("quota_unavailable", "V4 control could not be verified; no reset or migration is allowed.") from None

    def _base_control(self, previous, start, day):
        if previous is None:
            raise QuotaError("namespace_unverified", "Existing valid control history is required; runtime initialization is forbidden.")
        control = super()._base_control(previous, start, day)
        control.update({"schema": {"S": "nebius-attempts-v4"}, "layout": {"S": self.layout}, "mode": {"S": self.mode},
                        "occupied": deepcopy(previous["occupied"]) if previous else {"N": "0"},
                        "locks": deepcopy(previous["locks"]) if previous else {"B": b"\0" * 96},
                        "attemptCount": deepcopy(previous["attemptCount"]) if previous else {"N": "0"}})
        self._bounded(control)
        return control

    def snapshot(self):
        self._time()
        return self._read(CONTROL_KEY, control=True)

    def transition(self, item, previous_attempt, *, index, owner_hash, previous_control, uncertain=False, waiter):
        if (type(index) is not int or not 0 <= index < 3 or not re.fullmatch(r"[0-9a-f]{64}", owner_hash)
                or not callable(waiter) or item.get("PK") != {"S": "nebius"}
                or item.get("SK") != {"S": "attempt#v4#" + owner_hash}
                or item.get("expireAt") != {"N": str(self.policy.retention_until)}):
            raise AttemptStoreError("Invalid bounded attempt transition")
        self._bounded(item)
        finishing = previous_attempt is not None
        self.require_budget((self.policy.pacing_ms / 1000 + 1) if finishing else
                            (TIMEOUT_SECONDS + 2 * self.policy.pacing_ms / 1000 + 1))
        if previous_attempt is not None:
            self._bounded(previous_attempt)
        start, day = self._time()
        previous = previous_control
        if previous is not None and start < int(previous["nextAllowedMs"]["N"]):
            delay = int(previous["nextAllowedMs"]["N"]) - start
            if not 0 < delay <= 3000:
                raise AttemptStoreError("Attempt mutation is paced; no write started")
            waiter(delay / 1000)
            end, day = self._time()
            if end < start or end - start > 3000:
                raise AttemptStoreError("Bounded pre-transaction wait failed; no write started")
            start = end
            previous = self._read(CONTROL_KEY, control=True)
        self.require_budget(1 if finishing else TIMEOUT_SECONDS + self.policy.pacing_ms / 1000 + 1)
        control = self._base_control(previous, start, day)
        mask = int(control["occupied"]["N"])
        locks = bytearray(control["locks"]["B"])
        owner = bytes.fromhex(owner_hash)
        actual_owner = bytes(locks[index * 32:(index + 1) * 32])
        if previous_attempt is None:
            if mask & (1 << index):
                raise SourceBusy(actual_owner.hex())
            if int(control["attemptCount"]["N"]) >= MAX_ATTEMPTS:
                return False
            control["attemptCount"] = {"N": str(int(control["attemptCount"]["N"]) + 1)}
            mask |= 1 << index
            locks[index * 32:(index + 1) * 32] = owner
        else:
            if not mask & (1 << index) or actual_owner != owner:
                raise AttemptStoreError("Pending source lock ownership changed; no write started")
            if not uncertain:
                mask &= ~(1 << index)
                locks[index * 32:(index + 1) * 32] = b"\0" * 32
        control["occupied"], control["locks"] = {"N": str(mask)}, {"B": bytes(locks)}
        self._bounded(control)
        # Exactly two transactional Puts, including the real shared control CAS.
        self._commit([self._put(control, previous), self._put(item, previous_attempt)])
        self._completed_in_time(start)
        return True


class DynamoAttemptStore:
    def __init__(self, client, *, table_name, quota, waiter):
        if (not isinstance(quota, NebiusAttemptQuota) or quota.client is not client
                or quota.table_name != table_name or not callable(waiter)):
            raise ValueError("Bind the same raw client/table/v4 quota and explicit bounded waiter")
        self.client, self.table_name, self.quota, self.waiter = client, table_name, quota, waiter

    def _key(self, owner_hash):
        return {"PK": {"S": "nebius"}, "SK": {"S": "attempt#v4#" + owner_hash}}

    def _read(self, owner_hash):
        self.quota._time()
        key = self._key(owner_hash)
        response = self.client.get_item(TableName=self.table_name, Key=key, ConsistentRead=True)
        if not isinstance(response, dict):
            raise AttemptStoreError("Attempt read unavailable")
        item = response.get("Item")
        if item is None:
            return None, None
        data = decode_item(item, key, self.quota.policy.retention_until)
        if (not isinstance(data, dict) or set(data) != {"request_id", "source_key", "state", "receipt"}
                or request_hash(data["request_id"]) != owner_hash
                or data["state"] not in {"pending", "complete"}):
            raise AttemptStoreError("Attempt identity or state changed")
        source_index(data["source_key"], self.quota.mode)
        if data["state"] == "pending" and (data["receipt"] is not None or item["revision"] != {"N": "1"}):
            raise AttemptStoreError("Pending attempt changed")
        if data["state"] == "complete":
            if item["revision"] != {"N": "2"}:
                raise AttemptStoreError("Completed attempt revision changed")
            receipt_checked(data["receipt"], data["request_id"], data["source_key"], self.quota.mode)
        return item, data

    def _owner(self, control, index):
        if control is None or not int(control["occupied"]["N"]) & (1 << index):
            return None
        owner = control["locks"]["B"][index * 32:(index + 1) * 32].hex()
        _, data = self._read(owner)
        if data is None or source_index(data["source_key"], self.quota.mode) != index:
            raise AttemptStoreError("Source lock has no matching attempt; no action is allowed")
        if data["state"] == "complete" and data["receipt"]["proposal"]["outcome"] != "request_uncertain":
            raise AttemptStoreError("Source lock and completed receipt disagree")
        return data["request_id"]

    @staticmethod
    def _owns(control, index, owner_hash):
        return (control is not None and bool(int(control["occupied"]["N"]) & (1 << index))
                and control["locks"]["B"][index * 32:(index + 1) * 32].hex() == owner_hash)

    def claim(self, request_id, source_key):
        try:
            owner_hash, index = request_hash(request_id), source_index(source_key, self.quota.mode)
            item, data = self._read(owner_hash)
            control = self.quota.snapshot()
            if data is not None:
                if control is None:
                    raise AttemptStoreError("Attempt exists without its control barrier")
                if data["source_key"] != source_key:
                    return "conflict", None
                if data["state"] == "complete":
                    if data["receipt"]["proposal"]["outcome"] == "request_uncertain" and not self._owns(control, index, owner_hash):
                        raise AttemptStoreError("Uncertain attempt lost its source barrier")
                    return "complete", deepcopy(data["receipt"])
                if not self._owns(control, index, owner_hash):
                    raise AttemptStoreError("Pending attempt lost its source barrier")
                return "pending", None
            locked = self._owner(control, index)
            if locked is not None:
                return "source_pending", locked
            pending = {"request_id": request_id, "source_key": source_key, "state": "pending", "receipt": None}
            new = encode_item(self._key(owner_hash), 1, self.quota.policy.retention_until, pending)
            try:
                claimed = self.quota.transition(new, None, index=index, owner_hash=owner_hash,
                                                previous_control=control, waiter=self.waiter)
            except SourceBusy as busy:
                # A definite competing owner was observed before any mutation;
                # read it once. Never retry a transaction or restore permission.
                _, other = self._read(busy.owner)
                if (other is None or source_index(other["source_key"], self.quota.mode) != index
                        or other["state"] == "complete" and other["receipt"]["proposal"]["outcome"] != "request_uncertain"):
                    raise AttemptStoreError("Competing source barrier unavailable")
                return "source_pending", other["request_id"]
            return ("claimed", None) if claimed else ("capacity", None)
        except AttemptStoreError:
            raise
        except Exception:
            raise AttemptStoreError("Durable attempt claim unavailable or uncertain; no new attempt is allowed") from None

    def finish(self, request_id, source_key, receipt):
        try:
            owner_hash, index = request_hash(request_id), source_index(source_key, self.quota.mode)
            receipt = receipt_checked(receipt, request_id, source_key, self.quota.mode)
            item, data = self._read(owner_hash)
            control = self.quota.snapshot()
            if data is None or control is None or data["source_key"] != source_key:
                raise AttemptStoreError("Attempt reservation unavailable; no completion write allowed")
            if data["state"] == "complete":
                if data["receipt"] != receipt:
                    raise AttemptStoreError("Completed receipt changed; no replacement allowed")
                if receipt["proposal"]["outcome"] == "request_uncertain" and not self._owns(control, index, owner_hash):
                    raise AttemptStoreError("Uncertain completion lost its source barrier")
                return  # Read-only exact idempotent completion, no blind write retry.
            if not self._owns(control, index, owner_hash):
                raise AttemptStoreError("Pending source lock ownership changed")
            completed = {**data, "state": "complete", "receipt": receipt}
            new = encode_item(self._key(owner_hash), 2, self.quota.policy.retention_until, completed)
            self.quota.transition(new, item, index=index, owner_hash=owner_hash,
                                  previous_control=control,
                                  uncertain=receipt["proposal"]["outcome"] == "request_uncertain",
                                  waiter=self.waiter)
        except AttemptStoreError:
            raise
        except Exception:
            raise AttemptStoreError("Durable completion unavailable or uncertain; inspect the original attempt before retrying") from None
