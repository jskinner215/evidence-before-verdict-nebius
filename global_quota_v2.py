"""Up-front, two-item DynamoDB reservation; no per-call or finish writes.

This module initializes no SDK, credentials or network. Its injected client and
the instrumented raw transport must have automatic retries disabled. A reserved
tombstone is a consumed budget, never a provider result or execution receipt.
"""
from dataclasses import dataclass
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import hashlib
import inspect
import json
import re
import threading
import time


MAX_ITEM_BYTES = 1024
CEILINGS = {"qloo": (300, 2500), "nebius": (60, 1000)}


class QuotaError(Exception):
    def __init__(self, code, message, status=503):
        super().__init__(message)
        self.code, self.status = code, status


def _integer(value, name, minimum=1, maximum=9999999999):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(name + " must be a bounded integer")
    return value


def _fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise QuotaError("invalid_request", "A SHA256 action fingerprint is required.", 400)
    return value


def _request_hash(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 256 or not value.isascii() or any(not 33 <= ord(c) <= 126 for c in value):
        raise QuotaError("invalid_request", "A bounded opaque request ID is required.", 400)
    return hashlib.sha256(value.encode()).hexdigest()


def flat_item_size(item):
    """Conservative billed-size upper bound for flat DynamoDB S/N/B items.

    Native Binary is counted before base64 wire encoding. Decimal ASCII length
    plus one conservatively bounds DynamoDB's packed number representation.
    Nested/other attribute types are outside this compact-state contract.
    """
    if not isinstance(item, dict) or not item:
        raise ValueError("An explicit flat attribute map is required")
    total = 0
    for name, attribute in item.items():
        if not isinstance(name, str) or not name or not isinstance(attribute, dict) or len(attribute) != 1:
            raise ValueError("Only named flat S/N/B attributes are supported")
        total += len(name.encode("utf-8"))
        kind, value = next(iter(attribute.items()))
        if kind == "S" and isinstance(value, str):
            total += len(value.encode("utf-8"))
        elif kind == "N" and isinstance(value, str) and re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[Ee][+-]?[0-9]+)?", value):
            total += len(value.encode("ascii")) + 1
        elif kind == "B" and isinstance(value, (bytes, bytearray)):
            total += len(value)
        else:
            raise ValueError("Only bounded flat S/N/B attributes are supported")
    return total


@dataclass(frozen=True)
class QuotaPolicy:
    app_id: str
    expires_at: int
    retention_until: int
    post_daily: int = 100
    post_lifetime: int = 2000
    provider_daily: int | None = None
    provider_lifetime: int | None = None
    max_raw_calls_per_request: int = 0
    raw_bound_verified: bool = False
    entitlement_daily: int | None = None
    entitlement_lifetime: int | None = None
    live_enabled: bool = False
    pacing_ms: int = 2000
    max_reservation_latency_ms: int = 250

    def __post_init__(self):
        if self.app_id not in CEILINGS or type(self.live_enabled) is not bool or type(self.raw_bound_verified) is not bool:
            raise ValueError("Exact known app and boolean enable/verification flags required")
        _integer(self.expires_at, "expires_at")
        _integer(self.retention_until, "retention_until")
        if self.retention_until <= self.expires_at:
            raise ValueError("Replay retention must outlive runtime expiry")
        for name, maximum in (("post_daily", 100), ("post_lifetime", 2000)):
            _integer(getattr(self, name), name, maximum=maximum)
        for name, maximum in zip(("provider_daily", "provider_lifetime"), CEILINGS[self.app_id]):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name, maximum=maximum)
        for name in ("entitlement_daily", "entitlement_lifetime"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name)
        _integer(self.max_raw_calls_per_request, "max_raw_calls_per_request", minimum=0, maximum=CEILINGS[self.app_id][0])
        _integer(self.pacing_ms, "pacing_ms", minimum=2000, maximum=60000)
        _integer(self.max_reservation_latency_ms, "max_reservation_latency_ms", maximum=250)

    def live_limits(self):
        if not self.live_enabled or not self.raw_bound_verified or self.max_raw_calls_per_request < 1 or any(v is None for v in (self.provider_daily, self.provider_lifetime, self.entitlement_daily, self.entitlement_lifetime)):
            raise QuotaError("provider_disabled", "Live calls require verified raw fanout and free allowance plus explicit enablement.")
        if self.app_id == "nebius" and self.max_raw_calls_per_request != 1:
            raise QuotaError("provider_disabled", "Nebius requires exactly one precharged raw provider attempt.")
        return min(self.provider_daily, self.entitlement_daily), min(self.provider_lifetime, self.entitlement_lifetime)


def _clock_now(clock):
    try:
        return _integer(clock(), "trusted server milliseconds", minimum=0, maximum=9999999999999)
    except Exception:
        raise QuotaError("invalid_time", "A valid trusted server clock is required.") from None


class RequestPermit:
    """Fresh in-process budget lease: not serializable, resumable or a receipt.

    All raw calls, including any resolution/hydration, must pass through these
    wrappers. Callbacks must issue one request and must not retry internally.
    Never expose the permit to a client or reconstruct one from a tombstone.
    """
    def __init__(self, *, app_id, fingerprint, raw_reserved, clock_ms, reserved_at_ms, expires_at_ms):
        self._app_id, self._fingerprint, self._raw_reserved = app_id, fingerprint, raw_reserved
        self._clock, self._last_time, self._expires = clock_ms, reserved_at_ms, expires_at_ms
        self._started, self._seen = 0, set()
        self._active, self._closed = False, False
        self._lock = threading.Lock()

    def __copy__(self):
        raise TypeError("A fresh request permit cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("A fresh request permit cannot be copied")

    def __reduce__(self):
        raise TypeError("A fresh request permit cannot be serialized")

    @property
    def app_id(self):
        return self._app_id

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def raw_reserved(self):
        return self._raw_reserved

    @property
    def calls_started(self):
        with self._lock:
            return self._started

    def close(self):
        with self._lock:
            self._closed = True

    def _begin(self, descriptor_hash):
        descriptor_hash = _fingerprint(descriptor_hash)
        with self._lock:
            if self._closed:
                raise QuotaError("permit_closed", "This lease is closed; it cannot be resumed.", 409)
            if self._active:
                raise QuotaError("provider_in_progress", "Only one raw call may run at a time.", 409)
            if descriptor_hash in self._seen:
                self._closed = True
                raise QuotaError("call_replay", "That exact raw call must not execute again.", 409)
            if self._started >= self.raw_reserved:
                self._closed = True
                raise QuotaError("provider_budget_exhausted", "No precharged raw-call slot remains.", 429)
            try:
                now = _clock_now(self._clock)
                if now < self._last_time or now >= self._expires:
                    raise QuotaError("permit_expired", "The current trusted clock no longer permits this call.", 410)
            except BaseException:
                self._closed = True
                raise
            self._last_time = now
            self._seen.add(descriptor_hash)
            self._started += 1  # Consume before entering possibly uncertain I/O.
            self._active = True

    def _end(self, uncertain):
        with self._lock:
            self._active = False
            if uncertain or self._started >= self.raw_reserved:
                self._closed = True

    def invoke_raw(self, descriptor_hash, callback):
        if not callable(callback):
            self.close()
            raise QuotaError("invalid_transport", "An instrumented single-call transport is required.", 400)
        self._begin(descriptor_hash)
        try:
            result = callback()
            if inspect.isawaitable(result) or inspect.isgenerator(result) or inspect.isasyncgen(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise ValueError("Use the async wrapper for awaited I/O")
        except BaseException as error:
            self._end(True)
            if not isinstance(error, Exception):
                raise
            raise QuotaError("provider_uncertain", "The raw call outcome is uncertain; this lease is closed.") from None
        self._end(False)
        return result

    async def invoke_raw_async(self, descriptor_hash, callback):
        if not callable(callback):
            self.close()
            raise QuotaError("invalid_transport", "An instrumented single-call transport is required.", 400)
        self._begin(descriptor_hash)
        try:
            result = await callback()
        except BaseException as error:
            self._end(True)
            if not isinstance(error, Exception):
                raise
            raise QuotaError("provider_uncertain", "The raw call outcome is uncertain; this lease is closed.") from None
        self._end(False)
        return result


class DynamoQuotaStore:
    def __init__(self, client, *, table_name, policy, clock_ms=None):
        if not isinstance(policy, QuotaPolicy) or client is None or not all(callable(getattr(client, name, None)) for name in ("get_item", "transact_write_items")):
            raise ValueError("Explicit policy and injected low-level client required")
        if not isinstance(table_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name):
            raise ValueError("An exact table name is required")
        if clock_ms is not None and not callable(clock_ms):
            raise ValueError("An explicit trusted clock must be callable")
        self.client, self.table_name, self.policy = client, table_name, policy
        self.clock = clock_ms if clock_ms is not None else lambda: time.time_ns() // 1000000

    def _key(self, sk):
        return {"PK": {"S": self.policy.app_id}, "SK": {"S": sk}}

    @staticmethod
    def _bounded(item):
        if len(json.dumps(item, separators=(",", ":"), ensure_ascii=True).encode()) > MAX_ITEM_BYTES:
            raise ValueError("Bounded quota metadata exceeded one KiB")

    def _read(self, sk, control=False):
        try:
            response = self.client.get_item(TableName=self.table_name, Key=self._key(sk), ConsistentRead=True)
            if not isinstance(response, dict):
                raise ValueError()
            item = response.get("Item")
            if item is None:
                return None
            fields = {"PK", "SK", "expireAt", "revision", "day", "postsDay", "postsLifetime", "rawDay", "rawLifetime", "nextAllowedMs"} if control else {"PK", "SK", "expireAt", "fingerprint", "reservedAtMs", "rawReserved", "state"}
            if not isinstance(item, dict) or set(item) != fields or item["PK"] != self._key(sk)["PK"] or item["SK"] != self._key(sk)["SK"] or item["expireAt"] != {"N": str(self.policy.retention_until)}:
                raise ValueError()
            numbers = ("revision", "postsDay", "postsLifetime", "rawDay", "rawLifetime", "nextAllowedMs") if control else ("reservedAtMs", "rawReserved")
            for name in numbers:
                if not isinstance(item[name], dict) or set(item[name]) != {"N"} or not re.fullmatch(r"0|[1-9][0-9]{0,12}", item[name]["N"]):
                    raise ValueError()
            if control:
                if int(item["revision"]["N"]) < 1 or not isinstance(item["day"], dict) or set(item["day"]) != {"S"}:
                    raise ValueError()
                if date.fromisoformat(item["day"]["S"]).isoformat() != item["day"]["S"]:
                    raise ValueError()
            else:
                if item["state"] != {"S": "reserved"} or not isinstance(item["fingerprint"], dict) or set(item["fingerprint"]) != {"S"}:
                    raise ValueError()
                _fingerprint(item["fingerprint"]["S"])
            self._bounded(item)
            return item
        except Exception:
            raise QuotaError("quota_unavailable", "Durable limits could not be verified; no action may start.") from None

    def _put(self, item, previous=None):
        self._bounded(item)
        put = {"TableName": self.table_name, "Item": item, "ConditionExpression": "attribute_not_exists(PK)"}
        if previous is not None:
            put.update(ConditionExpression="#revision = :revision", ExpressionAttributeNames={"#revision": "revision"}, ExpressionAttributeValues={":revision": previous["revision"]})
        return {"Put": put}

    def _commit(self, changes):
        try:
            self.client.transact_write_items(TransactItems=changes)
        except Exception as error:
            response = getattr(error, "response", None)
            if isinstance(response, dict):
                reasons = response.get("CancellationReasons")
                if response.get("Error", {}).get("Code") == "TransactionCanceledException" and isinstance(reasons, list) and any(isinstance(r, dict) and r.get("Code") == "ConditionalCheckFailed" for r in reasons) and all(isinstance(r, dict) and r.get("Code") in {"None", "ConditionalCheckFailed"} for r in reasons):
                    raise QuotaError("quota_conflict", "Another mutation won the control-row check; no retry occurred.", 409) from None
            raise QuotaError("quota_uncertain", "The transaction is uncertain; no action or retry is authorized.") from None

    def _time(self):
        start = _clock_now(self.clock)
        if start >= self.policy.expires_at * 1000:
            raise QuotaError("demo_expired", "This demo no longer accepts new actions.", 410)
        try:
            return start, datetime.fromtimestamp(start / 1000, timezone.utc).date().isoformat()
        except (OverflowError, OSError, ValueError):
            raise QuotaError("invalid_time", "A valid trusted server date is required.") from None

    def _base_control(self, previous, start, day):
        if previous is not None:
            if day < previous["day"]["S"]:
                raise QuotaError("clock_regressed", "The trusted clock regressed; no action may start.")
            if start < int(previous["nextAllowedMs"]["N"]):
                raise QuotaError("quota_paced", "This app is pacing mutations; no transaction started.", 429)
        same_day = previous is not None and previous["day"] == {"S": day}
        values = {name: int(previous[name]["N"]) if previous is not None and (same_day or name.endswith("Lifetime")) else 0 for name in ("postsDay", "postsLifetime", "rawDay", "rawLifetime")}
        return {**self._key("quota#v2#control"), "expireAt": {"N": str(self.policy.retention_until)}, "revision": {"N": str(1 if previous is None else int(previous["revision"]["N"]) + 1)}, "day": {"S": day}, "nextAllowedMs": {"N": str(start + self.policy.pacing_ms)}, **{name: {"N": str(value)} for name, value in values.items()}}

    def _completed_in_time(self, start):
        end = _clock_now(self.clock)
        if end < start or end - start > self.policy.max_reservation_latency_ms or end >= self.policy.expires_at * 1000:
            raise QuotaError("reservation_timing_unknown", "The mutation remains consumed; timing did not qualify further action.")
        return end

    def reserve(self, request_id, fingerprint, *, use_provider=False):
        sk, fingerprint = "quota#v2#request#" + _request_hash(request_id), _fingerprint(fingerprint)
        if type(use_provider) is not bool:
            raise QuotaError("invalid_request", "An exact internal provider-mode flag is required.", 400)
        raw = self.policy.max_raw_calls_per_request if use_provider else 0
        limits = self.policy.live_limits() if use_provider else (0, 0)
        start, day = self._time()
        old_request = self._read(sk)
        if old_request is not None:
            if old_request["fingerprint"] != {"S": fingerprint}:
                raise QuotaError("request_conflict", "This ID is bound to other action data.", 409)
            raise QuotaError("replay_reserved", "This ID already consumed its budget; it cannot resume or execute again.", 409)
        previous = self._read("quota#v2#control", control=True)
        control = self._base_control(previous, start, day)
        for name, amount, maximum in (("postsDay", 1, self.policy.post_daily), ("postsLifetime", 1, self.policy.post_lifetime), ("rawDay", raw, limits[0]), ("rawLifetime", raw, limits[1])):
            # A disconnected synthetic request never resets or authorizes raw calls.
            if amount and int(control[name]["N"]) + amount > maximum:
                raise QuotaError("quota_exhausted", "The verified allowance cannot cover this entire request.", 429)
            control[name] = {"N": str(int(control[name]["N"]) + amount)}
        tombstone = {**self._key(sk), "expireAt": {"N": str(self.policy.retention_until)}, "fingerprint": {"S": fingerprint}, "reservedAtMs": {"N": str(start)}, "rawReserved": {"N": str(raw)}, "state": {"S": "reserved"}}
        self._commit([self._put(control, previous), self._put(tombstone)])
        end = self._completed_in_time(start)
        next_midnight = datetime.fromtimestamp(start / 1000, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        lease_expiry = min(self.policy.expires_at * 1000, int(next_midnight.timestamp()) * 1000)
        return RequestPermit(app_id=self.policy.app_id, fingerprint=fingerprint, raw_reserved=raw, clock_ms=self.clock, reserved_at_ms=end, expires_at_ms=lease_expiry)

    def guarded_transact(self, writes, now_ms=None, *, waiter=None):
        """Pace <=2 compact Qloo confirmation mutations through the same control.

        A waiter is optional and can run once, before any transaction, for at
        most 3 seconds. It receives seconds. Neither a failed nor an uncertain
        transaction is retried. This is not a generic DynamoDB proxy.
        """
        try:
            if self.policy.app_id != "qloo" or not isinstance(writes, list) or not 1 <= len(writes) <= 2 or (waiter is not None and not callable(waiter)):
                raise ValueError()
            changes, keys = deepcopy(writes), set()
            for record in changes:
                if not isinstance(record, dict) or len(record) != 1:
                    raise ValueError()
                kind, op = next(iter(record.items()))
                if kind not in {"Put", "ConditionCheck"} or not isinstance(op, dict) or op.get("TableName") != self.table_name:
                    raise ValueError()
                item = op.get("Item" if kind == "Put" else "Key")
                if not isinstance(item, dict) or item.get("PK") != {"S": "qloo"} or not isinstance(item.get("SK"), dict) or set(item["SK"]) != {"S"}:
                    raise ValueError()
                sk = item["SK"]["S"]
                if not isinstance(sk, str) or not re.fullmatch(r"session#[0-9a-f]{64}|operation#[0-9a-f]{64}#(?:resolve|recommend)#[0-9a-f]{64}", sk) or sk in keys:
                    raise ValueError()
                keys.add(sk)
                if flat_item_size(item) > MAX_ITEM_BYTES:
                    raise ValueError()
                if kind == "Put" and item.get("expireAt") != {"N": str(self.policy.retention_until)}:
                    raise ValueError()
                if kind == "ConditionCheck" and set(item) != {"PK", "SK"}:
                    raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise QuotaError("invalid_mutation", "Only bounded, own-Qloo confirmation mutations may use this gate.", 400) from None
        start, day = self._time()
        if now_ms is not None and (type(now_ms) is not int or now_ms != start):
            raise QuotaError("invalid_time", "Use the guard's current trusted clock for a mutation.")
        previous = self._read("quota#v2#control", control=True)
        if previous is not None and start < int(previous["nextAllowedMs"]["N"]):
            wait_ms = int(previous["nextAllowedMs"]["N"]) - start
            if waiter is None or not 0 < wait_ms <= 3000:
                raise QuotaError("quota_paced", "This app is pacing mutations; no transaction started.", 429)
            try:
                waiter(wait_ms / 1000)
            except Exception:
                raise QuotaError("quota_paced", "The bounded pre-transaction wait did not complete; no transaction started.", 429) from None
            start, day = self._time()
            previous = self._read("quota#v2#control", control=True)
        control = self._base_control(previous, start, day)
        self._commit([self._put(control, previous)] + changes)
        self._completed_in_time(start)
