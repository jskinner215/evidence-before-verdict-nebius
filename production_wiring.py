"""Private Nebius entry composition; import performs no cloud or secret work.

This module never constructs an SDK client, discovers credentials, initializes
control history, or enables the exported handler. Explicit trusted deployment
code must supply its already-reviewed dependencies and call start().
"""
from concurrent.futures import TimeoutError as FutureTimeout
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
import hashlib
import importlib.metadata
import math
from pathlib import Path
import re
import sys
import threading
import time

from attempt_binding import AsyncProposalRunner, BindingRefusal
from cloud_attempts import DynamoAttemptStore, NebiusAttemptQuota
from edge_base import EdgeConfig, EdgeError, NebiusDomain
from global_quota_v2 import QuotaPolicy, flat_item_size
from nebius_composition import NebiusComposition, _INVOCATION
from nebius_host import PersistentAsyncHost, HostRefusal, HostTimeout
from proposal_service import ProposalService, validate_packet
from triage import InputError
import proposal_service
import triage


class WiringRefusal(RuntimeError):
    pass


_SCOPE = ContextVar("nebius_production_invocation", default=None)
RUNTIME_FILES = frozenset({"production_wiring.py", "nebius_host.py", "attempt_binding.py", "cloud_attempts.py",
    "edge_base.py", "global_quota_v2.py", "nebius_adapter.py", "nebius_composition.py", "nebius_http.py",
    "proposal_service.py", "triage.py", "index.html", "SDK_CLOSURE.json"})


def source_revision():
    """Canonical source/UI/SDK-closure revision, independent of test evidence."""
    import json
    root = Path(__file__).resolve().parent
    files = json.loads((root / "INPUT_MANIFEST.json").read_bytes())["files"]
    if not RUNTIME_FILES <= files.keys() or any(not re.fullmatch(r"[0-9a-f]{64}", files[name]) for name in RUNTIME_FILES):
        raise WiringRefusal("Frozen runtime source manifest is incomplete.")
    value = {"schema": "nebius-production-source-v1", "files": {name: files[name] for name in sorted(RUNTIME_FILES)}}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_source_origins():
    """Reject foreign preloaded bare modules before starting any lifecycle.

    The outer release manifest must pin INPUT_MANIFEST.json itself and bind the
    deployed archive revision to EdgeConfig; no public caller supplies pins.
    """
    root = Path(__file__).resolve().parent
    import json
    data = json.loads((root / "INPUT_MANIFEST.json").read_bytes())
    for name in RUNTIME_FILES:
        path, expected = root / name, data["files"][name]
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise WiringRefusal("Local production source differs from its frozen input manifest.")
        if name.endswith(".py"):
            module = sys.modules.get(path.stem)
            if module is not None and Path(getattr(module, "__file__", "")).resolve() != path:
                raise WiringRefusal("A foreign preloaded bare module was found.")
    return True


class InvocationScope:
    """One response boundary, shared explicitly by loop and SDK worker.

    Revocation prevents a new I/O start, not cancellation of an in-flight remote
    request. A monotonic ceiling remains effective if a supplied context stalls.
    """
    def __init__(self, context):
        self.context = context
        self.revoked = threading.Event()
        self.deadline = time.monotonic() + self._observed()

    def _observed(self):
        method = getattr(self.context, "get_remaining_time_in_millis", None)
        if not callable(method):
            raise WiringRefusal("A trusted invocation deadline is required.")
        try:
            value = method()
        except Exception:
            raise WiringRefusal("Invocation time is unavailable.") from None
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise WiringRefusal("Invocation time is invalid.")
        return min(25.0, value / 1000)

    def remaining(self, minimum=0):
        if self.revoked.is_set():
            raise WiringRefusal("Invocation is closed; no new I/O may start.")
        left = min(self._observed(), self.deadline - time.monotonic())
        if left <= 0 or left < minimum:
            raise WiringRefusal("Invocation cannot cover this phase; inspect prior state.")
        return left


def current_scope():
    scope = _SCOPE.get()
    if type(scope) is not InvocationScope:
        raise WiringRefusal("Use the owned invocation entry.")
    scope.remaining()
    return scope


@dataclass(frozen=True)
class SdkClosure:
    """Exact file/version closure supplied by trusted release preparation.

    Pins are matched to installed distribution RECORD files, with no install or
    download. Only a complete independently qualified closure is acceptable.
    The expected distributions include SDK serialization/endpoint dependencies.
    """
    versions: tuple
    files: tuple


def verify_sdk_client(client, closure):
    if type(closure) is not SdkClosure:
        raise WiringRefusal("An explicit reviewed SDK closure is required.")
    versions = dict(closure.versions)
    if (sys.platform != "linux" or len(versions) != len(closure.versions)
            or versions != {"boto3": "1.42.97", "botocore": "1.42.97", "urllib3": "2.8.0", "jmespath": "1.0.1", "python-dateutil": "2.9.0.post0", "six": "1.17.0", "s3transfer": "0.16.0"}):
        raise WiringRefusal("SDK dependency closure is incomplete.")
    if not closure.files:
        raise WiringRefusal("Exact SDK source files must be pinned.")
    observed = set()
    root = Path("/var/lang")
    installed = {}
    for name, expected in versions.items():
        if importlib.metadata.version(name) != expected:
            raise WiringRefusal("SDK dependency version differs from reviewed source.")
        dist = importlib.metadata.distribution(name)
        installed[name] = {}
        for item in dist.files or ():
            path = Path(dist.locate_file(item)).resolve()
            if path.is_relative_to(root) and path.is_file() and path.suffix != ".pyc":
                installed[name][str(path.relative_to(root))] = path
        if not installed[name]:
            raise WiringRefusal("An SDK distribution has no in-bound pinned files.")
    for name, relative, expected in closure.files:
        if name not in versions or not isinstance(relative, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise WiringRefusal("Invalid SDK source closure.")
        entries = installed[name]
        key = relative.replace("\\", "/")
        if key not in entries or (name, key) in observed:
            raise WiringRefusal("SDK source origin is absent or duplicated.")
        actual = entries[key]
        if not actual.is_file() or hashlib.sha256(actual.read_bytes()).hexdigest() != expected:
            raise WiringRefusal("SDK source bytes differ from reviewed closure.")
        observed.add((name, key))
    if observed != {(name, relative) for name, files in installed.items() for relative in files}:
        raise WiringRefusal("Every non-bytecode installed SDK distribution file must match the reviewed closure.")
    package_dist = {"boto3": "boto3", "botocore": "botocore", "urllib3": "urllib3",
                    "jmespath": "jmespath", "dateutil": "python-dateutil", "six": "six", "s3transfer": "s3transfer"}
    for name, module in tuple(sys.modules.items()):
        distribution_name = package_dist.get(name.split(".", 1)[0])
        if distribution_name is None or module is None:
            continue
        origin = getattr(module, "__file__", None)
        # six synthetic namespace packages deliberately have no __file__.
        if name.startswith("six.moves") and origin is None:
            continue
        if not origin or Path(origin).resolve() not in installed[distribution_name].values():
            raise WiringRefusal("A loaded SDK module has a foreign origin.")
    if type(client).__module__ != "botocore.client" or type(client).__name__ != "DynamoDB":
        raise WiringRefusal("Use the reviewed low-level DynamoDB SDK client.")
    meta = client.meta
    cfg = meta.config
    if (meta.service_model.service_name != "dynamodb" or meta.region_name != "us-east-2"
            or meta.endpoint_url != "https://dynamodb.us-east-2.amazonaws.com"
            or cfg.region_name != "us-east-2" or cfg.retries != {"total_max_attempts": 1, "mode": "standard"}
            or cfg.max_pool_connections != 1 or cfg.proxies != {}
            # Botocore 1.42.97 normalizes explicit False to None when an exact
            # endpoint_url is supplied. Both mean no variant request here; True
            # remains refused, and endpoint/region are checked independently.
            or (cfg.use_dualstack_endpoint is not False and cfg.use_dualstack_endpoint is not None)
            or (cfg.use_fips_endpoint is not False and cfg.use_fips_endpoint is not None)
            or any(type(value) not in (float, int) or not math.isfinite(value) or not 0 < value <= .1
                   for value in (cfg.connect_timeout, cfg.read_timeout))):
        raise WiringRefusal("Effective SDK retry, endpoint, proxy or timeout scope differs.")
    if not all(callable(getattr(client, name, None)) for name in ("get_item", "transact_write_items")):
        raise WiringRefusal("Use only bounded low-level read and transaction methods.")
    return True


class GuardedDynamo:
    """No queued SDK I/O; timed-out work remains retained and poisons admission.

    The host's one retained executor is shared with DNS. Socket timeouts are not
    a wall-clock cancellation guarantee. SDK result wait is at most 250ms plus
    at most 50ms local registry cleanup. True uncertainty is fenced; no
    replacement host/worker is created here.
    """
    def __init__(self, raw_client, host, *, table_name):
        if not isinstance(table_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name):
            raise WiringRefusal("One explicit bounded table is required.")
        self.raw, self.host, self.table_name = raw_client, host, table_name
        self._busy = threading.Lock()
        self._poisoned = False
        self._future = None
        self._last_result_known = False
        self._cleanup_pending = False

    def status(self):
        registry_pending = bool(self._future and self.host._executor and self.host._executor.pending)
        return {"poisoned": self._poisoned, "pending_sdk": bool(self._future and not self._future.done()),
                "last_result_known": self._last_result_known,
                "cleanup_pending": self._cleanup_pending and registry_pending}

    def _run(self, method, kwargs):
        scope = current_scope()
        scope.remaining(.35)
        if self._poisoned or self.host._poisoned or self.host._closing:
            raise WiringRefusal("SDK history is uncertain or closing; no replacement I/O.")
        if self._cleanup_pending:
            if not self.host._executor.wait_idle(0):
                raise WiringRefusal("The prior SDK result is known but local cleanup is still draining; no new job queued.")
            self._cleanup_pending = False
        if not self._busy.acquire(blocking=False):
            raise WiringRefusal("SDK worker is occupied; no request queued.")
        try:
            if method == "get_item":
                if set(kwargs) != {"TableName", "Key", "ConsistentRead"} or kwargs["TableName"] != self.table_name or kwargs["ConsistentRead"] is not True:
                    raise WiringRefusal("Only strongly consistent reads of the bound table are allowed.")
                self._key(kwargs["Key"])
            elif method == "transact_write_items":
                if set(kwargs) != {"TransactItems"} or not isinstance(kwargs["TransactItems"], list) or len(kwargs["TransactItems"]) != 2:
                    raise WiringRefusal("Exactly one bounded two-item transaction is required.")
                if any(set(op) != {"Put"} or op["Put"].get("TableName") != self.table_name for op in kwargs["TransactItems"]):
                    raise WiringRefusal("Only conditional Puts in the bound table are allowed.")
                keys = []
                for op in kwargs["TransactItems"]:
                    put = op["Put"]
                    self._key({"PK": put.get("Item", {}).get("PK"), "SK": put.get("Item", {}).get("SK")})
                    if flat_item_size(put["Item"]) > 1024 or put.get("ConditionExpression") not in {"attribute_not_exists(PK)", "#revision = :revision"}:
                        raise WiringRefusal("A bounded conditional item write is required.")
                    if put["Item"]["SK"]["S"] == "quota#v2#control":
                        # Exact existing DynamoQuotaStore._put CAS contract.
                        # The final SDK fence must never create a control row.
                        values = put.get("ExpressionAttributeValues")
                        if (put.get("ConditionExpression") != "#revision = :revision"
                                or put.get("ExpressionAttributeNames") != {"#revision": "revision"}
                                or not isinstance(values, dict) or set(values) != {":revision"}
                                or not isinstance(values[":revision"], dict) or set(values[":revision"]) != {"N"}
                                or not isinstance(values[":revision"]["N"], str)
                                or not re.fullmatch(r"[1-9][0-9]{0,12}", values[":revision"]["N"])):
                            raise WiringRefusal("The control row requires the exact existing revision CAS; runtime creation is forbidden.")
                    keys.append(put["Item"]["SK"]["S"])
                if keys.count("quota#v2#control") != 1 or len(set(keys)) != 2:
                    raise WiringRefusal("One control CAS and one identity row are required.")
            else:
                raise WiringRefusal("Unsupported SDK operation.")
            captured = copy_context()
            def perform():
                # Revocation is checked inside the worker immediately before I/O.
                current_scope().remaining(.1)
                result = getattr(self.raw, method)(**kwargs)
                current_scope().remaining()
                return result
            self._future = self.host._executor.submit(captured.run, perform)
            self._last_result_known = False
            deadline = time.monotonic() + min(.25, scope.remaining())
            try:
                answer = self._future.result(timeout=max(0, deadline - time.monotonic()))
            except FutureTimeout:
                self._poisoned = True
                self.host._poisoned = True
                scope.revoked.set()
                raise WiringRefusal("SDK completion is uncertain; retained work forbids replacement.") from None
            # A returned SDK result is already known. Future notification can
            # precede executor-registry retirement; do not mislabel that as an
            # unknown remote completion or permanently poison the runtime.
            self._last_result_known = True
            self._cleanup_pending = not self.host._executor.wait_idle(0)
            scope.remaining(.05)
            if not self.host._executor.wait_idle(.05):
                self._cleanup_pending = True
                raise WiringRefusal("SDK result is known but local executor cleanup is still draining; no new job queued.")
            self._cleanup_pending = False
            scope.remaining()
            return answer
        finally:
            self._busy.release()

    def get_item(self, **kwargs):
        return self._run("get_item", kwargs)

    def transact_write_items(self, **kwargs):
        return self._run("transact_write_items", kwargs)

    @staticmethod
    def _key(value):
        if (not isinstance(value, dict) or set(value) != {"PK", "SK"}
                or value["PK"] != {"S": "nebius"} or not isinstance(value["SK"], dict)
                or set(value["SK"]) != {"S"} or not isinstance(value["SK"]["S"], str)
                or not re.fullmatch(r"quota#v2#control|(?:quota#v2#request#|attempt#v4#)[0-9a-f]{64}", value["SK"]["S"])):
            raise WiringRefusal("SDK item scope is outside the bound Nebius namespace.")


class PersistentDomain(NebiusDomain):
    def __init__(self, runtime):
        super().__init__(triage, proposal_service)
        self.runtime = runtime

    def get(self, path):
        if path == "/api/provider":
            result = ProposalService.describe("configured_unverified")
            result["proposal_available"] = self.runtime.enabled and self.runtime.ready()
            return result
        return super().get(path)

    def preflight(self, path, packet):
        if path != "/api/propose":
            return
        try:
            validate_packet(packet)
            self.runtime.preflight()
        except InputError:
            raise EdgeError("invalid_source", "Invalid or stale authored source.", 409) from None
        except Exception:
            raise EdgeError("binding_unavailable", "Private provider binding is disabled, uncertain or unready. No new allowance was reserved.", 503) from None

    def use_provider(self, path):
        return path == "/api/propose"

    def post_with_permit(self, path, packet, permit):
        if path != "/api/propose":
            return super().post(path, packet)
        scope = current_scope()
        scope.remaining(20)
        async def invoke():
            # Explicit context handoff; copied thread-local context is not enough
            # evidence of the correct invocation identity.
            st = _SCOPE.set(scope)
            it = _INVOCATION.set(scope.context)
            try:
                return await self.runtime.runner.propose(packet, permit=permit, action_fingerprint=permit.fingerprint)
            finally:
                _INVOCATION.reset(it)
                _SCOPE.reset(st)
        try:
            return self.runtime.host.run(invoke, timeout_seconds=min(24, scope.remaining() - 1))
        except (HostRefusal, HostTimeout, BindingRefusal):
            raise EdgeError("attempt_uncertain", "Inspect the original durable attempt; no automatic retry occurred.", 503) from None


class ProductionRuntime:
    def __init__(self, config, *, index_html, signing_key, client, table_name,
                 policy, clock_ms, waiter, api_key, sdk_closure, enabled=False,
                 session_factory=None, random_bytes=None):
        if (type(config) is not EdgeConfig or config.app_id != "nebius"
                or config.source_revision != source_revision()
                or type(policy) is not QuotaPolicy or policy.expires_at != config.expires_at
                or policy.app_id != "nebius" or type(enabled) is not bool
                or type(signing_key) is not bytes or len(signing_key) != 32
                or not callable(clock_ms) or not callable(waiter)):
            raise WiringRefusal("Exact reviewed edge, policy, keys and dependencies are required.")
        # Source/SDK verification is local only. No client is created or called.
        verify_source_origins()
        verify_sdk_client(client, sdk_closure)
        self.enabled, self._started = enabled, False
        self.host = PersistentAsyncHost()
        self.sdk = GuardedDynamo(client, self.host, table_name=table_name)
        self.quota = NebiusAttemptQuota(self.sdk, table_name=table_name, policy=policy,
            mode="configured_unverified", clock_ms=clock_ms,
            remaining_seconds=lambda: current_scope().remaining())
        def bounded_wait(seconds):
            scope = current_scope()
            if type(seconds) not in (int, float) or not 0 < seconds <= 3:
                raise WiringRefusal("Only one bounded pacing wait is allowed.")
            scope.remaining(seconds + .3)
            waiter(seconds)
            scope.remaining(.3)
        self.store = DynamoAttemptStore(self.sdk, table_name=table_name, quota=self.quota, waiter=bounded_wait)
        self.runner = AsyncProposalRunner(attempt_store=self.store, api_key=api_key,
            admission_check=self._admitted, enabled=enabled, session_factory=session_factory)
        self.domain = PersistentDomain(self)
        options = {} if random_bytes is None else {"random_bytes": random_bytes}
        self.edge = NebiusComposition(config, index_html=index_html, signing_key=signing_key,
            domain=self.domain, quota=self.quota, clock=lambda: clock_ms() / 1000, **options)
        self.edge.require_cloud_deadline = True
        self._entry_lock = threading.Lock()

    def start(self):
        with _INSTALL_LOCK:
            if self._started or _INSTALL_CLOSED:
                raise WiringRefusal("Runtime cannot start after a terminal close or restart.")
            self.host.start()
            self._started = True
        return self

    def ready(self):
        return (self._started and not self.host._closing and not self.host._poisoned
                and self.host._thread is not None and self.host._thread.is_alive()
                and not self.sdk.status()["poisoned"] and not self.sdk.status()["pending_sdk"]
                and not self.sdk.status()["cleanup_pending"])

    def _admitted(self):
        if not self.enabled or not self.ready():
            return False
        current_scope().remaining(18)
        return True

    def preflight(self):
        current_scope().remaining(21)
        self.runner.preflight()  # header-safe key/disabled/guard BEFORE reserve
        self.quota.policy.live_limits()
        self.quota.snapshot()  # existing v4 history only, no initialize/reset

    def __call__(self, event, context=None):
        # GET renders metadata without SDK operations or required AWS context.
        request_context = event.get("requestContext") if isinstance(event, dict) else None
        http = request_context.get("http") if isinstance(request_context, dict) else None
        method = http.get("method") if isinstance(http, dict) else None
        if method == "GET":
            return self.edge(event, context)
        if not self._entry_lock.acquire(blocking=False):
            return self.edge._response(503, {"error": {"code": "entry_busy", "message": "Another request is active; no operation was queued."}})
        scope = None
        st = it = None
        try:
            scope = InvocationScope(context)
            st, it = _SCOPE.set(scope), _INVOCATION.set(context)
            return self.edge(event, context)
        except Exception:
            return self.edge._response(503, {"error": {"code": "entry_unavailable", "message": "Inspect prior state; no automatic retry is available."}})
        finally:
            if scope is not None:
                scope.revoked.set()
            if it is not None:
                _INVOCATION.reset(it)
            if st is not None:
                _SCOPE.reset(st)
            self._entry_lock.release()

    def close(self):
        self.enabled = False
        return self.host.close(timeout_seconds=.5)


_INSTALL_LOCK = threading.Lock()
_INSTALL_ATTEMPTED = False
_INSTALLED = None
_INSTALL_CLOSED = False


def configure_production(runtime):
    """One trusted initialization attempt; never accepted from event/env input.

    Even a failed initialization consumes the installation latch. A draining or
    closed runtime cannot be replaced in this process to escape its fences.
    """
    global _INSTALL_ATTEMPTED, _INSTALLED
    with _INSTALL_LOCK:
        if _INSTALL_ATTEMPTED or _INSTALL_CLOSED:
            raise WiringRefusal("Production installation cannot be repeated or replaced.")
        _INSTALL_ATTEMPTED = True
        if type(runtime) is not ProductionRuntime or not runtime.ready():
            raise WiringRefusal("Install one already-started reviewed runtime.")
        verify_source_origins()
        _INSTALLED = runtime
    return True


def close_production():
    global _INSTALL_CLOSED
    with _INSTALL_LOCK:
        _INSTALL_CLOSED = True
        runtime = _INSTALLED
    return None if runtime is None else runtime.close()


def handler(event, context=None):
    """Same export stays closed until the trusted one-shot initializer runs."""
    with _INSTALL_LOCK:
        closed, runtime = _INSTALL_CLOSED, _INSTALLED
    if closed:
        draining = bool(runtime and (runtime.sdk.status()["pending_sdk"]
            or runtime.sdk.status()["cleanup_pending"]
            or (runtime.host._thread and runtime.host._thread.is_alive())))
        code = "production_binding_draining" if draining else "production_binding_closed"
        return {"statusCode": 503, "headers": {"cache-control": "no-store", "content-type": "application/json"},
                "body": '{"error":"' + code + '"}', "isBase64Encoded": False}
    if runtime is not None:
        return runtime(event, context)
    return {"statusCode": 503, "headers": {"cache-control": "no-store", "content-type": "application/json"},
            "body": '{"error":"production_binding_unconfigured"}', "isBase64Encoded": False}
