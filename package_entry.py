"""Immutable private Nebius package entry; default handler does no file/cloud I/O.

Trusted release code must pin this loader's bytes before import, then supply
the reviewed external lock hash and both revisions to configure_trusted().
Nothing here reads environment/credentials, constructs an SDK client, creates
control history, or infers provider/spending permission from a public request.
Python reflection and malicious trusted initialization are not sandboxed.
"""
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import threading


CORE_FILES = frozenset({"production_wiring.py", "nebius_host.py", "attempt_binding.py",
    "cloud_attempts.py", "edge_base.py", "global_quota_v2.py", "nebius_adapter.py",
    "nebius_composition.py", "nebius_http.py", "proposal_service.py", "triage.py",
    "index.html", "SDK_CLOSURE.json"})
HTTP_ROOTS = frozenset({"aiohappyeyeballs", "aiohttp", "aiosignal", "attr", "attrs",
    "frozenlist", "idna", "multidict", "propcache", "typing_extensions", "yarl"})
HTTP_VERSIONS = {"aiohappyeyeballs": "2.6.1", "aiohttp": "3.13.5", "aiosignal": "1.4.0",
    "attrs": "25.3.0", "frozenlist": "1.8.0", "idna": "3.10", "multidict": "6.7.1",
    "propcache": "0.4.1", "typing_extensions": "4.15.0", "yarl": "1.23.0"}
_LOCK = threading.Lock()
_ATTEMPTED = False
_CLOSED = False
_RUNTIME = None
_CORE = None
_CLOSE_REQUESTED = threading.Event()
_RETAINED_CANDIDATE = None
_LAST_CLOSE_STATUS = None


class PackageRefusal(RuntimeError):
    pass


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hex(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageRefusal("A release document contains duplicate fields.")
        result[key] = value
    return result


def _json(data, maximum=2_000_000):
    if not isinstance(data, bytes) or not 1 <= len(data) <= maximum:
        raise PackageRefusal("A bounded release document is required.")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(PackageRefusal("Nonfinite release data.")))
    except (UnicodeError, ValueError, TypeError):
        raise PackageRefusal("Release document is not strict JSON.") from None


def _name(value):
    if (not isinstance(value, str) or "\\" in value or ":" in value
            or value.startswith("/") or any(p in {"", ".", ".."} for p in value.split("/"))
            or PurePosixPath(value).is_absolute()):
        raise PackageRefusal("Unsafe release member name.")
    return value


def _file_digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            h.update(block)
    return h.hexdigest()


def _check_loaded_origins(root, files):
    """Reject foreign preloaded HTTP/core implementations, including extensions."""
    core_roots = {Path(p).stem for p in CORE_FILES if p.endswith(".py")}
    for name, module in tuple(sys.modules.items()):
        if module is None or name.split(".", 1)[0] not in HTTP_ROOTS | core_roots:
            continue
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise PackageRefusal("Loaded runtime module has no reviewed file origin.")
        try:
            relative = Path(origin).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            raise PackageRefusal("A loaded runtime module has a foreign origin.") from None
        if relative not in files or _file_digest(root / relative) != files[relative]["sha256"]:
            raise PackageRefusal("A loaded runtime implementation differs from the release.")


def _verify_release(root, *, expected_lock_sha256, expected_package_revision,
                    expected_production_revision, require_posix_modes=True):
    """Local-only integrity verification. Its root is fixed by the public caller."""
    if not all(_hex(v) for v in (expected_lock_sha256, expected_package_revision, expected_production_revision)):
        raise PackageRefusal("All externally reviewed release identities are required.")
    root = Path(root).resolve()
    lock_path = root / "PACKAGE_LOCK.json"
    if lock_path.is_symlink() or not lock_path.is_file() or lock_path.stat().st_size > 2_000_000:
        raise PackageRefusal("A regular bounded package lock is required.")
    raw = lock_path.read_bytes()
    if _digest(raw) != expected_lock_sha256:
        raise PackageRefusal("Package lock differs from the external reviewed hash.")
    lock = _json(raw)
    if (not isinstance(lock, dict) or lock.get("schema") != "nebius-production-package-v1"
            or lock.get("sourceRevision") != expected_package_revision
            or lock.get("productionSourceRevision") != expected_production_revision):
        raise PackageRefusal("Package or inner production revision differs.")
    files = lock.get("files")
    if (not isinstance(files, dict) or not 1 <= len(files) <= 1000
            or not CORE_FILES | {"INPUT_MANIFEST.json", "HTTP_DEPENDENCY_CLOSURE.json", "package_entry.py"} <= files.keys()
            or "PACKAGE_LOCK.json" in files):
        raise PackageRefusal("Complete runtime map is required; the lock cannot pin itself.")
    if len({str(n).casefold() for n in files}) != len(files):
        raise PackageRefusal("Case-ambiguous release names.")
    expected_names = set()
    for name, proof in files.items():
        _name(name)
        if (not isinstance(proof, dict) or set(proof) != {"sha256", "bytes", "mode"}
                or not _hex(proof["sha256"]) or type(proof["bytes"]) is not int
                or not 0 <= proof["bytes"] <= 64_000_000 or type(proof["mode"]) is not int
                or proof["mode"] not in {0o644, 0o755}):
            raise PackageRefusal("A bounded exact runtime file proof is required.")
        expected_names.add(name)
    if _digest(_canonical({"schema": "nebius-production-package-map-v1", "files": files})) != expected_package_revision:
        raise PackageRefusal("Canonical complete-package map revision differs.")
    actual_names = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PackageRefusal("Release symlinks are not permitted.")
        if path.is_dir():
            continue
        value = path.lstat()
        if not stat.S_ISREG(value.st_mode):
            raise PackageRefusal("Only regular release files are supported.")
        name = path.relative_to(root).as_posix()
        actual_names.add(name)
        if name == "PACKAGE_LOCK.json":
            if require_posix_modes and stat.S_IMODE(value.st_mode) != 0o644:
                raise PackageRefusal("Package lock permissions differ.")
            continue
        proof = files.get(name)
        if (proof is None or value.st_size != proof["bytes"]
                or (require_posix_modes and stat.S_IMODE(value.st_mode) != proof["mode"])
                or _file_digest(path) != proof["sha256"]):
            raise PackageRefusal("Runtime bytes, count or permissions differ from the release.")
    if actual_names != expected_names | {"PACKAGE_LOCK.json"}:
        raise PackageRefusal("Complete-package file set differs, including unexpected bytecode.")
    inner_files = {name: files[name]["sha256"] for name in sorted(CORE_FILES)}
    inner = _digest(_canonical({"schema": "nebius-production-source-v1", "files": inner_files}))
    source_input = _json((root / "INPUT_MANIFEST.json").read_bytes())
    if (inner != expected_production_revision or not isinstance(source_input, dict)
            or any(source_input.get("files", {}).get(name) != value for name, value in inner_files.items())):
        raise PackageRefusal("Inner source/UI/SDK revision or input source map differs.")
    deps = _json((root / "HTTP_DEPENDENCY_CLOSURE.json").read_bytes())
    dep_files = {name: proof for name, proof in files.items() if name.startswith("deps/")}
    if (not isinstance(deps, dict) or deps.get("schema") != "nebius-http-dependency-closure-v1"
            or deps.get("files") != dep_files or deps.get("versions") != HTTP_VERSIONS
            or not dep_files or lock.get("httpDependencyManifestSha256") != files["HTTP_DEPENDENCY_CLOSURE.json"]["sha256"]):
        raise PackageRefusal("HTTP dependency closure is incomplete or unbound.")
    _check_loaded_origins(root, files)
    return lock


def verify_release(*, expected_lock_sha256, expected_package_revision, expected_production_revision):
    if sys.platform != "linux":
        raise PackageRefusal("Trusted activation supports only the reviewed Linux package.")
    return _verify_release(Path(__file__).resolve().parent,
        expected_lock_sha256=expected_lock_sha256, expected_package_revision=expected_package_revision,
        expected_production_revision=expected_production_revision)


def _http_import_check(root, files):
    """Import pinned HTTP implementation locally; constructs no session or socket."""
    for name, expected in HTTP_VERSIONS.items():
        dist = importlib.metadata.distribution(name)
        if dist.version != expected or Path(dist.locate_file("")).resolve() != root / "deps":
            raise PackageRefusal("HTTP distribution version or installation origin differs.")
    for name in sorted(HTTP_ROOTS):
        importlib.import_module(name)
    _check_loaded_origins(root, files)


def _publish_runtime(core, runtime):
    """One ownership transfer, under _LOCK; close fence is checked afterward."""
    global _CORE, _RUNTIME
    _CORE, _RUNTIME = core, runtime


def configure_trusted(*, expected_lock_sha256, expected_package_revision,
        expected_production_revision, edge_config, quota_policy, signing_key,
        client, table_name, clock_ms, waiter, api_key, enabled=False,
        session_factory=None, random_bytes=None):
    """One initialization attempt, explicit dependencies; no secret/SDK factories.

    This is not callable via the public handler. Supplied client/key/config and
    permission/pricing evidence remain the operator's separate responsibility.
    A failure or close consumes this loader's latch; no replacement is attempted.
    """
    global _ATTEMPTED, _RUNTIME, _CORE, _RETAINED_CANDIDATE, _CLOSED, _LAST_CLOSE_STATUS
    with _LOCK:
        if _ATTEMPTED or _CLOSED or _CLOSE_REQUESTED.is_set():
            raise PackageRefusal("Package installation is already consumed or closed.")
        _ATTEMPTED = True
        def open_stage():
            if _CLOSE_REQUESTED.is_set():
                raise PackageRefusal("Closure was requested; no new initialization phase may begin.")
        open_stage()
        lock = verify_release(expected_lock_sha256=expected_lock_sha256,
            expected_package_revision=expected_package_revision,
            expected_production_revision=expected_production_revision)
        open_stage()
        root = Path(__file__).resolve().parent
        if (not isinstance(edge_config, dict) or edge_config.get("app_id") != "nebius"
                or edge_config.get("source_revision") != expected_production_revision
                or not isinstance(quota_policy, dict) or quota_policy.get("app_id") != "nebius"
                or type(enabled) is not bool):
            raise PackageRefusal("Explicit matching edge/policy inputs are required.")
        # No unpinned bytecode may be written after the exact-file-set check.
        sys.dont_write_bytecode = True
        sys.path[:0] = [str(root), str(root / "deps")]
        runtime = None
        core = None
        try:
            open_stage()
            _http_import_check(root, lock["files"])
            open_stage()
            core = importlib.import_module("production_wiring")
            _check_loaded_origins(root, lock["files"])
            if core.source_revision() != expected_production_revision:
                raise PackageRefusal("Imported production revision differs.")
            sdk = _json((root / "SDK_CLOSURE.json").read_bytes())
            closure = core.SdkClosure(tuple(tuple(x) for x in sdk["versions"]), tuple(tuple(x) for x in sdk["files"]))
            open_stage()
            runtime = core.ProductionRuntime(core.EdgeConfig(**edge_config),
                index_html=(root / "index.html").read_bytes(), signing_key=signing_key,
                client=client, table_name=table_name, policy=core.QuotaPolicy(**quota_policy),
                clock_ms=clock_ms, waiter=waiter, api_key=api_key,
                sdk_closure=closure, enabled=enabled, session_factory=session_factory,
                random_bytes=random_bytes)
            # A close can arrive while local SDK/source verification constructs
            # the candidate. It must be cleaned up, never started or published.
            open_stage()
            runtime.start()
            open_stage()
            core.configure_production(runtime)
            open_stage()
            _publish_runtime(core, runtime)
        except Exception:
            if core is not None:
                core.close_production()
            if runtime is not None:
                status = runtime.close()
                _LAST_CLOSE_STATUS = {"stopped": status.stopped, "pending": not status.stopped,
                    "pending_executor_jobs": status.pending_executor_jobs,
                    "pending_operation": status.pending_operation,
                    "initialization_in_progress": False}
                if not status.stopped:
                    _RETAINED_CANDIDATE = runtime
            _CLOSED = True
            raise PackageRefusal("Trusted package installation failed; inspect evidence, do not retry this process.") from None
    # Cover a close that arrives after the final stage check but while ownership
    # is being published under the lock. The earlier close truthfully returned
    # pending; this initializer now owns bounded cleanup after releasing _LOCK.
    # A later close can acquire the lock itself and sees the published owner.
    if _CLOSE_REQUESTED.is_set():
        close_production()
        raise PackageRefusal("Package closed during publication; inspect retained cleanup status.")
    return {"configured": True, "enabled": enabled,
        "sourceRevision": expected_package_revision, "productionSourceRevision": expected_production_revision}


def close_production():
    global _CLOSED, _LAST_CLOSE_STATUS
    # Set the fence BEFORE lock acquisition. Verification/construction may be
    # slow; neither an ordinary request nor close queues behind that operation.
    _CLOSE_REQUESTED.set()
    if not _LOCK.acquire(blocking=False):
        _LAST_CLOSE_STATUS = {"stopped": False, "pending": True, "initialization_in_progress": True}
        return dict(_LAST_CLOSE_STATUS)
    try:
        _CLOSED = True
        core = _CORE
        retained = _RETAINED_CANDIDATE
        # The external bounded close runs after releasing _LOCK. Until it
        # returns, retained work is pending, never already reported stopped.
        if core is not None or retained is not None:
            _LAST_CLOSE_STATUS = {"stopped": False, "pending": True,
                "initialization_in_progress": False}
    finally:
        _LOCK.release()
    if core is not None:
        status = core.close_production()
    elif retained is not None:
        status = retained.close()
    else:
        _LAST_CLOSE_STATUS = {"stopped": True, "pending": False, "initialization_in_progress": False}
        return dict(_LAST_CLOSE_STATUS)
    _LAST_CLOSE_STATUS = {"stopped": status.stopped, "pending": not status.stopped,
        "pending_executor_jobs": status.pending_executor_jobs,
        "pending_operation": status.pending_operation,
        "initialization_in_progress": False}
    return dict(_LAST_CLOSE_STATUS)


def _unavailable(code):
    return {"statusCode": 503, "headers": {"cache-control": "no-store", "content-type": "application/json"},
        "body": json.dumps({"error": code}, separators=(",", ":")), "isBase64Encoded": False}


def handler(event, context=None):
    """Default import/GET/POST stays 503 without opening files, keys or sockets."""
    if not _LOCK.acquire(blocking=False):
        return _unavailable("production_package_draining" if _CLOSE_REQUESTED.is_set()
            else "production_package_initializing")
    try:
        closed = _CLOSED or _CLOSE_REQUESTED.is_set()
        # A pending initialization close is no longer draining once the gate is
        # released without any installed/retained candidate. No work is hidden.
        draining = (closed and (_CORE is not None or _RETAINED_CANDIDATE is not None)
            and (_LAST_CLOSE_STATUS is None or not _LAST_CLOSE_STATUS["stopped"]))
        core = None if closed else _CORE
    finally:
        _LOCK.release()
    if core is not None:
        return core.handler(event, context)
    if closed:
        return _unavailable("production_package_draining" if draining else "production_package_closed")
    return _unavailable("production_package_unconfigured")
