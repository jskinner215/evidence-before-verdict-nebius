"""Verify public artifact cache; download only with --execute-download.

No artifact is imported, extracted, installed or executed. Network uses direct
HTTPS connections, without environment proxy discovery, cookies or credentials.
The repository root defaults to this file's parent tools directory's parent.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urljoin, urlsplit


ALLOWED_HOSTS = frozenset({"nodejs.org", "registry.npmjs.org", "files.pythonhosted.org"})
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACTS = 100
WALL_SECONDS = 60.0
IO_SECONDS = 10.0
CHUNK_BYTES = 65536
MAX_REDIRECTS = 3
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,239}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
WINDOWS_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)})


class Refusal(Exception):
    def __init__(self, status):
        self.status = status


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("invalid_arguments")


def emit(status, artifact_id=None):
    record = {"status": status}
    if artifact_id is not None:
        record["id"] = artifact_id
    print(json.dumps(record, separators=(",", ":")), flush=True)


def safe_url(value, expected_host=None):
    if (not isinstance(value, str) or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)):
        raise Refusal("artifact_url_refused")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise Refusal("artifact_url_refused") from None
    if (parsed.scheme != "https" or host not in ALLOWED_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or port not in (None, 443)
            or parsed.netloc.lower() not in {host, host + ":443"}
            or (expected_host is not None and host != expected_host)):
        raise Refusal("artifact_url_refused")
    if not parsed.path.startswith("/"):
        raise Refusal("artifact_url_refused")
    return parsed


def no_links(path):
    """Reject existing symbolic links and Windows reparse points in the path."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise Refusal("cache_link_refused")
    return absolute


def regular_file(path):
    no_links(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise Refusal("cache_file_type_refused")
    return info


def cache_path(root, filename):
    candidate = root / filename
    no_links(candidate)
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError:
        raise Refusal("cache_boundary_refused") from None
    if candidate.parent.resolve(strict=True) != root:
        raise Refusal("cache_boundary_refused")
    return candidate


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise Refusal("time_limit_partial_retained")
    return value


def verify_file(path, artifact):
    info = regular_file(path)
    if info is None:
        return False
    if info.st_size != artifact["bytes"]:
        raise Refusal("existing_cache_mismatch")
    digest = hashlib.sha256()
    deadline = time.monotonic() + WALL_SECONDS
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Refusal("cache_file_type_refused")
        size = 0
        while block := stream.read(CHUNK_BYTES):
            remaining(deadline)
            size += len(block)
            if size > artifact["bytes"]:
                raise Refusal("existing_cache_mismatch")
            digest.update(block)
    if size != artifact["bytes"] or digest.hexdigest() != artifact["sha256"]:
        raise Refusal("existing_cache_mismatch")
    return True


def load_manifest(source):
    path = source / "ARTIFACTS.json"
    if regular_file(path) is None or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise Refusal("manifest_refused")
    try:
        data = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise Refusal("manifest_refused") from None
    if (not isinstance(data, dict) or data.get("schema") != "public-artifacts-v1"
            or not isinstance(data.get("artifacts"), list)
            or not 1 <= len(data["artifacts"]) <= MAX_ARTIFACTS):
        raise Refusal("manifest_refused")
    names, ids = set(), set()
    for item in data["artifacts"]:
        if not isinstance(item, dict):
            raise Refusal("manifest_refused")
        name, artifact_id = item.get("filename"), item.get("id")
        if (not isinstance(name, str) or not FILENAME.fullmatch(name)
                or name.endswith(".") or name.split(".", 1)[0].upper() in WINDOWS_NAMES
                or not isinstance(artifact_id, str) or not ID.fullmatch(artifact_id)
                or name.casefold() in names or artifact_id in ids
                or not isinstance(item.get("sha256"), str)
                or not SHA256.fullmatch(item["sha256"])
                or type(item.get("bytes")) is not int
                or not 0 < item["bytes"] <= MAX_ARTIFACT_BYTES
                or not isinstance(item.get("kind"), str)
                or not ID.fullmatch(item["kind"])):
            raise Refusal("manifest_refused")
        safe_url(item.get("url"))
        names.add(name.casefold())
        ids.add(artifact_id)
    return data["artifacts"]


def download_worker(artifact, stream, deadline, result):
    """Write only the exclusive partial. This worker can never publish it."""
    connection = None
    try:
        current = artifact["url"]
        origin = safe_url(current).hostname
        digest, size = hashlib.sha256(), 0
        context = ssl.create_default_context()
        for redirect in range(MAX_REDIRECTS + 1):
            parsed = safe_url(current, origin)
            connection = http.client.HTTPSConnection(parsed.hostname, port=443,
                timeout=min(IO_SECONDS, remaining(deadline)), context=context)
            connection.request("GET", parsed.path, headers={
                "User-Agent": "public-artifact-fetch/1", "Accept-Encoding": "identity",
                "Accept": "application/octet-stream", "Connection": "close"})
            response = connection.getresponse()
            remaining(deadline)
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if redirect == MAX_REDIRECTS or not location:
                    raise Refusal("redirect_refused_partial_retained")
                next_url = urljoin(current, location)
                safe_url(next_url, origin)
                connection.close()
                connection = None
                current = next_url
                continue
            if response.status != 200:
                raise Refusal("http_failed_partial_retained")
            encoding = response.getheader("Content-Encoding")
            length = response.getheader("Content-Length")
            if encoding not in (None, "identity"):
                raise Refusal("response_encoding_refused_partial_retained")
            if length is not None and length != str(artifact["bytes"]):
                raise Refusal("response_size_refused_partial_retained")
            while True:
                timeout = min(IO_SECONDS, remaining(deadline))
                if connection.sock is not None:
                    connection.sock.settimeout(timeout)
                block = response.read(min(CHUNK_BYTES, artifact["bytes"] - size + 1))
                if not block:
                    break
                remaining(deadline)
                size += len(block)
                if size > artifact["bytes"]:
                    raise Refusal("response_size_refused_partial_retained")
                stream.write(block)
                digest.update(block)
            if size != artifact["bytes"] or digest.hexdigest() != artifact["sha256"]:
                raise Refusal("download_mismatch_partial_retained")
            stream.flush()
            os.fsync(stream.fileno())
            remaining(deadline)
            result["status"] = "verified"
            return
        raise Refusal("redirect_refused_partial_retained")
    except Refusal as error:
        result["status"] = error.status
    except Exception:
        result["status"] = "download_failed_partial_retained"
    finally:
        if connection is not None:
            connection.close()
        stream.close()


def publish_verified(partial, target):
    no_links(partial)
    no_links(target)
    if regular_file(target) is not None:
        raise Refusal("target_appeared_partial_retained")
    if os.name == "nt":
        # Windows rename is atomic and refuses an existing destination.
        os.rename(partial, target)
    else:
        # Portable POSIX rename overwrites. Link publishes complete verified
        # bytes atomically without replacement, then removes our partial name.
        os.link(partial, target, follow_symlinks=False)
        try:
            partial.unlink()
        except OSError:
            return "verified_published_partial_retained"
    return "verified_downloaded"


def fetch_one(root, artifact):
    target = cache_path(root, artifact["filename"])
    partial = cache_path(root, artifact["filename"] + ".partial")
    if regular_file(partial) is not None:
        raise Refusal("existing_partial_refused")
    if verify_file(target, artifact):
        return "verified_cached"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(partial, flags, 0o600)
    stream = os.fdopen(descriptor, "wb", buffering=0)
    result = {}
    deadline = time.monotonic() + WALL_SECONDS
    worker = threading.Thread(target=download_worker,
        args=(artifact, stream, deadline, result), daemon=True)
    try:
        worker.start()
    except Exception:
        stream.close()
        raise Refusal("download_start_failed_partial_retained") from None
    worker.join(max(0, deadline - time.monotonic()))
    if worker.is_alive():
        # Main returns immediately; the daemon may still be blocked in OS DNS.
        # It never publishes, and process exit ends it. Preserve the partial.
        raise Refusal("time_limit_partial_retained")
    if result.get("status") != "verified":
        raise Refusal(result.get("status", "download_failed_partial_retained"))
    remaining(deadline)
    no_links(root)
    return publish_verified(partial, target)


def main(argv=None):
    current_id = None
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--cache", type=Path, required=True)
        parser.add_argument("--execute-download", action="store_true")
        args = parser.parse_args(argv)
        artifacts = load_manifest(args.source)
        cache = no_links(args.cache)
        if cache.exists() and not cache.is_dir():
            raise Refusal("cache_directory_refused")
        if not cache.exists():
            if not args.execute_download:
                for artifact in artifacts:
                    emit("missing_download_not_requested", artifact["id"])
                return 0
            cache.mkdir(parents=True, exist_ok=False)
        no_links(cache)
        cache = cache.resolve(strict=True)
        missing = []
        # Complete all local checks before any network or partial creation.
        for artifact in artifacts:
            current_id = artifact["id"]
            target = cache_path(cache, artifact["filename"])
            partial = cache_path(cache, artifact["filename"] + ".partial")
            if regular_file(partial) is not None:
                raise Refusal("existing_partial_refused")
            if verify_file(target, artifact):
                emit("verified_cached", current_id)
            else:
                missing.append(artifact)
        for artifact in missing:
            current_id = artifact["id"]
            if not args.execute_download:
                emit("missing_download_not_requested", current_id)
                continue
            status = fetch_one(cache, artifact)
            emit(status, current_id)
        return 0
    except Refusal as error:
        emit(error.status, current_id)
        return 2
    except KeyboardInterrupt:
        emit("interrupted_inspect_partial_before_retry", current_id)
        return 130
    except Exception:
        emit("operation_failed_inspect_cache_before_retry", current_id)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
