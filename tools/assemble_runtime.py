"""Assemble an exact runtime from reviewed source and a verified local cache.

Offline only: no package installation, imports from the application, SDK,
credentials, subprocesses or network. Existing output is never replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import zipfile

MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 250 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    pass


def name(value):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or value.startswith("/") or any(p in {"", ".", ".."} for p in value.split("/"))
            or PurePosixPath(value).is_absolute() or any(ord(c) < 32 for c in value)):
        raise Refusal("unsafe_member_name")
    return value


def no_links(path):
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            value = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
            raise Refusal("filesystem_link_refused")
    return path


def regular(path):
    path = no_links(path)
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        raise Refusal("regular_file_required")
    return path


def digest(path):
    result = hashlib.sha256()
    with regular(path).open("rb") as source:
        while block := source.read(65536):
            result.update(block)
    return result.hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate_json_field")
        result[key] = value
    return result


def document(path):
    path = regular(path)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise Refusal("manifest_too_large")
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def validate(source, cache):
    data = document(source / "ASSEMBLY_MAP.json")
    artifacts = document(source / "ARTIFACTS.json")
    if (data.get("schema") != "public-runtime-assembly-v1"
            or not isinstance(data.get("files"), dict) or not 1 <= len(data["files"]) <= 5000
            or artifacts.get("schema") != "public-artifacts-v1"
            or not isinstance(artifacts.get("artifacts"), list)):
        raise Refusal("manifest_schema_refused")
    files, inputs, names, total = data["files"], {}, set(), 0
    for item in artifacts["artifacts"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise Refusal("artifact_manifest_refused")
        key, filename = item["id"], name(item.get("filename"))
        if (key in inputs or "/" in filename or filename.casefold() in names
                or type(item.get("bytes")) is not int or not 0 < item["bytes"] <= MAX_FILE
                or not isinstance(item.get("sha256"), str) or not HEX.fullmatch(item["sha256"])):
            raise Refusal("artifact_manifest_refused")
        path = regular(cache / filename)
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise Refusal("artifact_bytes_differ")
        inputs[key] = path
        names.add(filename.casefold())
    names = set()
    for path, proof in files.items():
        name(path)
        if (path.casefold() in names or not isinstance(proof, dict)
                or type(proof.get("bytes")) is not int or not 0 <= proof["bytes"] <= MAX_FILE
                or type(proof.get("mode")) is not int or proof["mode"] not in {0o644, 0o755}
                or not isinstance(proof.get("sha256"), str) or not HEX.fullmatch(proof["sha256"])):
            raise Refusal("file_proof_refused")
        base = {"sha256", "bytes", "mode"}
        if set(proof) == base | {"sourceFile"}:
            regular(source / name(proof["sourceFile"]))
        elif set(proof) == base | {"artifactId", "member"}:
            if proof["artifactId"] not in inputs:
                raise Refusal("artifact_id_missing")
            name(proof["member"])
        else:
            raise Refusal("exact_origin_required")
        names.add(path.casefold())
        total += proof["bytes"]
    if total > MAX_TOTAL:
        raise Refusal("runtime_size_limit")
    return files, inputs


def index_archive(path):
    if path.name.endswith(".whl") or path.name.endswith(".zip"):
        archive = zipfile.ZipFile(path)
        members = archive.infolist()
        reader = lambda item: archive.open(item)
        valid = lambda item: (not item.is_dir() and not item.flag_bits & 1
            and stat.S_IFMT(item.external_attr >> 16) in {0, stat.S_IFREG})
        size = lambda item: item.file_size
        label = lambda item: item.filename
    elif path.name.endswith((".tgz", ".tar.gz", ".tar.xz")):
        archive = tarfile.open(path, "r:*")
        members = archive.getmembers()
        reader, valid = archive.extractfile, lambda item: item.isreg()
        size, label = lambda item: item.size, lambda item: item.name
    else:
        raise Refusal("archive_kind_refused")
    if len(members) > 20000:
        archive.close()
        raise Refusal("archive_member_limit")
    result = {}
    for item in members:
        key = label(item)
        # Directories are never selected. Account for trailing '/' in archives.
        checked = key[:-1] if key.endswith("/") else key
        name(checked)
        if checked.casefold() in result:
            archive.close()
            raise Refusal("ambiguous_archive_member")
        result[checked.casefold()] = (key, item)
    return archive, result, reader, valid, size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix":
        raise Refusal("posix_runtime_assembly_required")
    source, cache, output = map(no_links, (args.source, args.cache, args.output))
    if not source.is_dir() or not cache.is_dir() or output.exists():
        raise Refusal("source_cache_or_new_output_required")
    if not output.parent.is_dir() or output.is_relative_to(source) or output.is_relative_to(cache):
        raise Refusal("separate_existing_output_parent_required")
    files, inputs = validate(source, cache)
    opened = {}
    try:
        # Inspect all archive indexes before creating the exclusive output.
        for key, path in inputs.items():
            opened[key] = index_archive(path)
        output.mkdir(mode=0o700, exist_ok=False)
        for path, proof in sorted(files.items()):
            target = output / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if "sourceFile" in proof:
                stream = regular(source / proof["sourceFile"]).open("rb")
            else:
                archive, entries, reader, valid, size = opened[proof["artifactId"]]
                entry = entries.get(proof["member"].casefold())
                if entry is None or entry[0] != proof["member"] or not valid(entry[1]) or size(entry[1]) != proof["bytes"]:
                    raise Refusal("selected_archive_member_differs")
                stream = reader(entry[1])
            with stream, target.open("xb") as destination:
                body = stream.read(proof["bytes"] + 1)
                if len(body) != proof["bytes"] or hashlib.sha256(body).hexdigest() != proof["sha256"]:
                    raise Refusal("selected_member_bytes_differ")
                destination.write(body)
            target.chmod(proof["mode"])
        actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
        if actual != set(files):
            raise Refusal("assembled_file_set_differs")
        for path, proof in files.items():
            target = regular(output / path)
            if target.stat().st_size != proof["bytes"] or stat.S_IMODE(target.stat().st_mode) != proof["mode"] or digest(target) != proof["sha256"]:
                raise Refusal("assembled_readback_differs")
        lock = next((document(output / p) for p in ("RUNTIME_LOCK.json", "PACKAGE_LOCK.json") if p in files), {})
        print(json.dumps({"state": "assembled_verified", "files": len(files), "sourceRevision": lock.get("sourceRevision"),
            "networkRequests": 0, "credentialsRead": 0, "appImported": False, "output": str(output)}))
    finally:
        for archive, *_ in opened.values():
            archive.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"state": "refused_partial_preserved", "reason": str(error) if isinstance(error, Refusal) else type(error).__name__}))
        sys.exit(1)
