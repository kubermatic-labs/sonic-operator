# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-executing pure-wheel tree installer. Invoked only by Native.

The installed RECORD is never used to select removal paths. Repair authority is
the protected before/candidate pair, published before the first live change.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MODULES = {"__init__", "chassis", "component", "eeprom", "fan", "fan_drawer", "platform", "psu", "sfp", "thermal"}
META = {"METADATA", "WHEEL", "RECORD", "INSTALLER", "REQUESTED", "direct_url.json", "top_level.txt"}
MAX_TREE = 32 * 1024 * 1024

def allowed(name):
    if name in {"sonic_platform/" + n + ".py" for n in MODULES}:
        return True
    if name in {"sonic_platform-1.0.dist-info/" + n for n in META}:
        return True
    m = re.fullmatch(r"sonic_platform/__pycache__/([a-z_]+)\.cpython-(311|313)(\.opt-[12])?\.pyc", name)
    return m is not None and m.group(1) in MODULES

def safe_path(root, name):
    if not allowed(name):
        raise RuntimeError("unapproved package path")
    target = root / name
    if target.resolve() != target:
        raise RuntimeError("package symlink conflict")
    return target

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def remove_owned_temporary(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_size > 1024 * 1024:
        raise RuntimeError('untrusted package replacement temporary')
    path.unlink()
    fsync_dir(path.parent)

def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
        fsync_dir(path.parent)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('untrusted package staging directory')

def atomic(path, data, mode=0o600, staging=None):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise RuntimeError("package state symlink")
    if staging is None:
        # Exact state-file temporary, not a wildcard cleanup of package files.
        temporary = path.parent / ('.atomic-' + path.name + '.tmp')
    else:
        root, directory = staging
        relative = str(path.relative_to(root))
        if not allowed(relative) or path.parent.stat().st_dev != directory.stat().st_dev:
            raise RuntimeError('unqualified package replacement filesystem')
        temporary = directory / (hashlib.sha256(relative.encode()).hexdigest() + '.tmp')
    remove_owned_temporary(temporary)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
        if temporary.parent != path.parent:
            fsync_dir(temporary.parent)
    finally:
        remove_owned_temporary(temporary)

def inspect(root):
    entries = {}
    total = 0
    for directory in [root / "sonic_platform", root / "sonic_platform-1.0.dist-info"]:
        if not directory.exists():
            continue
        if directory.is_symlink():
            raise RuntimeError("package directory symlink")
        for item in directory.rglob("*"):
            relative = str(item.relative_to(root))
            if item.is_symlink():
                raise RuntimeError("package symlink")
            if item.is_dir():
                if relative != "sonic_platform/__pycache__":
                    raise RuntimeError("unowned package directory")
                continue
            safe_path(root, relative)
            info = item.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024 or info.st_uid != os.geteuid():
                raise RuntimeError("unqualified package file")
            data = item.read_bytes()
            total += len(data)
            if total > MAX_TREE:
                raise RuntimeError("package snapshot too large")
            entries[relative] = {"data": base64.b64encode(data).decode(), "mode": stat.S_IMODE(info.st_mode)}
    return {"version": 1, "entries": entries}

def validate(snapshot):
    if set(snapshot) != {"version", "entries"} or snapshot["version"] != 1 or not isinstance(snapshot["entries"], dict):
        raise RuntimeError("invalid package snapshot")
    total = 0
    for name, entry in snapshot["entries"].items():
        if not allowed(name) or set(entry) != {"data", "mode"} or entry["mode"] & ~0o777:
            raise RuntimeError("invalid package snapshot entry")
        data = base64.b64decode(entry["data"], validate=True)
        if len(data) > 1024 * 1024:
            raise RuntimeError("package entry too large")
        total += len(data)
    if total > MAX_TREE:
        raise RuntimeError("package snapshot too large")

def install_tree(root, wanted, authority, fault=None, staging=None):
    # Inspect every live pathname before mutating anything. An unknown filename
    # or symlink is a conflict, never an instruction to uninstall arbitrary data.
    current = inspect(root)
    names = set(authority)
    if not set(current["entries"]).issubset(names):
        raise RuntimeError("unowned file appeared during package transaction")
    desired = {n: v for n, v in wanted["entries"].items() if "/__pycache__/" not in n}
    for directory in [root / "sonic_platform", root / "sonic_platform-1.0.dist-info"]:
        if not directory.exists():
            directory.mkdir(mode=0o755)
            fsync_dir(root)
    for name in sorted(names):
        destination = safe_path(root, name)
        if name not in desired:
            if destination.exists():
                destination.unlink()
                fsync_dir(destination.parent)
        else:
            entry = desired[name]
            atomic(destination, base64.b64decode(entry["data"]), entry["mode"], staging=staging)
        if fault is not None:
            fault(name)
    observed = inspect(root)
    if observed["entries"] != desired:
        raise RuntimeError("package repair readback failed")

def authority_paths(before, candidate):
    names = set(before['entries']) | set(candidate['entries'])
    for module in MODULES:
        if 'sonic_platform/' + module + '.py' in names:
            for version in ['311', '313']:
                for opt in ['', '.opt-1', '.opt-2']:
                    names.add('sonic_platform/__pycache__/' + module + '.cpython-' + version + opt + '.pyc')
    return names

def transaction(root, state, token, mode, before=None, candidate=None, fault=None, observed=None):
    root, state = Path(root), Path(state)
    if root.resolve() != root or state.resolve() != state or not re.fullmatch("[a-f0-9]{32}", token):
        raise RuntimeError("invalid package transaction root")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = state.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("untrusted package authority directory")
    lock_path = state / "lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if mode == "snapshot":
            return inspect(root)
        validate(before)
        validate(candidate)
        observed = before if observed is None else observed
        validate(observed)
        names = authority_paths(before, candidate)
        if not set(observed['entries']).issubset(names):
            raise RuntimeError('observation cannot expand package authority')
        record = {"version": 1, "before": hashlib.sha256(encode(before)).hexdigest(), "candidate": hashlib.sha256(encode(candidate)).hexdigest(), "observed": hashlib.sha256(encode(observed)).hexdigest()}
        authority = state / token / "authority.json"
        if authority.exists() and json.loads(authority.read_bytes()) != record:
            previous = json.loads(authority.read_bytes())
            historical = {k: v for k, v in record.items() if k != 'observed'}
            if previous != historical or record['observed'] != record['before']:
                raise RuntimeError("package transaction authority changed")
        if mode == "apply" and not authority.exists():
            # Before state must still be exact. This comparison and publication
            # share the installer lock with every subsequent repair operation.
            if inspect(root) != observed:
                raise RuntimeError("package changed before publication")
        if mode not in {"apply", "restore", "enforce"}:
            raise RuntimeError("invalid package transaction operation")
        atomic(authority, encode(record))
        # Package replacements use a private same-filesystem area outside both
        # inspected trees. Its exact temporary names derive from this durable
        # transaction's closed authority set, so a killed writer is recoverable
        # without accepting arbitrary extra files or symlinks in the package.
        staging_base = root / '.sonic-operator-package-staging'
        private_directory(staging_base)
        staging = staging_base / token
        private_directory(staging)
        expected_temporaries = {hashlib.sha256(name.encode()).hexdigest() + '.tmp' for name in names}
        for temporary in staging.iterdir():
            if temporary.name not in expected_temporaries:
                raise RuntimeError('unowned package staging file')
            remove_owned_temporary(temporary)
        # Full snapshots are retained in the supervisor's fsynced content vault.
        # Keep only compact replay identities here, bounded to recent tokens.
        histories = sorted((p for p in state.iterdir() if p.is_dir() and re.fullmatch('[a-f0-9]{32}', p.name)), key=lambda p: p.stat().st_mtime)
        for old in histories[:-8]:
            if old.name != token and {p.name for p in old.iterdir()} == {'authority.json'}:
                receipt = old / 'authority.json'
                if not receipt.is_symlink():
                    receipt.unlink(); old.rmdir(); fsync_dir(state)
        # The host journal supplies the same validated repair pair after a
        # container/process restart; broken/missing live RECORD is just data.
        install_tree(root, before if mode == "restore" else candidate,
                     names, fault, staging=(root, staging))
        staging.rmdir()
        fsync_dir(staging_base)
        return {"ok": True}

def main():
    targets = {"host": ("/usr/local/lib/python3.13/dist-packages", "/host/sonic-operator-artifacts/package-state"),
               "pmon": ("/usr/local/lib/python3.11/dist-packages", "/var/lib/sonic-operator-artifact-packages")}
    request = json.loads(sys.stdin.buffer.read(96 * 1024 * 1024 + 1))
    if set(request) - {"target", "token", "mode", "before", "candidate", "observed"}:
        raise RuntimeError("unknown package request fields")
    root, state = targets[request["target"]]
    result = transaction(root, state, request["token"], request["mode"], request.get("before"), request.get("candidate"), observed=request.get("observed"))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
