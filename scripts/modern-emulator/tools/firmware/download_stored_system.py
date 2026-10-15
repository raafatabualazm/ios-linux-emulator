#!/usr/bin/env python3
"""Retrieve one inventoried ZIP_STORED IPSW member with bounded HTTP ranges.

Image contents are copied unchanged. Downloads resume explicitly from a private
partial file; the source ETag, manifest hash, member size and CRC remain pinned.
No whole archive, firmware keys, signing tickets, or decoding is requested.
"""

from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
import zlib

from prepare_firmware import (DEFAULT_LIMIT, MAX_METADATA, MAX_REQUEST, MIB,
                              FirmwareError, RangeReader, checked_name,
                              exclusive_write, open_archive, read_member)

GIB = 1024 * MIB
MAX_MEMBER = 16 * GIB


class TruncatedRangeError(Exception):
    """A short HTTP body can be resumed from the bytes already written."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path: Path, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    if len(data) > MIB:
        raise FirmwareError("download report exceeds 1 MiB")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    exclusive_write(temporary, data)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def selected_member(report: dict, *, variant: str, component: str):
    if report.get("operation") != "manifest-and-directory-inventory-only":
        raise FirmwareError("archive inventory required")
    identities = [i for i in report.get("identities", [])
                  if i.get("info", {}).get("Variant") == variant]
    if len(identities) != 1:
        raise FirmwareError("inventory must select exactly one build identity")
    rows = [c for c in identities[0].get("components", [])
            if c.get("manifest_key") == component]
    if len(rows) != 1 or rows[0].get("archive_member_present") is not True:
        raise FirmwareError("inventory has no unique archive member for component")
    row = rows[0]
    checked_name(row["member"])
    if (not isinstance(row.get("zip_size"), int)
            or not 0 < row["zip_size"] <= MAX_MEMBER
            or row.get("compressed_size") != row["zip_size"]
            or not re.fullmatch(r"[0-9a-f]{8}", row.get("crc32", ""))):
        raise FirmwareError("invalid or oversized inventoried stored member")
    etag = report.get("http", {}).get("etag")
    if not isinstance(etag, str) or etag.startswith("W/") or not etag:
        raise FirmwareError("inventory requires a strong HTTP ETag")
    return identities[0], row, etag


def source_pins(report: dict, *, variant: str, component: str, timeout: float):
    identity, selected, etag = selected_member(report, variant=variant,
                                               component=component)
    source = report.get("source", "")
    with open_archive(source, limit=16 * MIB, timeout=timeout,
                      maximum_limit=DEFAULT_LIMIT) as (zf, reader, size):
        if not isinstance(reader, RangeReader) or reader.etag != etag:
            raise FirmwareError("source is not the inventoried HTTP entity")
        if size != report.get("archive_size"):
            raise FirmwareError("archive size changed since inventory")
        manifest = read_member(zf, "BuildManifest.plist", MAX_METADATA)
        if hashlib.sha256(manifest).hexdigest() != report.get("build_manifest_sha256"):
            raise FirmwareError("BuildManifest changed since inventory")
        try:
            member = zf.getinfo(selected["member"])
        except KeyError as exc:
            raise FirmwareError("inventoried image member is missing") from exc
        if (member.compress_type != zipfile.ZIP_STORED
                or member.file_size != selected["zip_size"]
                or member.compress_size != selected["compressed_size"]
                or member.CRC != int(selected["crc32"], 16)):
            raise FirmwareError("image member is not the inventoried stored payload")
        reader.seek(member.header_offset)
        header = reader.read(30)
        fields = struct.unpack("<4s5H3I2H", header)
        signature, _, flags, compression, _, _, _, _, _, name_len, extra_len = fields
        if (signature != b"PK\x03\x04" or flags != member.flag_bits
                or compression != zipfile.ZIP_STORED or flags & 1):
            raise FirmwareError("member local header does not match directory")
        encoded_name = reader.read(name_len)
        name = encoded_name.decode("utf-8" if flags & 0x800 else "cp437")
        if name != member.filename:
            raise FirmwareError("member local-header filename mismatch")
        data_offset = member.header_offset + 30 + name_len + extra_len
        if data_offset + member.file_size > size:
            raise FirmwareError("stored image extent outside archive")
        pins = {"schema": 1, "source": source, "archive_size": size,
                "etag": etag, "build_manifest_sha256": report["build_manifest_sha256"],
                "product_version": report.get("product_version"),
                "product_build": report.get("product_build"),
                "device_class": identity["info"].get("DeviceClass"),
                "variant": variant, "component": component,
                "member": member.filename, "size": member.file_size,
                "crc32": f"{member.CRC:08x}", "data_offset": data_offset,
                "compression": "ZIP_STORED"}
        return pins, reader.transferred


def response_for(pins: dict, start: int, count: int, timeout: float):
    absolute = pins["data_offset"] + start
    end = absolute + count - 1
    request = urllib.request.Request(pins["source"], headers={
        "Range": f"bytes={absolute}-{end}", "Accept-Encoding": "identity",
        "If-Match": pins["etag"],
    })
    response = urllib.request.urlopen(request, timeout=timeout)
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)",
                         response.headers.get("Content-Range", ""))
    length = response.headers.get("Content-Length")
    if (response.status != 206 or match is None
            or tuple(map(int, match.groups())) != (absolute, end, pins["archive_size"])
            or response.headers.get("ETag") != pins["etag"]
            or response.headers.get("Content-Encoding", "identity").lower() != "identity"
            or (length is not None and (not length.isdigit() or int(length) != count))):
        response.close()
        raise FirmwareError("range response differs from pinned source/extent")
    return response


def download(report: dict, output: Path, *, variant: str, component: str,
             resume=False, timeout=15, wall_time=3600, reserve=GIB):
    if (not math.isfinite(timeout) or not 0 < timeout <= 60
            or not math.isfinite(wall_time) or not 1 <= wall_time <= 7200
            or not GIB <= reserve <= 32 * GIB):
        raise FirmwareError("invalid timeout, wall time, or disk reserve")
    started = time.monotonic()
    deadline = started + wall_time
    pins, metadata_transferred = source_pins(report, variant=variant,
                                             component=component, timeout=timeout)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    filename = Path(pins["member"]).name
    final = output / filename
    partial = output / (filename + ".part")
    state = output / (filename + ".part.json")
    if final.exists() or final.is_symlink():
        raise FirmwareError("refusing to replace completed image")
    flags = os.O_RDWR | os.O_NOFOLLOW
    if resume:
        if not state.is_file() or state.is_symlink():
            raise FirmwareError("resume requires saved source pins")
        saved = json.loads(state.read_bytes())
        if saved != pins:
            raise FirmwareError("resume source pins differ from current metadata")
    else:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(partial, flags, 0o600)
    progress = {**pins, "status": "starting", "pid": os.getpid(),
                "created_utc": utc_now(), "partial": str(partial),
                "output": str(final), "downloaded_bytes": 0,
                "metadata_transferred_bytes": metadata_transferred,
                "payload_transferred_bytes_this_run": 0,
                "range_requests_this_run": 0, "disk_reserve_bytes": reserve,
                "maximum_wall_seconds": wall_time, "resumed": resume}
    progress_path = output / "progress.json"
    locked = False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        details = os.fstat(fd)
        if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                or details.st_size > pins["size"]):
            raise FirmwareError("partial image is not an independent bounded regular file")
        remaining = pins["size"] - details.st_size
        disk = os.statvfs(output)
        if remaining + reserve > disk.f_bavail * disk.f_frsize:
            raise FirmwareError("remaining image bytes exceed available space plus reserve")
        if not resume:
            exclusive_write(state, (json.dumps(pins, indent=2) + "\n").encode())
        sha = hashlib.sha256()
        crc = 0
        received = 0
        # Re-read a resumed prefix; trusting an interrupted process's digest
        # would miss a truncated or modified partial file.
        with os.fdopen(fd, "r+b", closefd=False) as stream:
            while received < details.st_size:
                if time.monotonic() >= deadline:
                    raise FirmwareError("prefix verification exceeded wall-time budget")
                chunk = stream.read(min(MIB, details.st_size - received))
                if not chunk:
                    raise FirmwareError("partial image changed during prefix verification")
                sha.update(chunk)
                crc = zlib.crc32(chunk, crc)
                received += len(chunk)
            initial_bytes = received
            progress["initial_bytes"] = initial_bytes
            last_update = 0
            attempts = 0
            while received < pins["size"]:
                now = time.monotonic()
                if now >= deadline:
                    raise FirmwareError("download exceeded wall-time budget; partial retained")
                disk = os.statvfs(output)
                if disk.f_bavail * disk.f_frsize < reserve + min(MAX_REQUEST, pins["size"] - received):
                    raise FirmwareError("disk reserve reached; partial retained")
                count = min(MAX_REQUEST, pins["size"] - received)
                progress["range_requests_this_run"] += 1
                if progress["range_requests_this_run"] > 8192:
                    raise FirmwareError("range request budget exceeded")
                try:
                    with response_for(pins, received, count,
                                      min(timeout, deadline - now)) as response:
                        # Short read1 calls let the wall-time budget apply even
                        # when a peer trickles data within its socket timeout.
                        read = getattr(response, "read1", response.read)
                        range_bytes = 0
                        while range_bytes < count:
                            if time.monotonic() >= deadline:
                                raise FirmwareError("HTTP body exceeded wall-time budget")
                            chunk = read(min(64 * 1024, count - range_bytes))
                            if not chunk:
                                raise TruncatedRangeError("truncated HTTP range")
                            if stream.write(chunk) != len(chunk):
                                raise OSError("short partial-image write")
                            sha.update(chunk)
                            crc = zlib.crc32(chunk, crc)
                            received += len(chunk)
                            range_bytes += len(chunk)
                            progress["payload_transferred_bytes_this_run"] += len(chunk)
                            now = time.monotonic()
                            if now - last_update >= 2:
                                progress.update({"status": "downloading", "updated_utc": utc_now(),
                                                 "downloaded_bytes": received,
                                                 "percent": received * 100 / pins["size"],
                                                 "elapsed_seconds": now - started,
                                                 "bytes_per_second": (received - initial_bytes) / max(0.001, now - started)})
                                atomic_json(progress_path, progress)
                                last_update = now
                        # Validate the exact range body length before accepting
                        # the next extent. Servers may not return extra bytes.
                        if read(1):
                            raise FirmwareError("overlong HTTP range body")
                    attempts = 0
                except urllib.error.HTTPError as exc:
                    if exc.code not in (408, 429, 500, 502, 503, 504):
                        raise FirmwareError(f"HTTP range failed ({exc.code})") from exc
                    attempts += 1
                    if attempts > 5:
                        raise FirmwareError("HTTP retry budget exceeded") from exc
                    time.sleep(min(2 ** attempts, 16, max(0, deadline - time.monotonic())))
                except (urllib.error.URLError, TimeoutError, ConnectionError,
                        TruncatedRangeError) as exc:
                    attempts += 1
                    if attempts > 5:
                        raise FirmwareError("network retry budget exceeded") from exc
                    time.sleep(min(2 ** attempts, 16, max(0, deadline - time.monotonic())))
                stream.flush()
            stream.flush()
            os.fsync(fd)
        if os.fstat(fd).st_size != pins["size"] or crc != int(pins["crc32"], 16):
            raise FirmwareError("completed image length or ZIP CRC mismatch; partial retained")
        # link is exclusive, unlike rename; a pre-existing complete image can
        # never be overwritten. The partial is removed only after validation.
        os.link(partial, final, follow_symlinks=False)
        partial.unlink()
        progress.update({"status": "complete", "updated_utc": utc_now(),
                         "downloaded_bytes": received, "percent": 100.0,
                         "elapsed_seconds": time.monotonic() - started,
                         "sha256": sha.hexdigest(), "verified_crc32": f"{crc:08x}",
                         "length_verified": True, "zip_crc_verified": True})
        atomic_json(progress_path, progress)
        exclusive_write(output / "provenance.json",
                        (json.dumps(progress, indent=2) + "\n").encode())
        return progress
    except BaseException as exc:
        if locked:
            progress.update({"status": "interrupted" if isinstance(exc, (InterruptedError, KeyboardInterrupt)) else "error",
                             "updated_utc": utc_now(), "downloaded_bytes": os.fstat(fd).st_size,
                             "elapsed_seconds": time.monotonic() - started,
                             "message": str(exc)})
            atomic_json(progress_path, progress)
        raise
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", default="Customer Erase Install (IPSW)")
    parser.add_argument("--component", choices=("OS", "Cryptex1,SystemOS", "Cryptex1,AppOS"), default="OS")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--wall-time", type=float, default=3600)
    parser.add_argument("--reserve-gib", type=int, default=1)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError(f"interrupted by signal {signum}; partial retained")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.inventory.stat().st_size > MIB:
            raise FirmwareError("inventory report exceeds 1 MiB")
        report = json.loads(args.inventory.read_bytes())
        result = download(report, args.output, variant=args.variant,
                          component=args.component, resume=args.resume,
                          timeout=args.timeout, wall_time=args.wall_time,
                          reserve=args.reserve_gib * GIB)
        print(json.dumps({"status": result["status"], "path": result["output"],
                          "sha256": result["sha256"], "size": result["downloaded_bytes"]}))
    except (FirmwareError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
