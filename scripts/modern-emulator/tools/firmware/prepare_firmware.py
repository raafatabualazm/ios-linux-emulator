#!/usr/bin/env python3
"""Read a local or HTTP-range IPSW and prepare matched, unmodified boot payloads.

No root filesystem, restore ramdisk, key, ticket, or security patch is selected.
Requires only Python's standard library. Compressed Image4 payloads optionally
use an existing img4 executable with its ordinary extraction operation.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import resource
import stat
import struct
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile


MIB = 1024 * 1024
MAX_METADATA = 16 * MIB
DEFAULT_LIMIT = 300 * MIB
MAX_REQUEST = 8 * MIB
MAX_REPORT = MIB
COMPONENTS = {
    "bootkc": ("KernelCache",),
    "dtree": ("DeviceTree",),
    "sptm": ("Ap,SecurePageTableMonitor", "Ap,SPTM", "SPTM"),
    "txm": ("Ap,TrustedExecutionMonitor", "Ap,TXM", "TXM"),
    "restore-trustcache": ("RestoreTrustCache",),
}
IMAGE4_TYPES = {"bootkc": "krnl", "dtree": "dtre", "sptm": "sptm",
                "txm": "trxm", "restore-trustcache": "rtsc"}


class FirmwareError(Exception):
    """A checked input, identity, range, or resource error."""


class RangeReader(io.RawIOBase):
    """Seekable, bounded, identity-encoded HTTP byte ranges with entity pinning."""

    def __init__(self, url: str, *, limit: int = DEFAULT_LIMIT, timeout: float = 15):
        super().__init__()
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise FirmwareError("HTTP(S) source required")
        if parsed.username or parsed.password or parsed.fragment:
            raise FirmwareError("credentials and fragments are not allowed in source URLs")
        self.url = url
        if not 0 < limit <= DEFAULT_LIMIT or not math.isfinite(timeout) or not 0 < timeout <= 120:
            raise FirmwareError("invalid transfer budget or timeout")
        self.limit = limit
        self.timeout = timeout
        self.pos = 0
        self.size = None
        self.etag = None
        self.modified = None
        self.transferred = 0
        self.requests = []
        self.deadline = time.monotonic() + 300
        self._fetch(0, 1)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=os.SEEK_SET):
        if whence not in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END):
            raise FirmwareError("invalid seek origin")
        start = (0, self.pos, self.size)[whence]
        pos = start + offset
        if not 0 <= pos <= self.size:
            raise FirmwareError("ZIP seek outside archive")
        self.pos = pos
        return pos

    def read(self, size=-1):
        if self.closed:
            raise ValueError("read from closed reader")
        remaining = self.size - self.pos
        size = remaining if size is None or size < 0 else min(size, remaining)
        if size > MAX_REQUEST:
            raise FirmwareError("ZIP request exceeds 8 MiB read bound")
        if not size:
            return b""
        data = self._fetch(self.pos, size)
        self.pos += len(data)
        return data

    def _fetch(self, start, count):
        if count <= 0 or count > MAX_REQUEST or self.transferred + count > self.limit:
            raise FirmwareError("HTTP transfer budget exceeded")
        remaining_time = self.deadline - time.monotonic()
        if remaining_time <= 0 or len(self.requests) >= 4096:
            raise FirmwareError("HTTP operation exceeded time/request budget")
        end = start + count - 1
        headers = {"Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"}
        if self.etag:
            headers["If-Match"] = self.etag
        elif self.modified:
            headers["If-Unmodified-Since"] = self.modified
        req = urllib.request.Request(self.url, headers=headers)
        try:
            response = urllib.request.urlopen(req, timeout=min(self.timeout, remaining_time))
        except Exception as exc:
            raise FirmwareError(f"range request failed: {exc}") from exc
        with response:
            if response.status != 206:
                raise FirmwareError(f"server ignored Range (HTTP {response.status}); body not read")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise FirmwareError("server returned an encoded range")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
            if not match:
                raise FirmwareError("missing or invalid Content-Range")
            actual_start, actual_end, total = map(int, match.groups())
            if actual_start != start or actual_end != end or total <= end:
                raise FirmwareError("server returned the wrong byte range")
            if self.size is not None and total != self.size:
                raise FirmwareError("archive size changed between ranges")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) != count):
                raise FirmwareError("range Content-Length mismatch")
            etag = response.headers.get("ETag")
            modified = response.headers.get("Last-Modified")
            if self.size is not None:
                if self.etag and etag != self.etag:
                    raise FirmwareError("archive ETag changed between ranges")
                if not self.etag and self.modified and modified != self.modified:
                    raise FirmwareError("archive modification time changed between ranges")
            else:
                self.etag = etag if etag and not etag.startswith("W/") else None
                self.modified = modified
                if not self.etag and not self.modified:
                    raise FirmwareError("HTTP archive has no stable ETag or Last-Modified validator")
            try:
                data = bytearray()
                # read1 performs at most one underlying buffered/socket read,
                # so a drip-feeding peer cannot hide the operation deadline
                # inside one large read(). Socket timeout bounds each read.
                read_chunk = getattr(response, "read1", response.read)
                while len(data) < count + 1:
                    if time.monotonic() >= self.deadline:
                        raise FirmwareError("HTTP body exceeded operation time budget")
                    chunk = read_chunk(min(64 * 1024, count + 1 - len(data)))
                    if time.monotonic() >= self.deadline:
                        raise FirmwareError("HTTP body exceeded operation time budget")
                    if not chunk:
                        break
                    data.extend(chunk)
            except FirmwareError:
                raise
            except Exception as exc:
                raise FirmwareError("truncated HTTP range body") from exc
            if len(data) != count:
                raise FirmwareError("truncated or overlong HTTP range")
            self.size = total
            self.transferred += count
            self.requests.append({"start": start, "length": count})
            return bytes(data)


def checked_name(name: str):
    path = PurePosixPath(name)
    if (not name or "\x00" in name or "\\" in name or ":" in name
            or path.is_absolute() or ".." in path.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
        raise FirmwareError("unsafe ZIP member path")
    return name


def validate_directory(zf: zipfile.ZipFile, archive_size: int):
    if len(zf.infolist()) > 20000:
        raise FirmwareError("too many ZIP members")
    seen = set()
    for member in zf.infolist():
        checked_name(member.orig_filename)
        if member.filename in seen:
            raise FirmwareError("duplicate ZIP member")
        seen.add(member.filename)
        kind = stat.S_IFMT(member.external_attr >> 16)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise FirmwareError("ZIP symbolic links and special files are not accepted")
        if member.flag_bits & 1:
            raise FirmwareError("encrypted ZIP member")
        if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise FirmwareError("unsupported ZIP compression")
        if (member.header_offset < 0 or member.header_offset + 30 > archive_size
                or member.compress_size < 0 or member.file_size < 0
                or member.header_offset + 30 + member.compress_size > archive_size):
            raise FirmwareError("ZIP member extent outside archive")


def check_zip_metadata(reader):
    """Reject excessive central directories before zipfile allocates them."""
    size = reader.seek(0, os.SEEK_END)
    reader.seek(max(0, size - 65557))
    tail = reader.read(min(size, 65557))
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or offset + 22 > len(tail):
        raise FirmwareError("ZIP end record missing or truncated")
    fields = struct.unpack_from("<4s4H2IH", tail, offset)
    _, disk, cd_disk, entries_disk, entries, cd_size, cd_offset, comment = fields
    if offset + 22 + comment != len(tail):
        raise FirmwareError("invalid ZIP end record/comment bounds")
    if disk or cd_disk or entries_disk != entries:
        raise FirmwareError("multipart ZIP archives are unsupported")
    absolute = size - len(tail) + offset
    if cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF or entries == 0xFFFF:
        if absolute < 20:
            raise FirmwareError("ZIP64 locator missing")
        reader.seek(absolute - 20)
        locator = reader.read(20)
        sig, zip64_disk, zip64_offset, disks = struct.unpack("<4sIQI", locator)
        if sig != b"PK\x06\x07" or zip64_disk or disks != 1 or zip64_offset + 56 > absolute - 20:
            raise FirmwareError("invalid ZIP64 locator")
        reader.seek(zip64_offset)
        record = reader.read(56)
        vals = struct.unpack("<4sQ2H2I4Q", record)
        if vals[0] != b"PK\x06\x06" or vals[1] < 44 or zip64_offset + 12 + vals[1] != absolute - 20:
            raise FirmwareError("invalid ZIP64 end record")
        if vals[4] or vals[5] or vals[6] != vals[7]:
            raise FirmwareError("multipart ZIP64 archive")
        entries, cd_size, cd_offset = vals[7], vals[8], vals[9]
        absolute = zip64_offset
    if entries > 20000 or cd_size > MAX_METADATA or cd_offset + cd_size > absolute:
        raise FirmwareError("central directory exceeds archive or metadata budget")


@contextlib.contextmanager
def open_archive(source, limit=DEFAULT_LIMIT, timeout=15):
    if urllib.parse.urlsplit(source).scheme in ("http", "https"):
        reader = RangeReader(source, limit=limit, timeout=timeout)
    else:
        reader = open(source, "rb")
    try:
        check_zip_metadata(reader)
        size = reader.seek(0, os.SEEK_END)
        try:
            zf = zipfile.ZipFile(reader)
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            raise FirmwareError(f"malformed ZIP: {exc}") from exc
        with zf:
            validate_directory(zf, size)
            yield zf, reader, size
    finally:
        reader.close()


def read_member(zf, name, limit):
    checked_name(name)
    try:
        info = zf.getinfo(name)
    except KeyError as exc:
        raise FirmwareError(f"missing selected ZIP member: {name}") from exc
    if info.is_dir() or info.file_size > limit:
        raise FirmwareError("selected member exceeds output budget")
    data = bytearray()
    try:
        with zf.open(info) as member:
            while True:
                chunk = member.read(min(256 * 1024, limit - len(data) + 1))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise FirmwareError("member expanded beyond budget")
    except (zipfile.BadZipFile, EOFError, ValueError, RuntimeError) as exc:
        raise FirmwareError(f"selected ZIP member is invalid: {exc}") from exc
    if len(data) != info.file_size:
        raise FirmwareError("selected member length mismatch")
    return bytes(data)


def select_identity(manifest, *, product, board, version=None, build=None, variant=None):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("SupportedProductTypes"), list):
        raise FirmwareError("invalid BuildManifest dictionary/products")
    if product not in manifest.get("SupportedProductTypes", []):
        raise FirmwareError("product does not match BuildManifest")
    if version and version != manifest.get("ProductVersion"):
        raise FirmwareError("product version does not match BuildManifest")
    if build and build != manifest.get("ProductBuildVersion"):
        raise FirmwareError("product build does not match BuildManifest")
    candidates = []
    identities = manifest.get("BuildIdentities")
    if not isinstance(identities, list):
        raise FirmwareError("invalid BuildManifest identities")
    for identity in identities:
        if not isinstance(identity, dict) or not isinstance(identity.get("Info"), dict):
            raise FirmwareError("invalid build identity dictionary/info")
        info = identity.get("Info", {})
        device_class = info.get("DeviceClass", "")
        if not isinstance(device_class, str):
            raise FirmwareError("invalid build identity device class")
        if device_class.lower() != board.lower():
            continue
        if variant and info.get("Variant") != variant:
            continue
        candidates.append(identity)
    if not candidates:
        raise FirmwareError("no matching board/build identity")
    if len(candidates) > 1 and not variant:
        erase = [x for x in candidates if x.get("Info", {}).get("RestoreBehavior") == "Erase"]
        if len(erase) == 1:
            candidates = erase
    if len(candidates) != 1:
        raise FirmwareError("ambiguous build identity; select an exact --variant")
    identity = candidates[0]
    if not isinstance(identity.get("Manifest"), dict):
        raise FirmwareError("invalid build identity component manifest")
    components = {}
    for dest, aliases in COMPONENTS.items():
        found = [(name, identity.get("Manifest", {}).get(name)) for name in aliases
                 if name in identity.get("Manifest", {})]
        if len(found) > 1:
            raise FirmwareError(f"ambiguous manifest component: {dest}")
        if not found:
            if dest in ("sptm", "txm", "restore-trustcache"):
                continue
            raise FirmwareError(f"missing required manifest component: {dest}")
        name, component = found[0]
        if not isinstance(component, dict) or not isinstance(component.get("Info"), dict):
            raise FirmwareError("invalid selected component info")
        member = component.get("Info", {}).get("Path")
        if not isinstance(member, str):
            raise FirmwareError("selected component has no member path")
        checked_name(member)
        components[dest] = {"manifest_key": name, "member": member}
    if ("sptm" in components) != ("txm" in components):
        raise FirmwareError("SPTM/TXM pair is incomplete")
    return identity, components


def der_item(data, offset, end):
    if offset + 2 > end:
        raise FirmwareError("truncated Image4 DER")
    tag, length = data[offset], data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 8 or start + count > end or data[start] == 0:
            raise FirmwareError("invalid Image4 DER length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
        if length < 128:
            raise FirmwareError("noncanonical Image4 DER length")
    if start + length > end:
        raise FirmwareError("Image4 DER payload outside input")
    return tag, start, start + length


def im4p_payload(data):
    tag, start, end = der_item(data, 0, len(data))
    if tag != 0x30 or end != len(data):
        raise FirmwareError("expected a complete IM4P DER sequence")
    items = []
    pos = start
    while pos < end:
        tag, begin, finish = der_item(data, pos, end)
        items.append((tag, begin, finish))
        pos = finish
        if len(items) > 12:
            raise FirmwareError("too many Image4 fields")
    if (len(items) < 4 or items[0][0] != 0x16
            or data[items[0][1]:items[0][2]] != b"IM4P"
            or items[1][0] != 0x16 or items[1][2] - items[1][1] != 4
            or items[2][0] != 0x16 or items[3][0] != 4):
        raise FirmwareError("unsupported Image4 wrapper; keys and tickets are not processed")
    if len(items) > 4 and items[4][0] == 4 and items[4][2] > items[4][1]:
        raise FirmwareError("encrypted Image4 payload; no keys are accepted")
    try:
        typ = data[items[1][1]:items[1][2]].decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise FirmwareError("invalid Image4 payload type") from exc
    if any(ord(c) < 32 or ord(c) > 126 for c in typ):
        raise FirmwareError("invalid Image4 payload type")
    return typ, data[items[3][1]:items[3][2]]


def digest(data):
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def exclusive_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def extract_payload(data, original, output, *, img4, limit, expected_type=None):
    typ, payload = im4p_payload(data)
    if expected_type is not None and typ != expected_type:
        raise FirmwareError(f"Image4 type {typ!r} does not match selected component {expected_type!r}")
    compressed = payload.startswith((b"bvx", b"complzss"))
    if not compressed:
        if len(payload) > limit:
            raise FirmwareError("decoded payload exceeds disk budget")
        exclusive_write(output, payload)
        return typ, digest(payload), "IM4P octet extraction; no modifications"
    if not img4:
        raise FirmwareError("compressed payload needs an existing --img4-tool executable")
    if output.exists() or output.is_symlink():
        raise FirmwareError("refusing to replace an existing derived file")

    def bounds():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_AS, (1024 * MIB, 1024 * MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (45, 45))

    # Ordinary decode only: no -k/-D/-P or any ticket/security operations.
    try:
        result = subprocess.run([img4, "-i", str(original), "-o", str(output)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=60, preexec_fn=bounds)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    if result.returncode or not output.is_file() or output.stat().st_size > limit:
        output.unlink(missing_ok=True)
        raise FirmwareError(f"Image4 decompression failed (exit {result.returncode})")
    decoded = output.read_bytes()
    if not decoded or decoded.startswith((b"bvx", b"complzss")):
        output.unlink(missing_ok=True)
        raise FirmwareError("Image4 decoder did not produce an uncompressed payload")
    return typ, digest(decoded), "img4 -i ORIGINAL -o DERIVED; decode only"


def prepare(source, output, *, product, board, version=None, build=None,
            variant=None, inspect_only=False, img4=None, limit=DEFAULT_LIMIT, timeout=15):
    if not 0 < limit <= DEFAULT_LIMIT or not math.isfinite(timeout) or not 0 < timeout <= 120:
        raise FirmwareError("resource limit must be between 1 byte and 300 MiB")
    # Reserve space for a bounded failure/success report even if payload output
    # consumes its allowance. The limit covers all file contents, not just images.
    data_limit = limit - MAX_REPORT
    if data_limit <= 0:
        raise FirmwareError("disk budget must include 1 MiB reserved for provenance")
    out = Path(output)
    if out.exists() or out.is_symlink():
        raise FirmwareError("output directory must be new; existing firmware is never overwritten")
    report = {"schema": 1, "source": source, "requested_product": product,
              "requested_board": board, "inspect_only": inspect_only,
              "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "security_changes": [], "artifacts": [], "status": "started"}
    with open_archive(source, limit=limit, timeout=timeout) as (zf, reader, archive_size):
        raw_manifest = read_member(zf, "BuildManifest.plist", MAX_METADATA)
        try:
            manifest = plistlib.loads(raw_manifest)
        except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
            raise FirmwareError("invalid BuildManifest plist") from exc
        identity, components = select_identity(manifest, product=product, board=board,
                                               version=version, build=build, variant=variant)
        report.update({"archive_size": archive_size,
                       "product_version": manifest.get("ProductVersion"),
                       "product_build": manifest.get("ProductBuildVersion"),
                       "identity": {"DeviceClass": identity.get("Info", {}).get("DeviceClass"),
                                    "Variant": identity.get("Info", {}).get("Variant"),
                                    "RestoreBehavior": identity.get("Info", {}).get("RestoreBehavior"),
                                    "ApChipID": identity.get("ApChipID"),
                                    "ApBoardID": identity.get("ApBoardID")},
                       "build_manifest": digest(raw_manifest), "selected": {}})
        for name, component in components.items():
            member = zf.getinfo(component["member"])
            if member.file_size > 128 * MIB:
                raise FirmwareError("selected boot component exceeds 128 MiB bound")
            report["selected"][name] = {**component, "zip_size": member.file_size,
                                         "compressed_size": member.compress_size,
                                         "crc32": f"{member.CRC:08x}"}
        planned_originals = 0 if inspect_only else sum(x["zip_size"] for x in report["selected"].values())
        if planned_originals + len(raw_manifest) > data_limit:
            raise FirmwareError("selected originals exceed disk budget")
        if len(json.dumps(report).encode()) > MAX_REPORT // 2:
            raise FirmwareError("identity metadata exceeds provenance budget")
        out.mkdir(parents=True, mode=0o700)
        exclusive_write(out / "BuildManifest.plist", raw_manifest)
        disk_used = len(raw_manifest)
        try:
            if not inspect_only:
                (out / "original").mkdir(mode=0o700)
                (out / "derived").mkdir(mode=0o700)
                for name, component in components.items():
                    raw = read_member(zf, component["member"], min(128 * MIB, data_limit - disk_used))
                    original = out / "original" / (name + ".im4p")
                    derived = out / "derived" / name
                    exclusive_write(original, raw)
                    disk_used += len(raw)
                    record = {"component": name, "member": component["member"],
                              "original": {"path": str(original), **digest(raw)}}
                    report["artifacts"].append(record)
                    typ, derived_digest, operation = extract_payload(raw, original, derived,
                                                  img4=img4, limit=data_limit - disk_used,
                                                  expected_type=IMAGE4_TYPES[name])
                    record["derived"] = {"path": str(derived), **derived_digest}
                    record["image4_type"] = typ
                    record["operation"] = operation
                    disk_used += derived_digest["size"]
            report["status"] = "inspected" if inspect_only else "prepared-unmodified"
        except BaseException as exc:
            report["status"] = "incomplete"
            report["error"] = str(exc)
            raise
        finally:
            report["artifact_bytes"] = disk_used
            report["disk_bytes"] = disk_used
            if isinstance(reader, RangeReader):
                report["http"] = {"etag": reader.etag, "last_modified": reader.modified,
                                  "transferred_bytes": reader.transferred,
                                  "ranges": reader.requests}
            # The serialized size changes when its own total gains a digit.
            # Iteration stabilizes the total before publishing the new file.
            for _ in range(8):
                report_data = (json.dumps(report, indent=2) + "\n").encode()
                total = disk_used + len(report_data)
                if report["disk_bytes"] == total:
                    break
                report["disk_bytes"] = total
            if len(report_data) > MAX_REPORT or total > limit:
                raise FirmwareError("provenance exceeds disk budget")
            exclusive_write(out / "provenance.json", report_data)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="local IPSW path or HTTP(S) URL")
    parser.add_argument("--output", required=True, help="new private output directory")
    parser.add_argument("--product", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version")
    parser.add_argument("--build")
    parser.add_argument("--variant")
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--img4-tool", help="existing Image4 decoder; no keys or patch operations")
    parser.add_argument("--limit-mib", type=int, default=300)
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    try:
        report = prepare(args.source, args.output, product=args.product, board=args.board,
                         version=args.version, build=args.build, variant=args.variant,
                         inspect_only=args.inspect_only, img4=args.img4_tool,
                         limit=args.limit_mib * MIB, timeout=args.timeout)
    except (FirmwareError, OSError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"firmware preparation failed: {exc}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
