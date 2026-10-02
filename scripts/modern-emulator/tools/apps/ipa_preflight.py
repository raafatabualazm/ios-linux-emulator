#!/usr/bin/env python3
"""Validate and optionally stage an owned device IPA without installing it.

Uses only the Python standard library; OpenSSL is optional for safe provisioning
metadata. Never extracts archive members into a filesystem, modifies signing,
opens a device connection, or treats staging as guest registration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from xml.parsers.expat import ExpatError


class PreflightError(ValueError):
    """The archive or selected target fails a required preflight check."""


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 256 * 1024 * 1024
    uncompressed_bytes: int = 512 * 1024 * 1024
    member_bytes: int = 128 * 1024 * 1024
    entries: int = 20000
    plist_bytes: int = 2 * 1024 * 1024
    profile_bytes: int = 8 * 1024 * 1024


@dataclass
class InspectedIPA:
    report: dict
    # Original inner IPA bytes, preserved exactly, including existing signatures.
    ipa: bytes


MACH_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
               b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
               b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
               b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
CPU_NAMES = {12: "arm", 0x0100000C: "arm64", 7: "i386", 0x01000007: "x86_64"}
PLATFORM_NAMES = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS",
                  6: "MacCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator",
                  9: "watchOSSimulator"}


def version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value):
        raise PreflightError("OS version must have one to three decimal components")
    parts = tuple(int(v) for v in value.split("."))
    if any(v > 65535 for v in parts):
        raise PreflightError("OS version component is out of range")
    return parts + (0,) * (3 - len(parts))


def encoded_version(value: int) -> str:
    return ".".join(str(v) for v in (value >> 16, (value >> 8) & 255, value & 255))


def _safe_name(info: zipfile.ZipInfo) -> str:
    # ZipInfo truncates filename at NUL; check orig_filename as well.
    name = info.orig_filename
    if not name or "\x00" in name or "\\" in name or ":" in name:
        raise PreflightError("archive contains an unsafe member name")
    if name.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise PreflightError("archive contains an absolute or control-character member name")
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise PreflightError("archive contains an ambiguous or traversing member path")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise PreflightError("archive contains a symlink or special file")
    if kind == stat.S_IFDIR and not info.is_dir():
        raise PreflightError("archive directory metadata disagrees with its name")
    if info.is_dir() and kind == stat.S_IFREG:
        raise PreflightError("archive file metadata disagrees with its directory name")
    if info.flag_bits & 1:
        raise PreflightError("encrypted ZIP members are unsupported")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise PreflightError("unsupported ZIP compression method")
    return name


def _validated_zip(data: bytes, limits: Limits, budget: list[int]) -> tuple[zipfile.ZipFile, dict[str, zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise PreflightError("invalid ZIP archive") from exc
    entries = archive.infolist()
    if len(entries) > limits.entries:
        archive.close()
        raise PreflightError("ZIP entry count exceeds the configured limit")
    names: dict[str, zipfile.ZipInfo] = {}
    canonical: set[str] = set()
    try:
        for entry in entries:
            name = _safe_name(entry)
            # iOS filesystems commonly ignore case. Reject aliases before choosing
            # a bundle, rather than allowing an installer to choose another file.
            key = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
            if key in canonical:
                raise PreflightError("archive contains duplicate or case/Unicode-colliding paths")
            canonical.add(key)
            if entry.file_size > limits.member_bytes:
                raise PreflightError("ZIP member exceeds the configured size limit")
            budget[0] += entry.file_size
            if budget[0] > limits.uncompressed_bytes:
                raise PreflightError("combined uncompressed ZIP size exceeds the configured limit")
            names[name] = entry
        # Reject file-versus-directory prefix collisions, including implicit dirs.
        file_keys = {unicodedata.normalize("NFC", n).casefold() for n in names if not n.endswith("/")}
        for name in names:
            pieces = name.rstrip("/").split("/")
            for length in range(1, len(pieces)):
                parent = unicodedata.normalize("NFC", "/".join(pieces[:length])).casefold()
                if parent in file_keys:
                    raise PreflightError("archive file collides with a parent directory")
        # Stream every member to validate CRC/truncation without unbounded reads.
        for name, entry in names.items():
            count = 0
            with archive.open(entry) as member:
                while chunk := member.read(1024 * 1024):
                    count += len(chunk)
                    if count > limits.member_bytes or count > entry.file_size:
                        raise PreflightError("ZIP member expands beyond its declared or allowed size")
            if count != entry.file_size:
                raise PreflightError("ZIP member has a truncated payload")
        return archive, names
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, ValueError, zlib.error) as exc:
        archive.close()
        if isinstance(exc, PreflightError):
            raise
        raise PreflightError("ZIP payload integrity validation failed") from exc


def _read(archive: zipfile.ZipFile, names: dict, name: str, limit: int) -> bytes:
    if name not in names or names[name].is_dir():
        raise PreflightError("bundle executable or metadata is missing")
    if names[name].file_size > limit:
        raise PreflightError("bundle metadata or executable exceeds its size limit")
    return archive.read(names[name])


def _plist(archive: zipfile.ZipFile, names: dict, name: str, limits: Limits) -> dict:
    try:
        value = plistlib.loads(_read(archive, names, name, limits.plist_bytes))
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, ExpatError) as exc:
        raise PreflightError("invalid bundle Info.plist") from exc
    if not isinstance(value, dict):
        raise PreflightError("bundle Info.plist is not a dictionary")
    return value


def _thin_macho(data: bytes) -> dict:
    layouts = {b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False),
               b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True)}
    if data[:4] not in layouts:
        raise PreflightError("fat Mach-O contains a non-Mach-O slice")
    endian, is64 = layouts[data[:4]]
    header_size = 32 if is64 else 28
    if len(data) < header_size:
        raise PreflightError("truncated Mach-O header")
    cpu, subtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "6I", data, 4)
    if bool(cpu & 0x01000000) != is64:
        raise PreflightError("Mach-O CPU ABI disagrees with its 32/64-bit header")
    if ncmds > 65536 or sizeofcmds > len(data) - header_size:
        raise PreflightError("Mach-O load-command bounds are invalid")
    arch = CPU_NAMES.get(cpu, f"cpu-{cpu}")
    if cpu == 0x0100000C:
        arm_subtype = subtype & 0xFFFFFF
        if arm_subtype == 2:
            arch = "arm64e"
        elif arm_subtype not in (0, 1):
            arch = f"arm64-subtype-{arm_subtype}"
    result = {"architecture": arch, "cpu_type": cpu, "cpu_subtype": subtype,
              "file_type": filetype, "platform": None, "minimum_os": None,
              "sdk": None, "encryption_records": [], "code_signature_present": False}
    offset = header_size
    end = header_size + sizeofcmds
    version_records = []
    for _ in range(ncmds):
        if offset + 8 > end:
            raise PreflightError("truncated Mach-O load command")
        command, size = struct.unpack_from(endian + "2I", data, offset)
        if size < 8 or size % (8 if is64 else 4) or offset + size > end:
            raise PreflightError("Mach-O load-command size is invalid")
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise PreflightError("truncated Mach-O build-version command")
            platform, minimum, sdk, ntools = struct.unpack_from(endian + "4I", data, offset + 8)
            if 24 + 8 * ntools != size:
                raise PreflightError("Mach-O build-version tool records are invalid")
            version_records.append((PLATFORM_NAMES.get(platform, f"platform-{platform}"), minimum, sdk))
        elif command in (0x24, 0x25, 0x2F, 0x30):  # legacy minimum-version commands
            if size != 16:
                raise PreflightError("invalid Mach-O minimum-version command")
            minimum, sdk = struct.unpack_from(endian + "2I", data, offset + 8)
            platform = {0x24: "macOS", 0x25: "iOS", 0x2F: "tvOS", 0x30: "watchOS"}[command]
            if platform == "iOS" and arch in ("i386", "x86_64"):
                platform = "iOSSimulator"
            version_records.append((platform, minimum, sdk))
        elif command in (0x21, 0x2C):  # LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
            if size != (24 if command == 0x2C else 20):
                raise PreflightError("invalid Mach-O encryption command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "3I", data, offset + 8)
            if cryptoff > len(data) or cryptsize > len(data) - cryptoff:
                raise PreflightError("Mach-O encryption range is outside the slice")
            result["encryption_records"].append({"cryptid": cryptid, "offset": cryptoff, "size": cryptsize})
        elif command == 0x1D:  # LC_CODE_SIGNATURE
            if size != 16:
                raise PreflightError("invalid Mach-O code-signature command")
            sigoff, sigsize = struct.unpack_from(endian + "2I", data, offset + 8)
            if sigoff > len(data) or sigsize > len(data) - sigoff:
                raise PreflightError("Mach-O code signature is outside the slice")
            result["code_signature_present"] = sigsize > 0
        offset += size
    if offset != end:
        raise PreflightError("Mach-O load-command count and size disagree")
    if not version_records:
        raise PreflightError("Mach-O has no platform/minimum-OS record")
    if len(set(version_records)) != 1:
        raise PreflightError("Mach-O contains conflicting platform/minimum-OS records")
    platform, minimum, sdk = version_records[0]
    result.update(platform=platform, minimum_os=encoded_version(minimum), sdk=encoded_version(sdk))
    return result


def macho_slices(data: bytes) -> list[dict]:
    magic = data[:4]
    fat = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
           b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}
    if magic not in fat:
        return [_thin_macho(data)]
    if len(data) < 8:
        raise PreflightError("truncated fat Mach-O header")
    endian, is64 = fat[magic]
    count, = struct.unpack_from(endian + "I", data, 4)
    record_size = 32 if is64 else 20
    table_end = 8 + count * record_size
    if not 1 <= count <= 64 or table_end > len(data):
        raise PreflightError("fat Mach-O slice table is invalid")
    ranges = []
    slices = []
    for index in range(count):
        position = 8 + index * record_size
        cpu, subtype = struct.unpack_from(endian + "2I", data, position)
        if is64:
            offset, size, align, reserved = struct.unpack_from(endian + "2Q2I", data, position + 8)
            if reserved:
                raise PreflightError("fat Mach-O reserved field is nonzero")
        else:
            offset, size, align = struct.unpack_from(endian + "3I", data, position + 8)
        if align > 31 or offset < table_end or offset % (1 << align) or size < 28 or offset > len(data) or size > len(data) - offset:
            raise PreflightError("fat Mach-O slice bounds/alignment are invalid")
        if any(offset < right and left < offset + size for left, right in ranges):
            raise PreflightError("fat Mach-O slices overlap")
        ranges.append((offset, offset + size))
        parsed = _thin_macho(data[offset:offset + size])
        if parsed["cpu_type"] != cpu or parsed["cpu_subtype"] != subtype:
            raise PreflightError("fat and thin Mach-O architecture records disagree")
        slices.append(parsed)
    return slices


def _target_slices(slices: list[dict], architecture: str, guest_os: tuple, path: str) -> list[dict]:
    allowed = {architecture}
    if architecture == "arm64e":
        allowed.add("arm64")
    matching = [s for s in slices if s["architecture"] in allowed and s["platform"] == "iOS"]
    if not matching:
        raise PreflightError(f"{path}: no compatible physical-iOS {architecture} slice")
    for item in matching:
        if version(item["minimum_os"]) > guest_os:
            raise PreflightError(f"{path}: Mach-O minimum OS exceeds the guest OS")
        if any(r["cryptid"] != 0 for r in item["encryption_records"]):
            raise PreflightError(f"{path}: encrypted target Mach-O slice is unsupported")
    return matching


def _safe_profile_metadata(data: bytes, now: dt.datetime) -> dict:
    # Only extract public installation constraints. Never serialize the plist,
    # names, team IDs, device identifiers, certificates, or entitlements.
    result = {"present": True, "expiry": None, "profile_type": "unknown", "udid_count": None}
    openssl = shutil.which("openssl")
    if not openssl:
        return result
    try:
        decoded = subprocess.run([openssl, "cms", "-verify", "-noverify", "-inform", "DER"],
                                 input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=8, check=False)
        if decoded.returncode or len(decoded.stdout) > 8 * 1024 * 1024:
            return result
        profile = plistlib.loads(decoded.stdout)
        if not isinstance(profile, dict):
            return result
        expiry = profile.get("ExpirationDate")
        if isinstance(expiry, dt.datetime):
            expiry = expiry.replace(tzinfo=dt.timezone.utc) if expiry.tzinfo is None else expiry.astimezone(dt.timezone.utc)
            result["expiry"] = expiry.isoformat().replace("+00:00", "Z")
            result["expired"] = expiry <= now
        devices = profile.get("ProvisionedDevices")
        result["udid_count"] = len(devices) if isinstance(devices, list) else 0
        entitlements = profile.get("Entitlements", {})
        if not isinstance(entitlements, dict):
            entitlements = {}
        result["profile_type"] = ("enterprise" if profile.get("ProvisionsAllDevices") is True
                                  else "development" if entitlements.get("get-task-allow") is True
                                  else "ad-hoc" if isinstance(devices, list) and devices
                                  else "app-store")
    except (subprocess.TimeoutExpired, OSError, ValueError, plistlib.InvalidFileException, OverflowError, ExpatError):
        pass
    return result


def inspect_ipa(source: Path | str, guest_ios: str, architecture: str = "arm64", device_family: int = 1,
                limits: Limits | None = None, now: dt.datetime | None = None) -> InspectedIPA:
    limits = limits or Limits()
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    guest = version(guest_ios)
    if architecture not in ("arm64", "arm64e") or device_family not in (1, 2):
        raise PreflightError("unsupported target architecture or device family")
    source = Path(source)
    with source.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limits.archive_bytes:
            raise PreflightError("input is not a regular file within the archive size limit")
        outer_data = handle.read(limits.archive_bytes + 1)
        after = os.fstat(handle.fileno())
    if len(outer_data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise PreflightError("input changed while it was being inspected")
    budget = [0]
    outer, outer_names = _validated_zip(outer_data, limits, budget)
    with outer:
        root_plists = [n for n in outer_names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if root_plists:
            ipa_data = outer_data
            wrapper_name = None
        else:
            candidates = [n for n in outer_names if not n.startswith("__MACOSX/") and n.lower().endswith(".ipa") and not outer_names[n].is_dir()]
            if len(candidates) != 1:
                raise PreflightError("wrapper must contain exactly one non-metadata IPA")
            wrapper_name = candidates[0]
            ipa_data = _read(outer, outer_names, wrapper_name, limits.archive_bytes)
    if len(ipa_data) > limits.archive_bytes:
        raise PreflightError("inner IPA exceeds the archive size limit")
    # Direct IPAs were already fully validated: avoid double-counting their size.
    if wrapper_name is None:
        budget[0] = 0
    archive, names = _validated_zip(ipa_data, limits, budget)
    with archive:
        roots = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if len(roots) != 1:
            raise PreflightError("IPA must contain exactly one root app bundle")
        root_info = roots[0]
        app_root = root_info.rsplit("/", 1)[0]
        unexpected_payload = [n for n in names if n.startswith("Payload/") and n != "Payload/" and not (n == app_root + "/" or n.startswith(app_root + "/"))]
        if unexpected_payload:
            raise PreflightError("IPA Payload contains files outside its single root app")
        root = _plist(archive, names, root_info, limits)
        bundle_id = root.get("CFBundleIdentifier")
        if not isinstance(bundle_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", bundle_id):
            raise PreflightError("root app has an invalid bundle identifier")
        bundles = []
        required_binaries = set()
        binary_roles = {}
        for name in sorted(names):
            if not re.fullmatch(re.escape(app_root) + r"(?:/.*)?/(?:Info\.plist)", name):
                continue
            directory = name.rsplit("/", 1)[0]
            if not directory.endswith((".app", ".appex", ".framework")):
                continue
            info = root if name == root_info else _plist(archive, names, name, limits)
            minimum = info.get("MinimumOSVersion")
            if minimum is None and directory.endswith(".framework"):
                minimum = None  # Mach-O deployment record remains mandatory.
            elif version(minimum) > guest:
                raise PreflightError(f"{name}: Info.plist minimum OS exceeds the guest OS")
            platforms = info.get("CFBundleSupportedPlatforms")
            if platforms is not None and (not isinstance(platforms, list) or "iPhoneOS" not in platforms or any(p != "iPhoneOS" for p in platforms)):
                raise PreflightError(f"{name}: bundle is not for physical iPhoneOS")
            platform_name = info.get("DTPlatformName")
            if platform_name is not None and platform_name != "iphoneos":
                raise PreflightError(f"{name}: bundle build platform is not physical iOS")
            families = info.get("UIDeviceFamily")
            if families is not None and (not isinstance(families, list) or
                                         not all(type(f) is int and f in (1, 2) for f in families) or
                                         device_family not in families):
                raise PreflightError(f"{name}: bundle does not support the selected device family")
            executable = info.get("CFBundleExecutable")
            if (not isinstance(executable, str) or not executable or executable in (".", "..") or
                    any(c in executable for c in ("/", "\\", ":")) or
                    any(ord(c) < 32 or ord(c) == 127 for c in executable)):
                raise PreflightError(f"{name}: bundle executable name is unsafe or absent")
            binary_path = directory + "/" + executable
            if binary_path not in names or names[binary_path].is_dir():
                raise PreflightError(f"{name}: declared bundle executable is absent")
            required_binaries.add(binary_path)
            binary_roles[binary_path] = "dynamic-library" if directory.endswith(".framework") else "executable"
            capabilities = info.get("UIRequiredDeviceCapabilities", [])
            if not isinstance(capabilities, (list, dict)):
                raise PreflightError(f"{name}: required device capabilities have an invalid shape")
            bundles.append({"path": directory, "minimum_os": minimum,
                            "device_families": families, "required_capabilities": capabilities})
        if app_root + "/" + root.get("CFBundleExecutable", "") not in required_binaries:
            raise PreflightError("root app executable was not found")
        binaries = []
        found = set()
        for name, entry in sorted(names.items()):
            if entry.is_dir():
                continue
            with archive.open(entry) as member:
                magic = member.read(4)
            if magic not in MACH_MAGICS:
                if name in required_binaries:
                    raise PreflightError(f"{name}: declared executable is not Mach-O")
                if name.endswith(".dylib"):
                    raise PreflightError(f"{name}: embedded dynamic library is not Mach-O")
                continue
            slices = macho_slices(_read(archive, names, name, limits.member_bytes))
            selected = _target_slices(slices, architecture, guest, name)
            role = binary_roles.get(name, "dynamic-library" if name.endswith(".dylib") else "embedded-code")
            expected_file_type = {"executable": 2, "dynamic-library": 6}.get(role)
            if expected_file_type is not None and any(s["file_type"] != expected_file_type for s in selected):
                raise PreflightError(f"{name}: Mach-O file type does not match its {role} bundle role")
            found.add(name)
            binaries.append({"path": name, "role": role, "slices": slices,
                             "target_architectures": [s["architecture"] for s in selected]})
        if not required_binaries <= found:
            raise PreflightError("some declared bundle executables lack validated Mach-O code")
        profiles = []
        for name in sorted(names):
            if name.endswith("/embedded.mobileprovision"):
                metadata = _safe_profile_metadata(_read(archive, names, name, limits.profile_bytes), now)
                profiles.append({"path": name, **metadata})
        blockers = ["expired provisioning profile" for p in profiles if p.get("expired")]
        if not profiles:
            blockers.append("no embedded provisioning profile; installation acceptance is unverified")
        if any(not s["code_signature_present"] for b in binaries for s in b["slices"] if s["architecture"] in b["target_architectures"] and s["platform"] == "iOS"):
            blockers.append("one or more selected Mach-O slices have no code-signature record")
        report = {
            "schema_version": 1, "checked_at": now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "preflight-passed", "installed": False, "registered": False, "launched": False,
            "source": {"name": source.name, "bytes": len(outer_data), "sha256": hashlib.sha256(outer_data).hexdigest(),
                       "wrapper_member": wrapper_name},
            "ipa": {"bytes": len(ipa_data), "sha256": hashlib.sha256(ipa_data).hexdigest(),
                    "entry_count": len(names), "combined_uncompressed_bytes": budget[0]},
            "target": {"guest_ios": guest_ios, "architecture": architecture, "device_family": device_family},
            "app": {"bundle_identifier": bundle_id, "display_name": root.get("CFBundleDisplayName"),
                    "version": root.get("CFBundleShortVersionString"), "build": root.get("CFBundleVersion"),
                    "minimum_os": root.get("MinimumOSVersion")},
            "bundles": bundles, "mach_o": binaries, "provisioning": profiles,
            "installation_gate": {"status": "blocked" if blockers else "unverified", "blockers": sorted(set(blockers)),
                                  "signature_validity": "not-verified", "profile_trust_and_device_membership": "not-verified",
                                  "capability_and_runtime_support": "not-verified"},
            "limitations": ["Metadata compatibility does not establish runtime API or framework availability.",
                            "CMS metadata extraction does not validate Apple's certificate chain or guest acceptance.",
                            "Installation, guest registration, SpringBoard launch, rendering, input and persistence require separate evidence."],
        }
    return InspectedIPA(report, ipa_data)


def stage_ipa(inspected: InspectedIPA, destination: Path | str) -> dict:
    """Publish the exact checked IPA into a new private directory, no extraction."""
    if (inspected.report.get("status") != "preflight-passed" or
            inspected.report.get("ipa", {}).get("sha256") != hashlib.sha256(inspected.ipa).hexdigest() or
            inspected.report.get("ipa", {}).get("bytes") != len(inspected.ipa)):
        raise PreflightError("staging payload no longer matches its successful preflight report")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the destination exclusively so a previous stage cannot be replaced.
    destination.mkdir(mode=0o700)
    try:
        ipa_path = destination / "application.ipa"
        with ipa_path.open("xb") as handle:
            handle.write(inspected.ipa)
            handle.flush()
            os.fsync(handle.fileno())
        ipa_path.chmod(0o600)
        report = {**inspected.report, "status": "staged-not-installed",
                  "stage": {"directory": str(destination.resolve()), "ipa_filename": "application.ipa"}}
        with (destination / "preflight.json").open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        (destination / "preflight.json").chmod(0o600)
        return report
    except Exception:
        for name in ("application.ipa", "preflight.json"):
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="owned .ipa or ZIP containing exactly one .ipa")
    parser.add_argument("--guest-ios", required=True, help="guest OS version, e.g. 14.0")
    parser.add_argument("--architecture", choices=("arm64", "arm64e"), default="arm64")
    parser.add_argument("--device-family", type=int, choices=(1, 2), default=1, help="1=iPhone, 2=iPad")
    parser.add_argument("--stage-dir", type=Path, help="new directory for unchanged IPA and report; never installs")
    parser.add_argument("--report", type=Path, help="write safe JSON metadata here (stdout always receives JSON)")
    parser.add_argument("--max-uncompressed-bytes", type=int, default=Limits.uncompressed_bytes)
    args = parser.parse_args(argv)
    if args.max_uncompressed_bytes <= 0:
        parser.error("--max-uncompressed-bytes must be positive")
    try:
        inspected = inspect_ipa(args.archive, args.guest_ios, args.architecture, args.device_family,
                                Limits(uncompressed_bytes=args.max_uncompressed_bytes))
        report = stage_ipa(inspected, args.stage_dir) if args.stage_dir else inspected.report
        code = 0
    except (PreflightError, OSError) as exc:
        report = {"schema_version": 1, "status": "rejected", "installed": False,
                  "registered": False, "launched": False, "reason": str(exc)}
        code = 2
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x", encoding="utf-8") as handle:
            handle.write(output)
    print(output, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
