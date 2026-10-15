#!/usr/bin/env python3
"""Inventory matched IPSW system payloads without extracting image contents.

Accepts a saved BuildManifest.plist, a local IPSW, or an HTTP-range IPSW URL.
Reports system, cryptex, restore and metadata members separately. No firmware
keys, signing tickets, decryption, or image preparation is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import urllib.parse

from prepare_firmware import (DEFAULT_LIMIT, MAX_METADATA, MAX_REPORT, MIB, FirmwareError,
                              RangeReader, checked_name, exclusive_write,
                              open_archive, read_member)


ROLES = {
    "OS": "system-payload",
    "Cryptex1,SystemOS": "system-cryptex",
    "Cryptex1,AppOS": "app-cryptex",
    "RestoreRamDisk": "restore-ramdisk",
    "RecoveryMode": "recovery-image",
    "SystemVolume": "system-volume-metadata",
    "SystemVolumeCanonicalMetadata": "system-volume-metadata",
    "StaticTrustCache": "system-trustcache-metadata",
    "RestoreTrustCache": "restore-trustcache-metadata",
    "KernelCache": "kernelcache",
    "RestoreKernelCache": "restore-kernelcache",
    "Ap,SecurePageTableMonitor": "sptm",
    "Ap,TrustedExecutionMonitor": "txm",
}
INFO_FIELDS = ("DeviceClass", "Variant", "RestoreBehavior", "ContentEncoding",
               "MinimumSystemPartition", "OSDiskImageSize", "OSVarContentSize",
               "Cryptex1,SystemOSSize", "Cryptex1,AppOSSize")


def local_candidates(member: str, roots: list[Path]) -> list[dict]:
    """Report files at the original member path or flat basename in chosen roots."""
    present = []
    seen = set()
    for root in roots:
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise FirmwareError("local search root is not a directory")
        for candidate in (root / member, root / Path(member).name):
            resolved = candidate.resolve()
            # A compatibility link may leave this explicit search root. Avoid
            # reading arbitrary linked paths while making an inventory.
            if not resolved.is_relative_to(root) or resolved in seen:
                continue
            seen.add(resolved)
            if resolved.is_file():
                present.append({"path": str(resolved),
                                "size": resolved.stat().st_size})
    return present


def describe_manifest(data: bytes, *, directory=None, roots=(), product=None,
                      board=None, version=None, build=None) -> dict:
    try:
        manifest = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise FirmwareError("invalid BuildManifest plist") from exc
    if not isinstance(manifest, dict):
        raise FirmwareError("BuildManifest is not a dictionary")
    products = manifest.get("SupportedProductTypes")
    identities = manifest.get("BuildIdentities")
    if (not isinstance(products, list) or not all(isinstance(x, str) for x in products)
            or len(products) > 256 or not isinstance(identities, list)
            or len(identities) > 256):
        raise FirmwareError("invalid or excessive products/build identities")
    if product and product not in products:
        raise FirmwareError("requested product does not match BuildManifest")
    if version and version != manifest.get("ProductVersion"):
        raise FirmwareError("requested version does not match BuildManifest")
    if build and build != manifest.get("ProductBuildVersion"):
        raise FirmwareError("requested build does not match BuildManifest")
    result = {
        "product_version": manifest.get("ProductVersion"),
        "product_build": manifest.get("ProductBuildVersion"),
        "supported_products": products,
        "build_manifest_sha256": hashlib.sha256(data).hexdigest(),
        "build_manifest_size": len(data),
        "identities": [],
    }
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict) or not isinstance(identity.get("Info"), dict):
            raise FirmwareError("invalid build identity/info")
        info = identity["Info"]
        device_class = info.get("DeviceClass")
        if not isinstance(device_class, str):
            raise FirmwareError("invalid build identity device class")
        if board and device_class.lower() != board.lower():
            continue
        components = identity.get("Manifest")
        if not isinstance(components, dict):
            raise FirmwareError("invalid component manifest")
        recovery = str(info.get("Variant", "")).startswith("Recovery ")
        item = {"index": index, "chip_id": identity.get("ApChipID"),
                "board_id": identity.get("ApBoardID"),
                "recovery_identity": recovery,
                "info": {k: info[k] for k in INFO_FIELDS if k in info},
                "components": []}
        for key, role in ROLES.items():
            component = components.get(key)
            if component is None:
                continue
            if not isinstance(component, dict) or not isinstance(component.get("Info"), dict):
                raise FirmwareError("invalid selected component/info")
            member = component["Info"].get("Path")
            if not isinstance(member, str):
                raise FirmwareError("selected component has no member path")
            checked_name(member)
            row = {"manifest_key": key,
                   "role": "recovery-system-payload" if recovery and key == "OS" else role,
                   "member": member,
                   "filename_encoding": "aea" if member.endswith(".aea") else None,
                   "archive_member_present": None,
                   "local_candidates": local_candidates(member, list(roots))}
            if directory is not None:
                zipped = directory.get(member)
                row["archive_member_present"] = zipped is not None
                if zipped is not None:
                    row.update({"zip_size": zipped.file_size,
                                "compressed_size": zipped.compress_size,
                                "crc32": f"{zipped.CRC:08x}"})
            item["components"].append(row)
        result["identities"].append(item)
    if not result["identities"]:
        raise FirmwareError("requested board has no build identity")
    return result


def inventory(source: str, *, roots=(), product=None, board=None, version=None,
              build=None, limit=16 * MIB, timeout=15) -> dict:
    if not 0 < limit <= 32 * MIB:
        raise FirmwareError("metadata transfer budget must be at most 32 MiB")
    remote = urllib.parse.urlsplit(source).scheme in ("http", "https")
    args = {"roots": roots, "product": product, "board": board,
            "version": version, "build": build}
    report = {"schema": 1, "source": source,
              "operation": "manifest-and-directory-inventory-only",
              "image_payloads_read": False}
    if not remote and Path(source).suffix.lower() == ".plist":
        with Path(source).open("rb") as stream:
            data = stream.read(MAX_METADATA + 1)
        if len(data) > MAX_METADATA:
            raise FirmwareError("BuildManifest exceeds metadata budget")
        report.update(describe_manifest(data, **args))
        return report
    with open_archive(source, limit=limit, timeout=timeout,
                      maximum_limit=DEFAULT_LIMIT) as (zf, reader, size):
        data = read_member(zf, "BuildManifest.plist", MAX_METADATA)
        directory = {item.filename: item for item in zf.infolist()}
        report.update(describe_manifest(data, directory=directory, **args))
        report.update({"archive_size": size, "archive_member_count": len(directory)})
        if isinstance(reader, RangeReader):
            report["http"] = {"transferred_bytes": reader.transferred,
                              "etag": reader.etag, "last_modified": reader.modified,
                              "ranges": reader.requests}
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="BuildManifest.plist, local IPSW, or IPSW URL")
    parser.add_argument("--product")
    parser.add_argument("--board")
    parser.add_argument("--version")
    parser.add_argument("--build")
    parser.add_argument("--local-root", type=Path, action="append", default=[],
                        help="look for matching member paths or flat basenames here")
    parser.add_argument("--limit-mib", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--output", type=Path,
                        help="write a new report; existing files are never replaced")
    args = parser.parse_args()
    try:
        report = inventory(args.source, roots=args.local_root, product=args.product,
                           board=args.board, version=args.version, build=args.build,
                           limit=args.limit_mib * MIB, timeout=args.timeout)
        data = (json.dumps(report, indent=2) + "\n").encode()
        if len(data) > MAX_REPORT:
            raise FirmwareError("inventory report exceeds 1 MiB budget")
        if args.output:
            exclusive_write(args.output, data)
        else:
            sys.stdout.buffer.write(data)
    except (FirmwareError, OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
