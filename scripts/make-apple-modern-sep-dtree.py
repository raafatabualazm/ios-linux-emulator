#!/usr/bin/env python3
"""Generate a served device tree that keeps the SEP subtree matchable.

Darwin-VM's dt_fixup.py strips `compatible` from every node whose driver the
emulated board does not provide (447 of 451 nodes on this tree). That is why
/arm-io/sep carries no `compatible` in the normal served tree and no SEP driver
can match, so AppleSEPManager never publishes and never prints.

This produces the normal fixed-up tree and then restores exactly the two
`compatible` strings of the SEP subtree, taken from the unmodified stock tree.
Nothing else changes. The result is a DECLARED OPT-IN measurement asset: it
makes the guest match a device the board only partially models, so it is not
the default tree and must not become one until a run shows the boot still
reaches its shell with it.

Both the stock input and the generated output are hashed into the report.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

SEP_PATH = ("arm-io", "sep")
NUB = "iop-sep-nub"


def load_fixup(path):
    spec = importlib.util.spec_from_file_location("dt_fixup", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def node_at(root, parts):
    node = root
    for part in parts:
        node = node[part]
    return node


def compatible_of(tree, fixup, parts, child=None):
    node = node_at(tree, parts)
    if child is not None:
        node = node[child]
    value = node.props.get("compatible")
    if value is None:
        raise SystemExit("stock tree has no compatible at %s" % "/".join(parts))
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", required=True, help="unmodified DeviceTree")
    parser.add_argument("--nvram", required=True)
    parser.add_argument("--dt-fixup", required=True, help="Darwin dt_fixup.py")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    for path in (args.output, args.report):
        if Path(path).exists():
            raise SystemExit("refusing to replace existing %s" % path)

    fixup = load_fixup(args.dt_fixup)
    stock_bytes = Path(args.stock).read_bytes()

    # Read the stock compatible strings before any fixup touches them.
    stock = fixup.ADTNode()
    fixup.decode_node(stock_bytes, stock)
    sep_compatible = compatible_of(stock, fixup, SEP_PATH)
    nub_compatible = compatible_of(stock, fixup, SEP_PATH, NUB)

    # Normal served tree, then restore only those two properties.
    tree = fixup.ADTNode()
    fixup.decode_node(stock_bytes, tree)
    with open(args.nvram, "rb") as nvram:
        fixup.fixup(tree, nvram_file=nvram)
    sep = node_at(tree, SEP_PATH)
    if "compatible" in sep.props or "compatible" in sep[NUB].props:
        raise SystemExit("fixup unexpectedly kept the SEP compatible strings")
    sep.props["compatible"] = sep_compatible
    sep[NUB].props["compatible"] = nub_compatible

    encoded = fixup.encode_node(tree)

    # Round-trip check: exactly the SEP subtree gained a compatible string.
    check = fixup.ADTNode()
    fixup.decode_node(encoded, check)
    if node_at(check, SEP_PATH).props.get("compatible") != sep_compatible:
        raise SystemExit("generated tree lost the SEP compatible string")
    if node_at(check, SEP_PATH)[NUB].props.get("compatible") != nub_compatible:
        raise SystemExit("generated tree lost the nub compatible string")

    plain = fixup.ADTNode()
    fixup.decode_node(stock_bytes, plain)
    with open(args.nvram, "rb") as nvram:
        fixup.fixup(plain, nvram_file=nvram)
    plain_encoded = fixup.encode_node(plain)

    def count_compatible(root):
        total = [0]

        def walk(node):
            total[0] += "compatible" in node.props
            for child in node.children:
                walk(child)

        walk(root)
        return total[0]

    plain_check = fixup.ADTNode()
    fixup.decode_node(plain_encoded, plain_check)
    added = count_compatible(check) - count_compatible(plain_check)
    if added != 2:
        raise SystemExit("expected exactly two restored compatible strings, "
                         "got %d" % added)

    Path(args.output).write_bytes(encoded)
    report = {
        "operation": "sep-matchable-device-tree",
        "declared_opt_in_measurement_asset": True,
        "stock_sha256": hashlib.sha256(stock_bytes).hexdigest(),
        "normal_served_sha256": hashlib.sha256(plain_encoded).hexdigest(),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "output_size": len(encoded),
        "restored": {"/arm-io/sep": sep_compatible,
                     "/arm-io/sep/" + NUB: nub_compatible},
        "restored_property_count": added,
        "guest_visible_deviation_from_darwin_dt_fixup": True,
    }
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
