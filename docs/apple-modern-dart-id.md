# Loader-generated `dart-id` (`adt-dart-ids`)

SPTM's `t8110dart_bootstrap_instance` panics (`error -1 getting dart-id`) for a
`dart,t8110` node without a `dart-id` property, and none of the 25 such nodes in
the stock iPhone17,3 tree carries one. `apple-modern,adt-dart-ids=on` makes the
metadata loader give every node whose `compatible` list contains `dart,t8110`
a four-byte `dart-id`: 0, 1, 2, ... in ADT order (depth-first, as the nodes
appear in the blob). A `dart-id` the input already carries is replaced; nothing
else in the tree changes. Default off.

* **Attested (measured).** The SPTM panic above and the absence of `dart-id`
  in the stock tree (`features-20261008/sep-review`).
* **Analogy.** Cody Ho's SPTM DART notes call it the logical DART object id that
  every SPTM DART endpoint takes in `x0`, so it must be unique. The
  Darwin-VM/MaliosDark `dt_fixup.py` numbers DARTs in tree order.
* **Declared.** iBoot numbering is not measured; ADT order from zero is assumed.

The numbering is relative to the nodes that keep `dart,t8110` in the input. On
the stock tree dart-sep is 2 and dart-sio is 3. On a tree that restores only
dart-sep it is 0, which is the value the SEP work has always declared there, so
the served tree for that existing tree is byte-identical with or without the
option. A tree with no `dart,t8110` node (the Darwin-derived trees strip every
DART compatible) is refused at startup rather than silently ignored, and an ADT
override naming `dart-id` is refused while ids are generated.

```sh
python3 scripts/test-apple-modern-dart-id.py --components /path/to/derived
python3 scripts/test-apple-modern-dart-id-qemu.py --binary /pinned/qemu \
  --components /path/to/derived --output-dir /new/dir \
  --served-tree /path/to/darwin/dtree --sep-tree /path/to/dart-sep/dtree \
  --previous-binary /older/qemu
```

The core test flattens whole trees with an independent reader and requires the
generated tree to equal the plain build except for one extra id per dart node,
on synthetic edge cases (second list entry, no terminating NUL, longer and
shorter strings, an existing 8-byte id, a nested node, a node at the
4096-property limit) and on the real stock tree (25 nodes, ids 0..24). It
rejects twelve deliberately broken variants of the loader. The machine gate
reads the served ADT back from guest RAM.
