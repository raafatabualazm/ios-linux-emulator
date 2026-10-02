# Owned IPA preflight and staging

`ipa_preflight.py` accepts a device IPA or a ZIP containing exactly one IPA,
ignoring `__MACOSX` metadata when choosing that inner IPA. It uses Python's
standard library and optionally OpenSSL for a small provisioning summary.

```sh
python3 modern-emulator/tools/apps/ipa_preflight.py ECardsAndKeys.ipa.zip \
  --guest-ios 14.0 --architecture arm64 --device-family 1

python3 modern-emulator/tools/apps/ipa_preflight.py ECardsAndKeys.ipa.zip \
  --guest-ios 14.0 --stage-dir /tmp/owned-ipa-stage

python3 -m unittest discover -s modern-emulator/tests/apps -p 'test*.py' -v
```

The staging destination must be new. It contains `application.ipa`, with the
exact checked inner-IPA bytes, and a safe JSON report. Staging checks the hash
again, preserves existing signing bytes, and never extracts the app into the
guest. Every result explicitly records `installed`, `registered` and `launched`
as false. `preflight-passed` means the archive and target metadata passed;
`installation_gate` separately reports signing blockers or unverified checks.

Checks include archive paths, symlinks/special files, duplicate and case/Unicode
aliases, parent/file collisions, CRC/DEFLATE integrity, declared and actual
uncompressed size, bundle device family and minimum OS, all embedded Mach-O
slices, platform/ABI, deployment version, encryption records, command bounds,
and main/extension/framework/dylib file roles. Extra architectures are allowed
when the selected physical-iOS target is present and compatible. An arm64 guest
does not accept a binary supplying only arm64e or simulator slices.

Defaults bound each input archive to 256 MiB, each member to 128 MiB, combined
wrapper-plus-IPA uncompressed contents to 512 MiB, and each archive to 20,000
entries. Info.plists are bounded to 2 MiB and profiles to 8 MiB. These limits
intentionally reject larger or unsupported archives rather than claiming broad
IPA support. Only stored and DEFLATE ZIP compression are accepted.

Provisioning output contains only expiry, profile type and device-count
metadata. Profile names, team/certificate identities and device identifiers are
never written. OpenSSL's CMS metadata extraction does not verify Apple's trust
chain or the app's code signature, so signature validity and guest acceptance
remain unverified even when profile metadata decodes.

## Uploaded-app result

`ECardsAndKeys.ipa.zip` supplies `com.ecrads.ECardsAndKeys`, iOS 14.0 minimum,
with one physical-arm64 executable and ten compatible embedded dynamic
libraries. Its development profile expired **2025-12-25T18:24:44Z** and lists
five provisioned devices. On 2026-10-02 this is an installation blocker. An
updated, legitimately signed app/profile valid for the target device is needed.
Signature-record presence is not proof of signature validity.

The unchanged inner IPA SHA-256 is
`c1cf999d3a574fa60dbb546a49eee90812fb0ea4982f4123c8bf0bf60f28ec1d`.
Safe review evidence is under `modern-emulator/evidence/apps-20261002/`,
including `reviewed-stage.json`, `review-summary.json`, and `review-tests.txt`.

## Installation and GUI launch gate

Use the normal guest installation service after Setup Assistant, trust/pairing,
and signing requirements are satisfied. The existing Linux USB companion is a
possible transport because the phone exposes USBMux; normal-mode lockdown and
installation services have not been verified in this review. The saved restore
launcher invokes `idevicerestore` and cannot serve as an IPA install command.
The companion must use disposable state for the installation experiment.

Inside the running companion, inspect tool availability and syntax first:

```sh
command -v usbmuxd idevice_id idevicepair ideviceinfo ideviceinstaller
ideviceinstaller --help
idevice_id -l
idevicepair -u "$PHONE_UDID" validate
ideviceinfo -u "$PHONE_UDID" -k ProductVersion
```

Choose the syntax actually reported by that companion's tool version. The
current upstream command is:

```sh
ideviceinstaller -u "$PHONE_UDID" install /tmp/owned-ipa-stage/application.ipa
ideviceinstaller -u "$PHONE_UDID" list
```

Older distribution versions use:

```sh
ideviceinstaller -u "$PHONE_UDID" -i /tmp/owned-ipa-stage/application.ipa
ideviceinstaller -u "$PHONE_UDID" -l
```

The install return code and an independent installed-app list containing the
bundle identifier are necessary installation/registration evidence. Preserve
the specific service error if installation fails. Complete the GUI launch gate
by tapping the registered app's SpringBoard icon and observing the app's first
screen; exercise a meaningful interaction, quit/relaunch, and data persistence.
Installing or staging alone does not establish any of those runtime results.

`idevicedebug run BUNDLEID` is an optional developer-service route. Upstream
requires a mounted matching DeveloperDiskImage when debugserver is unavailable;
the profile and guest must also permit development/debugging. It is not a
general replacement for the SpringBoard launch gate.

Primary references: [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller)
and [idevicedebug source](https://github.com/libimobiledevice/libimobiledevice/blob/master/tools/idevicedebug.c).
