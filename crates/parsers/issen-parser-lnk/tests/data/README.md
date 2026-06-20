# issen-parser-lnk test fixtures

#### removable_media.lnk
- **Source**: `lnk-forensic` test corpus (SecurityRonin/`h4x0r`), `tests/data/removable_media.lnk`.
- **Provenance**: spec-exact, hand-authored byte-for-byte per [MS-SHLLINK] (a macOS host
  cannot author a real Windows Shell Link); validated by `lnk-core`'s own tests.
- **MD5**: `ba3dbe2429bdfa93d8a0a9be80ca0fbe`
- **Contents**: a `.lnk` targeting `E:\payload.exe` on a REMOVABLE volume
  "KINGSTON USB" (drive serial `0xDEADBEEF`) — exercises the target-path + USB-origin
  fields the wrapper must surface.
- **Used by**: `tests/depth.rs` (the LNK parser-depth regression).

#### network_share.lnk
- **Source**: `lnk-forensic` test corpus (SecurityRonin/`h4x0r`), `tests/data/network_share.lnk`.
- **Provenance**: SYNTHETIC, spec-exact hand-authored per [MS-SHLLINK] (a macOS host
  cannot author a real Windows Shell Link); validated by `lnk-core`'s own tests.
- **MD5**: `547e0d2686e6652d8d144fb1b767bf9a`
- **Contents**: a `.lnk` whose `LinkInfo` carries a `CommonNetworkRelativeLink`
  (`NetName = \\SERVER\share`, `DeviceName = Z:`) — exercises the UNC network-share
  origin (lateral-movement join key) the wrapper must surface.
- **Used by**: `tests/depth.rs` (the LNK parser-depth regression).

Cross-reference: [`issen/docs/corpus-catalog.md`](../../../../../docs/corpus-catalog.md).
