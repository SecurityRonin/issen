# issen-parser-mft test fixtures

#### dc01_mft_record_74419.bin

Real 1024-byte `$MFT` record (DC01 entry 74419, a WinSxS `settingcontent-ms`)
from DFIR Madness "Stolen Szechuan Sauce" Case 001. MD5 `4c911975cff69016c3095553ed4540c6`.
Full provenance + extraction command: `issen/docs/corpus-catalog.md` §A3e (also
committed in `issen/crates/issen-mft-tree/tests/data/`, the prefetch two-repo pattern).

TSK `istat` oracle: `$SI` Modified `2013-06-18T15:02:18.305856600Z`. Consumed by
`parse_preserves_100ns_si_precision` — guards that the **timeline** ingester keeps
full 100 ns precision (the `mft` crate truncates 100 ns → µs).
