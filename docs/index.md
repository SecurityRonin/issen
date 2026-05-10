# Issen

**Incident response triage — fast, scriptable, forensically sound.**

Issen is an open-source CLI tool for digital forensics and incident response (DFIR) practitioners. It parses artefacts, correlates events, and surfaces indicators of compromise across Windows, Linux, and macOS evidence — from live collections, disk images, memory dumps, and log streams simultaneously.

```bash
cargo install --git https://github.com/SecurityRonin/issen rt-cli
```

**[GitHub Repository →](https://github.com/SecurityRonin/issen)** · **[Architecture →](architecture-diagram.html)**

---

## Three evidence paths. One timeline.

```
Disk image         Memory dump          Log stream
  ewf → ext4fs       memf → VA→PA         winevt / zeek
       ↓                   ↓                    ↓
  browser-forensic   carve → parser       EventRecord
  srum-forensic      srum-forensic        srum-forensic
       ↓                   ↓                    ↓
            Issen — correlation — TimelineEvent
```

Issen navigates each evidence type on its own terms — filesystem paths for disk images, page-table walks for memory, record-number seeks for log streams — then correlates across all three.

---

## Parser libraries

Each library is independently usable in your own Rust tooling:

| Crate | Description |
|---|---|
| [browser-forensic](https://github.com/SecurityRonin/browser-forensic) | Chrome/Firefox/Safari history, cookies, downloads, bookmarks, session data |
| [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic) | EVTX binary seek + BinXML decode → typed Windows EventRecord |
| [srum-forensic](https://github.com/SecurityRonin/srum-forensic) | ESE/JET Blue page walk → SRUM network/process/energy usage records |
| [ext4fs-forensic](https://github.com/SecurityRonin/ext4fs-forensic) | ext4 sector stream → files by path (name → inode → block) |
| [ewf](https://github.com/SecurityRonin/ewf) | E01/EWF → raw sector stream with hash verification |
| [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon) | Zero-dep compile-time artifact specs, magic bytes, format constants |

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/issen) · © 2026 Security Ronin Ltd.
