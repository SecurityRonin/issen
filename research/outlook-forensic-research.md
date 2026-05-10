# PST/OST Forensic Parsing — Comprehensive Research

**Date:** 2026-03-25
**Purpose:** Inform design of `~/src/outlook-forensic` Rust crate

---

## 1. File Format Specification

### Magic Bytes
- Offset 0: `!BDN` (0x21 0x42 0x44 0x4E)
- Offset 8: `SM` (0x53 0x4D)

### Format Variants (detected by `wVer` at offset 10)
| Variant | wVer | Page Size | Block Size | Notes |
|---------|------|-----------|------------|-------|
| ANSI | 14 | 512 bytes | 8192 bytes | Legacy (Outlook 97-2002) |
| Unicode | 23 | 512 bytes | 8192 bytes | Standard (Outlook 2003+) |
| Unicode 4K | 36 | 4096 bytes | 65536 bytes | OST 2013+ with DEFLATE |

### Encryption (offset 513)
| Value | Type | Method | Crackable? |
|-------|------|--------|------------|
| 0x00 | None | — | N/A |
| 0x01 | Compressible | Permute (substitution cipher) | Trivial — no password needed |
| 0x02 | High | Cyclic (3-rotor Enigma variant) | Trivial — no password needed |

**Critical:** Neither encryption type uses the stored password. The password is just a CRC-32 hash stored for UI verification — trivially bypassed or ignored entirely.

---

## 2. Three-Layer Architecture

### NDB (Node Database) Layer
- **Header:** File signature, version, sizes, root pointers, CRC
- **AMap (Allocation Map):** Tracks which pages/blocks are allocated vs free
- **FMap (Free Map):** Summarizes AMap for fast free-space lookup
- **PMap (Page Map):** Which pages have free space
- **NBT (Node BTree):** Maps node IDs to data block references
- **BBT (Block BTree):** Maps block IDs to file offsets
- **Blocks:** Data blocks (external) and subnode blocks (internal)

### LTP (Lists, Tables, Properties) Layer
- **Heap-on-Node (HN):** Variable-size heap allocator within a node's data
- **BTree-on-Heap (BTH):** B-tree stored on HN for fast key lookup
- **Property Context (PC):** Collection of properties for a single object
- **Table Context (TC):** Two-dimensional table (rows = items, columns = properties)

### Messaging Layer
- **Message Store:** Root folder, named properties, search folders
- **Folder Objects:** Hierarchy table (subfolders) + contents table (messages)
- **Message Objects:** Properties, recipients, attachments
- **Attachment Objects:** Properties + data stream

---

## 3. Forensic Timeline Properties (MAPI)

### Core Email Timestamps
| Property | Tag | Type | Forensic Significance |
|----------|-----|------|----------------------|
| PR_CLIENT_SUBMIT_TIME | 0x0039 | PtypTime | When sender clicked Send |
| PR_MESSAGE_DELIVERY_TIME | 0x0E06 | PtypTime | When delivered to recipient mailbox |
| PR_CREATION_TIME | 0x3007 | PtypTime | When item created in message store |
| PR_LAST_MODIFICATION_TIME | 0x3008 | PtypTime | Last modification (tampering indicator) |
| PR_MESSAGE_FLAGS | 0x0E07 | PtypInteger32 | Read/unread, draft, submitted flags |
| PR_TRANSPORT_MESSAGE_HEADERS | 0x007D | PtypString | Full RFC 5322 headers with Received: chain |
| PR_CONVERSATION_INDEX | 0x0071 | PtypBinary | Thread position with embedded timestamps |
| PR_SENDER_EMAIL_ADDRESS | 0x0C1F | PtypString8 | Sender email |
| PR_INTERNET_MESSAGE_ID | 0x1035 | PtypString | RFC 5322 Message-ID |
| PR_IN_REPLY_TO_ID | 0x1042 | PtypString | RFC 5322 In-Reply-To |

### Calendar/Appointment Properties
| Property | Tag | Forensic Significance |
|----------|-----|----------------------|
| PR_START_DATE | 0x0060 | Appointment start time |
| PR_END_DATE | 0x0061 | Appointment end time |
| dispidApptStartWhole | Named | Start (full day precision) |
| dispidApptEndWhole | Named | End (full day precision) |
| dispidResponseStatus | Named | Accept/Decline/Tentative status |
| dispidBusyStatus | Named | Free/Busy/Tentative/OOF |

### Task Properties
| Property | Tag | Forensic Significance |
|----------|-----|----------------------|
| dispidTaskDueDate | Named | Due date |
| dispidTaskStartDate | Named | Start date |
| dispidTaskDateCompleted | Named | Completion date |
| dispidPercentComplete | Named | Completion percentage |

### Attachment Properties
| Property | Tag | Forensic Significance |
|----------|-----|----------------------|
| PR_ATTACH_FILENAME | 0x3704 | Attachment filename |
| PR_ATTACH_LONG_FILENAME | 0x3707 | Long filename |
| PR_ATTACH_SIZE | 0x0E20 | Attachment size |
| PR_CREATION_TIME | 0x3007 | Attachment creation time |
| PR_LAST_MODIFICATION_TIME | 0x3008 | Attachment modification time |
| PR_ATTACH_METHOD | 0x3705 | How attached (file, OLE, embedded msg) |

### PR_CONVERSATION_INDEX Structure
```
Header (22 bytes):
  reserved: 1 byte (0x01)
  timestamp: 5 bytes (FILETIME, top 5 bytes — gives ~1 minute resolution)
  guid: 16 bytes (unique per conversation thread)

Child entries (5 bytes each):
  time_delta: 5 bytes (offset from header time)
```

**Forensic significance:** The header timestamp is the conversation START time. Each reply adds a 5-byte child entry with time delta. This reveals: thread creation time, reply times, and thread structure — even if message timestamps were tampered.

---

## 4. Forensic Timeline Event Types

- EMAIL_SENT (PR_CLIENT_SUBMIT_TIME)
- EMAIL_DELIVERED (PR_MESSAGE_DELIVERY_TIME)
- EMAIL_CREATED (PR_CREATION_TIME)
- EMAIL_MODIFIED (PR_LAST_MODIFICATION_TIME)
- EMAIL_READ (flags + modification time)
- DRAFT_SAVED (creation time + UNSENT flag)
- APPOINTMENT_CREATED / START / END / MODIFIED
- TASK_CREATED / DUE / COMPLETED
- CONTACT_CREATED / MODIFIED
- ATTACHMENT_CREATED / MODIFIED
- THREAD_STARTED (conversation index header)
- THREAD_REPLIED (conversation index child entries)
- SERVER_HOP (Received: header timestamps)
- JOURNAL_ENTRY

---

## 5. Data Recovery

### Deleted Item Mechanics
- Deleted items persist in unallocated blocks until compaction
- AMap/FMap track free space — orphaned allocated nodes = deleted items
- Items in "Deleted Items" folder are soft-deleted (still in folder tree)
- Hard-deleted items: node removed from NBT but blocks not zeroed

### Recovery Approaches
1. **AMap scanning:** Walk free-space bitmap, parse orphaned blocks
2. **Block scanning:** Scan all blocks for valid signatures, rebuild orphaned nodes
3. **Orphan node detection:** Find nodes in BBT not referenced by any NBT entry
4. **Carving:** Header-based carving from raw disk (58% fragmentation rate!)

### PST Fragmentation Challenge
Garfinkel's research shows PST files are **58% fragmented** on average. This makes simple header-footer carving fail on over half of Outlook archives. Bifragment gap carving is essential.

### scanpst.exe Internals
Microsoft's Inbox Repair Tool:
- Validates AMap/PMap/FMap consistency
- Rebuilds NBT and BBT from block-level scan
- Moves unrepairable items to "Lost and Found"
- Does NOT recover hard-deleted items

---

## 6. OST-Specific Considerations

### OST 2013 Format Changes (Mythicsoft research)
- 4096-byte pages (vs 512 for standard)
- DEFLATE block compression
- 24-byte block trailers
- Different allocation table format
- Profile binding (tied to Outlook profile, not portable)

### Orphaned OST Forensics
- OST files survive profile deletion
- Can be opened by rebinding to a new profile (or parsing directly)
- Contains full offline cache of Exchange mailbox

### Modern Outlook
- New Outlook (One Outlook) does NOT use PST/OST
- Uses browser-style storage (Chromium-based)
- Classic Outlook + PST/OST will remain relevant for years

---

## 7. Library Comparison

| Library | Language | PST | OST | ANSI | Unicode | 4K/DEFLATE | Deleted Recovery | License |
|---------|----------|-----|-----|------|---------|-----------|-----------------|---------|
| libpff (Metz) | C | Yes | Yes | Yes | Yes | Yes | Yes | LGPLv3+ |
| outlook-pst-rs (MS) | Rust | Yes | No | Yes | Yes | No | No | MIT |
| XstReader (Beercow) | C# | Yes | Yes | Yes | Yes | No | No | Ms-PL |
| libpst/readpst | C | Yes | Yes | Yes | Yes | No | Yes | GPLv2 |
| java-libpst | Java | Yes | Yes | Yes | Yes | No | No | Apache 2.0 |
| pff-tools | Rust(FFI) | Yes | Yes | Yes | Yes | Yes | Yes | MIT |
| msg_parser | Rust | .msg | — | — | — | — | No | MIT |

**Gap:** No pure-Rust crate handles both PST and OST (including 4K/DEFLATE), provides deleted recovery, handles corruption, AND generates forensic timelines.

---

## 8. Email Forgery Detection

1. **Timestamp consistency:** PR_CLIENT_SUBMIT_TIME vs Received: header chain vs PR_CREATION_TIME
2. **PR_CONVERSATION_INDEX validation:** Embedded timestamps must be consistent with message dates
3. **Transport header analysis:** Received: hop timestamps must be monotonically increasing
4. **Message-ID format:** Domain should match sender's mail system
5. **X-Originating-IP:** Reveals actual sender IP (if present)
6. **MUA (Mail User Agent) fingerprinting:** Software version vs claimed client
7. **MIME boundary analysis:** Consistent generation patterns per MUA

---

## 9. Recommended Architecture

```
outlook-forensic/
├── src/
│   ├── lib.rs                    # Public API
│   ├── ndb/                      # Node Database layer
│   │   ├── header.rs             # File header parsing + variant detection
│   │   ├── pages.rs              # AMap, PMap, FMap, DList
│   │   ├── blocks.rs             # Data blocks + subnode blocks
│   │   ├── nbt.rs                # Node BTree
│   │   ├── bbt.rs                # Block BTree
│   │   └── crypto.rs             # Permute + Cyclic decryption
│   ├── ltp/                      # Lists, Tables, Properties layer
│   │   ├── heap.rs               # Heap-on-Node
│   │   ├── btree.rs              # BTree-on-Heap
│   │   ├── property_context.rs   # PC (single object properties)
│   │   └── table_context.rs      # TC (tabular data)
│   ├── messaging/                # Messaging layer
│   │   ├── store.rs              # Message store root
│   │   ├── folder.rs             # Folder objects
│   │   ├── message.rs            # Message objects
│   │   ├── attachment.rs         # Attachment objects
│   │   ├── recipient.rs          # Recipient objects
│   │   └── named_props.rs        # Named property mapping
│   ├── mapi/                     # MAPI property definitions
│   │   ├── tags.rs               # All property tag constants
│   │   ├── types.rs              # Property type definitions
│   │   └── conversation.rs       # PR_CONVERSATION_INDEX parser
│   ├── recovery/                 # Deleted item recovery
│   │   ├── amap_scan.rs          # Free-space analysis
│   │   ├── orphan_nodes.rs       # Orphaned node detection
│   │   ├── block_carver.rs       # Block-level carving
│   │   └── rebuild.rs            # Structure rebuilding
│   ├── ost/                      # OST-specific handling
│   │   ├── deflate.rs            # DEFLATE decompression
│   │   ├── trailer.rs            # 24-byte block trailers
│   │   └── profile.rs            # Profile binding info
│   ├── timeline/                 # Forensic timeline generation
│   │   ├── events.rs             # Timeline event types
│   │   ├── extractor.rs          # MAPI → timeline events
│   │   └── forgery.rs            # Forgery detection checks
│   └── carving/                  # PST/OST carving from raw disk
│       ├── scanner.rs            # Header detection
│       ├── bifragment.rs         # Bifragment gap carving
│       └── validator.rs          # Carved file validation
```

**Dependencies:** `binrw`/`nom`, `flate2` (DEFLATE), `chrono`, `thiserror`, `memmap2`, `encoding_rs` (ANSI codepages), `serde`, `uuid`

---

## Sources
- [MS-PST Official Specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546)
- [libpff PFF Format Documentation](https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20(PFF)%20format.asciidoc)
- [libpff GitHub](https://github.com/libyal/libpff)
- [Microsoft outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs)
- [XstReader (Beercow)](https://github.com/Beercow/XstReader)
- [OST 2013 Missing Documentation (Mythicsoft)](https://blog.mythicsoft.com/ost-2013-file-format-the-missing-documentation/)
- [Forensics Wiki — PFF](https://forensics.wiki/personal_folder_file_(pab,_pst,_ost)/)
- [Meridian — Conversation Index Forensics](https://www.meridiandiscovery.com/how-to/e-mail-conversation-index-metadata-computer-forensics/)
- [Meridian — Attachment Timestamps](https://www.meridiandiscovery.com/articles/email-attachment-timestamps-forensics-outlook/)
- [Forensic Focus — Email Falsification (Metz)](https://www.forensicfocus.com/articles/e-mail-and-appointment-falsification-analysis/)
- [1234n6 — Extended MAPI Properties](https://blog.1234n6.com/using-extended-mapi-properties-to-determine-email-sent-time/)
- [Metaspike — Hidden Timestamps](https://www.metaspike.com/timestamps-forensic-email-examination/)
- [Library of Congress — PST Unicode Format](https://www.loc.gov/preservation/digital/formats/fdd/fdd000378.shtml)
