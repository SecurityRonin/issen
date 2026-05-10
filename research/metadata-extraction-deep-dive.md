# Metadata Extraction Research: Comprehensive Deep Dive

**Date:** 2026-03-25
**Purpose:** Inform the design of a shared metadata extraction module for Issen forensic toolkit (Rust)

---

## Table of Contents

1. [ExifTool Deep Dive](#1-exiftool-deep-dive)
2. [Forensically Critical Metadata Fields](#2-forensically-critical-metadata-fields)
3. [Other Metadata Databases & Tools](#3-other-metadata-databases--tools)
4. [Format-Specific Metadata Specifications](#4-format-specific-metadata-specifications)
5. [Rust Ecosystem for Metadata](#5-rust-ecosystem-for-metadata)
6. [Anti-Forensic Metadata Techniques](#6-anti-forensic-metadata-techniques)
7. [Architecture Recommendations](#7-architecture-recommendations)

---

## 1. ExifTool Deep Dive

### 1.1 Overview & Statistics

- **Author:** Phil Harvey (actively maintained since 2003)
- **Language:** Perl (Image::ExifTool library)
- **Current version:** 13.50 (Feb 2026)
- **License:** GPL v1+ / Artistic License
- **Total tags recognized:** 29,183 (as of March 19, 2026)
- **Unique tag names:** 18,132
- **File formats:** 150+ file types (400+ variants counting sub-formats and camera RAW types)
- **MakerNote manufacturers:** 20+ (Apple, Canon, Casio, DJI, FLIR, FujiFilm, GE, Google, GoPro, Hasselblad, HP, JVC, Kodak, Leaf, Minolta/Konica-Minolta, Motorola, Nikon, Olympus/Epson, Panasonic/Leica, Pentax/Asahi, PhaseOne, Reconyx, Ricoh, Samsung, Sanyo, Sigma/Foveon, Sony)

### 1.2 Architecture

```
exiftool (CLI)
    |
    v
lib/Image/ExifTool.pm (Core Library)
    |-- %fileTypeLookup (lines 226-578) -- extension -> type mapping
    |-- %magicNumber (lines 908-1027) -- magic byte signatures
    |-- %moduleName (lines 840-904) -- type -> Perl module mapping
    |-- @fileTypes (lines 196-203) -- master file type list
    |
    v
lib/Image/ExifTool/*.pm (Format-Specific Modules)
    |-- EXIF.pm        -- TIFF/EXIF IFD parsing (foundation for most image formats)
    |-- IPTC.pm        -- IPTC IIM data parsing
    |-- XMP.pm         -- XMP (XML-based) metadata
    |-- ICC_Profile.pm -- Color profile metadata
    |-- Photoshop.pm   -- PSD/IRB resource parsing
    |-- QuickTime.pm   -- MP4/MOV atom parsing
    |-- ID3.pm         -- MP3 tag parsing
    |-- PDF.pm         -- PDF info dictionary + XMP streams
    |-- RIFF.pm        -- AVI/WAV chunk parsing
    |-- ASF.pm         -- WMV/WMA metadata
    |-- Matroska.pm    -- MKV/WebM
    |-- FLAC.pm        -- FLAC metadata blocks
    |-- ZIP.pm         -- ZIP/DOCX/XLSX/PPTX (OOXML)
    |-- OOXML.pm       -- Office XML properties (docProps)
    |-- Flash.pm       -- SWF/FLV
    |-- Canon.pm       -- Canon MakerNotes
    |-- Nikon.pm       -- Nikon MakerNotes
    |-- Sony.pm        -- Sony MakerNotes
    |-- Fujifilm.pm    -- Fujifilm MakerNotes
    |-- Panasonic.pm   -- Panasonic/Leica MakerNotes
    |-- Olympus.pm     -- Olympus/Epson MakerNotes
    |-- Pentax.pm      -- Pentax/Asahi MakerNotes
    |-- Samsung.pm     -- Samsung MakerNotes
    |-- Apple.pm       -- Apple MakerNotes (iPhone)
    |-- DJI.pm         -- DJI drone MakerNotes
    |-- GoPro.pm       -- GoPro MakerNotes
    |-- FLIR.pm        -- Thermal camera MakerNotes
    |-- ... (50+ modules total)
```

### 1.3 File Processing Pipeline

1. **File Type Detection:** Examines file extension (`%fileTypeLookup`) and magic bytes (`%magicNumber`)
2. **Module Loading:** Dynamically loads appropriate module via `%moduleName` mapping
3. **Metadata Extraction:** Format-specific binary parsing methods
4. **Tag Processing:** Groups into families, applies print conversions
5. **Output:** JSON, XML, HTML, CSV, or custom format templates

### 1.4 Tag Organization System

**Group Families:**

| Family | Criteria | Examples |
|--------|----------|---------|
| Family 0 | General location (format) | EXIF, XMP, IPTC, MakerNotes, ICC_Profile, Photoshop, QuickTime, PDF, File |
| Family 1 | Specific location (sub-format) | IFD0, IFD1, ExifIFD, GPS, InteropIFD, SubIFD, XMP-dc, XMP-xmp, XMP-xmpMM, XMP-photoshop, Canon, Nikon |
| Family 2 | Logical category | Camera, Image, Time, Location, Audio, Video, Author, Document, Other |

**Tag Definition Structure:**
```perl
TagID => {
    Name        => 'TagName',
    Description => 'Human-readable description',
    Groups      => { 0 => 'EXIF', 1 => 'ExifIFD', 2 => 'Camera' },
    Writable    => 'string',
    Format      => 'int16u',
    Count       => 1,
    PrintConv   => { 0 => 'Normal', 1 => 'Manual' },  # or \&conversion_function
    Notes       => 'Additional information',
    Protected   => 1,  # 1=not writable directly
    Flags       => ['Unsafe', 'Permanent', 'Deletable'],
}
```

### 1.5 MakerNotes Architecture

MakerNotes are proprietary metadata blocks stored in EXIF tag 0x927c. Each manufacturer uses a different internal format (IFD-like with custom tag IDs, binary data blocks, or nested structures).

**Key characteristics:**
- Marked "Permanent" in ExifTool (editable but not individually creatable/deletable)
- Copied as a block during metadata operations
- Offset-dependent formats break if preceding tags are inserted/removed
- Some data is encrypted (e.g., Nikon lens data, Canon color data)
- Serial numbers often stored only here (not in standard EXIF)
- Camera-specific processing parameters (white balance coefficients, AF points, shutter count)

### 1.6 Write Priority Order

Default precedence when writing: EXIF > IPTC > XMP > MakerNotes > QuickTime > Photoshop > ICC_Profile > CanonVRD > Adobe

---

## 2. Forensically Critical Metadata Fields

### 2.1 Timestamps

#### EXIF/TIFF Timestamps
| Tag Name | Tag ID | IFD Group | Data Type | Forensic Significance |
|----------|--------|-----------|-----------|----------------------|
| DateTimeOriginal | 0x9003 | ExifIFD | ASCII(20) | Original capture time (shutter press) |
| CreateDate (DateTimeDigitized) | 0x9004 | ExifIFD | ASCII(20) | Digital data creation time |
| ModifyDate (DateTime) | 0x0132 | IFD0 | ASCII(20) | Last file modification |
| GPSDateStamp | 0x001d | GPS | ASCII(11) | GPS date in UTC (YYYY:MM:DD) |
| GPSTimeStamp | 0x0007 | GPS | rational64u[3] | GPS time in UTC (HH,MM,SS) |
| SubSecTime | 0x9290 | ExifIFD | ASCII | Sub-second precision for ModifyDate |
| SubSecTimeOriginal | 0x9291 | ExifIFD | ASCII | Sub-second for DateTimeOriginal |
| SubSecTimeDigitized | 0x9292 | ExifIFD | ASCII | Sub-second for CreateDate |
| OffsetTime | 0x9010 | ExifIFD | ASCII | Timezone offset for ModifyDate (EXIF 2.31+) |
| OffsetTimeOriginal | 0x9011 | ExifIFD | ASCII | Timezone for DateTimeOriginal |
| OffsetTimeDigitized | 0x9012 | ExifIFD | ASCII | Timezone for CreateDate |

**Forensic notes:**
- EXIF timestamps historically lacked timezone info (just local time) until EXIF 2.31 added OffsetTime tags
- GPS timestamps are always UTC -- comparing with EXIF local time reveals timezone and clock drift
- SubSecTime provides millisecond precision for burst photography sequence analysis
- Format: "YYYY:MM:DD HH:MM:SS" (note: colons in date, not hyphens)

#### XMP Timestamps
| Tag | Namespace | Forensic Significance |
|-----|-----------|----------------------|
| xmp:CreateDate | XMP-xmp | Document/resource creation time (ISO 8601 with timezone) |
| xmp:ModifyDate | XMP-xmp | Last modification (ISO 8601 with timezone) |
| xmp:MetadataDate | XMP-xmp | When XMP metadata was last changed (may differ from ModifyDate) |
| xmpMM:History[n]/stEvt:when | XMP-xmpMM | Timestamp of each save/edit event |
| photoshop:DateCreated | XMP-photoshop | IPTC-aligned creation date |

#### IPTC IIM Timestamps
| Tag | Record:Dataset | Data Type | Forensic Significance |
|-----|---------------|-----------|----------------------|
| DateCreated | 2:55 | CCYYMMDD | Intellectual content creation date |
| TimeCreated | 2:60 | HHMMSS+HHMM | Time with timezone offset |
| DigitalCreationDate | 2:62 | CCYYMMDD | Digital representation creation |
| DigitalCreationTime | 2:63 | HHMMSS+HHMM | Digital creation time |
| ReleaseDate | 2:30 | CCYYMMDD | Earliest release date |
| ExpirationDate | 2:37 | CCYYMMDD | Latest use date |

#### PDF Timestamps
| Tag | Location | Format | Forensic Significance |
|-----|----------|--------|----------------------|
| CreationDate | Info Dict (required) | D:YYYYMMDDHHmmSSOHH'mm | Original creation -- includes timezone |
| ModDate | Info Dict (required if PieceInfo) | D:YYYYMMDDHHmmSSOHH'mm | Last save -- timezone reveals location |
| xmp:CreateDate | XMP stream | ISO 8601 | Should match Info Dict CreationDate |
| xmp:ModifyDate | XMP stream | ISO 8601 | Should match Info Dict ModDate |
| xmp:MetadataDate | XMP stream | ISO 8601 | When XMP metadata itself was edited |
| xmpMM:History[n]/stEvt:when | XMP stream | ISO 8601 | Full save history (can show 100s of saves) |

**PDF forensic notes:**
- PDF 2.0 deprecates Info Dict for everything except CreationDate/ModDate
- Info Dict and XMP timestamps SHOULD agree -- discrepancy indicates tool mismatch
- XMP Core version can reveal post-processing by different software
- Multiple XMP metadata streams may exist in a single PDF

#### Office Document Timestamps
| Tag | Location | Format | Forensic Significance |
|-----|----------|--------|----------------------|
| dcterms:created | OOXML docProps/core.xml | W3CDTF (ISO 8601) | Document creation time |
| dcterms:modified | OOXML docProps/core.xml | W3CDTF | Last modification time |
| cp:lastPrinted | OOXML docProps/core.xml | W3CDTF | Last print time |
| TotalTime / TotalEditingTime | OOXML docProps/app.xml | Minutes (integer) | Cumulative editing time |
| cp:revision | OOXML docProps/core.xml | Integer | Save count |
| CreateDate | OLE2 SummaryInformation | FILETIME | Legacy Office creation |
| ModifyDate | OLE2 SummaryInformation | FILETIME | Legacy Office last save |
| LastPrinted | OLE2 SummaryInformation | FILETIME | Legacy Office last print |
| EditTime | OLE2 SummaryInformation | FILETIME duration | Total editing time |

**Office forensic notes:**
- Revision identifier (rsid) in OOXML tracks editing sessions -- content with same rsid was edited in same session
- TotalEditingTime may reveal if a document was hastily created (low time) or heavily worked on
- Template name reveals organizational document templates

#### Video/Audio Timestamps
| Tag | Format/Container | Data Type | Forensic Significance |
|-----|-----------------|-----------|----------------------|
| CreateDate | QuickTime mvhd atom | uint32 (seconds since 1904-01-01) | Track creation time |
| ModifyDate | QuickTime mvhd atom | uint32 | Track modification time |
| TrackCreateDate | QuickTime tkhd atom | uint32 | Per-track creation |
| TrackModifyDate | QuickTime tkhd atom | uint32 | Per-track modification |
| MediaCreateDate | QuickTime mdhd atom | uint32 | Media handler creation |
| MediaModifyDate | QuickTime mdhd atom | uint32 | Media handler modification |
| TDRC (RecordingTime) | ID3v2.4 | ISO 8601 | When audio was recorded |
| TYER (Year) | ID3v2.3 | YYYY | Recording year |
| TDEN (EncodingTime) | ID3v2.4 | ISO 8601 | When encoded |
| TDRL (ReleaseTime) | ID3v2.4 | ISO 8601 | Release date |

### 2.2 Device Identification

#### Camera/Device Tags
| Tag | Tag ID | Group | Data Type | Forensic Significance |
|-----|--------|-------|-----------|----------------------|
| Make | 0x010f | IFD0 | ASCII | Camera manufacturer |
| Model | 0x0110 | IFD0 | ASCII | Camera model (often includes variant info) |
| Software | 0x0131 | IFD0 | ASCII | Firmware version or processing software |
| SerialNumber / BodySerialNumber | 0xa431 | ExifIFD | ASCII | Camera body serial (EXIF 2.3+) |
| LensSerialNumber | 0xa435 | ExifIFD | ASCII | Lens serial number |
| LensModel | 0xa434 | ExifIFD | ASCII | Lens identification string |
| LensMake | 0xa433 | ExifIFD | ASCII | Lens manufacturer |
| HostComputer | 0x013c | IFD0 | ASCII | Computer used to process (iPhone model, etc.) |
| ProcessingSoftware | 0x000b | IFD0 | ASCII | Software that processed the image |
| ImageUniqueID | 0xa420 | ExifIFD | ASCII | Globally unique image identifier |

#### MakerNotes Device Tags (Selected)
| Tag | Manufacturer | Forensic Significance |
|-----|-------------|----------------------|
| CanonSerialNumber | Canon | Camera serial (redundant check vs EXIF) |
| InternalSerialNumber | Canon/Nikon/Sony | Internal device identifier (different format) |
| OwnerName | Canon | Registered owner name stored in camera |
| FirmwareVersion | All | Exact firmware build version |
| ShutterCount | Canon/Nikon/Sony/Pentax | Total actuations (camera usage history) |
| ImageNumber | Canon/Nikon | Sequential image counter |
| LensID | All | Exact lens identification (vendor-specific database) |
| ColorTemperature | All | White balance setting (environment indicator) |
| AFAreaMode / AFPoint | All | Focus settings (intent indicator) |

#### Software/Processing Identification
| Tag | Group | Forensic Significance |
|-----|-------|----------------------|
| xmp:CreatorTool | XMP-xmp | Application that created the resource |
| pdf:Producer | XMP-pdf / PDF Info | PDF generation engine (e.g., "cairo 1.16.0") |
| pdf:Creator | PDF Info | Application name (e.g., "Writer", "Chrome") |
| Application | OOXML app.xml | Office application name + version |
| AppVersion | OOXML app.xml | Precise version number (e.g., "16.0000") |
| Company | OOXML app.xml | Organization name from install |
| Template | OOXML app.xml | Document template filename |

### 2.3 Geolocation

#### GPS Tags (Full Set)
| Tag | Tag ID | Data Type | Forensic Significance |
|-----|--------|-----------|----------------------|
| GPSVersionID | 0x0000 | int8u[4] | GPS IFD version (2.3.0.0 typical) |
| GPSLatitudeRef | 0x0001 | ASCII(2) | 'N' or 'S' |
| GPSLatitude | 0x0002 | rational64u[3] | Degrees, minutes, seconds |
| GPSLongitudeRef | 0x0003 | ASCII(2) | 'E' or 'W' |
| GPSLongitude | 0x0004 | rational64u[3] | Degrees, minutes, seconds |
| GPSAltitudeRef | 0x0005 | int8u | 0=above sea level, 1=below |
| GPSAltitude | 0x0006 | rational64u | Meters |
| GPSTimeStamp | 0x0007 | rational64u[3] | UTC time (independent of EXIF time) |
| GPSSatellites | 0x0008 | ASCII | Satellites used (count/IDs) |
| GPSStatus | 0x0009 | ASCII(2) | 'A'=active, 'V'=void |
| GPSMeasureMode | 0x000a | ASCII(2) | '2'=2D, '3'=3D |
| GPSDOP | 0x000b | rational64u | Dilution of Precision (accuracy) |
| GPSSpeed | 0x000d | rational64u | Movement speed |
| GPSSpeedRef | 0x000c | ASCII(2) | Speed unit (K=km/h, M=mph, N=knots) |
| GPSTrack | 0x000f | rational64u | Direction of movement |
| GPSImgDirection | 0x0011 | rational64u | Direction camera was pointing |
| GPSImgDirectionRef | 0x0010 | ASCII(2) | 'T'=true north, 'M'=magnetic north |
| GPSMapDatum | 0x0012 | ASCII | Geodetic datum (e.g., "WGS-84") |
| GPSDestLatitude | 0x0014 | rational64u[3] | Destination coordinates |
| GPSDestLongitude | 0x0016 | rational64u[3] | Destination coordinates |
| GPSDateStamp | 0x001d | ASCII(11) | UTC date (YYYY:MM:DD) |
| GPSDifferential | 0x001e | int16u | Differential correction applied |
| GPSHPositioningError | 0x001f | rational64u | Horizontal positioning error (meters, EXIF 2.31+) |
| GPSProcessingMethod | 0x001b | undef | Method used (GPS/CELLID/WLAN/MANUAL) |
| GPSAreaInformation | 0x001c | undef | GPS area name |

**GPS Forensic Analysis:**
- Compare GPSTimeStamp (UTC) with DateTimeOriginal (local) for timezone verification
- GPSProcessingMethod reveals if position came from satellite, cell tower, or WiFi
- GPSHPositioningError (EXIF 2.31+) indicates accuracy -- cell tower fixes are less precise
- GPSDOP value indicates satellite geometry quality
- GPSSpeed on a "stationary" photo may indicate it was taken from a moving vehicle
- GPSImgDirection shows which way the camera was pointed (verifies scene orientation)

#### IPTC/XMP Location Tags
| Tag | Source | Forensic Significance |
|-----|--------|----------------------|
| City | IPTC 2:90 / XMP Iptc4xmpCore | City name |
| Province-State | IPTC 2:95 / XMP Iptc4xmpCore | State/province |
| Country-PrimaryLocationName | IPTC 2:101 / XMP Iptc4xmpCore | Country name |
| Country-PrimaryLocationCode | IPTC 2:100 / XMP Iptc4xmpCore | ISO 3166 country code |
| Sub-location | IPTC 2:92 / XMP Iptc4xmpCore | Specific location within city |
| LocationCreated | XMP Iptc4xmpExt | Structured: where content was created |
| LocationShown | XMP Iptc4xmpExt | Structured: location depicted in content |

### 2.4 Authorship / Origin

| Tag | Source | Forensic Significance |
|-----|--------|----------------------|
| Artist | EXIF IFD0 0x013b | Image creator name |
| Copyright | EXIF IFD0 0x8298 | Copyright holder |
| XPAuthor | EXIF IFD0 0x9c9d | Windows XP author field |
| By-line | IPTC 2:80 | Creator/photographer name |
| CopyrightNotice | IPTC 2:116 | Copyright string |
| dc:creator | XMP-dc | Creator array (multiple authors) |
| dc:rights | XMP-dc | Copyright/usage rights |
| xmpRights:WebStatement | XMP-xmpRights | URL to license |
| OwnerName | Canon MakerNotes | Camera owner (set in camera menu) |
| dc:creator | OOXML core.xml | Document author |
| cp:lastModifiedBy | OOXML core.xml | Last person who saved |
| Author | OLE2 SummaryInformation | Legacy Office author |
| LastAuthor | OLE2 SummaryInformation | Last person to save |
| Company | OOXML app.xml / OLE2 DocSummary | Organization name |
| Manager | OOXML app.xml / OLE2 DocSummary | Manager name |

### 2.5 Edit History

#### XMP Media Management History (xmpMM:History)
Each entry in the ResourceEvent array:
| Field | XMP Path | Forensic Significance |
|-------|----------|----------------------|
| Action | stEvt:action | created, saved, converted, derived, printed |
| When | stEvt:when | ISO 8601 timestamp of the action |
| SoftwareAgent | stEvt:softwareAgent | Full software name+version (e.g., "Adobe Photoshop CC 2024 (Windows)") |
| InstanceID | stEvt:instanceID | xmp.iid:UUID unique to this save |
| Changed | stEvt:changed | Which parts changed (e.g., "/metadata", "/content") |
| Parameters | stEvt:parameters | Additional details (e.g., conversion parameters) |

#### XMP Identity Tracking
| Field | Forensic Significance |
|-------|----------------------|
| xmpMM:DocumentID | Stable across saves; changes only on Save-As (tracks document lineage) |
| xmpMM:InstanceID | Changes every save (tracks individual save states) |
| xmpMM:OriginalDocumentID | Original source document ID |
| xmpMM:DerivedFrom/stRef:documentID | Parent document ID (proves derivation) |
| xmpMM:DerivedFrom/stRef:instanceID | Specific parent instance |

#### Photoshop-Specific History
| Field | Forensic Significance |
|-------|----------------------|
| photoshop:History | Concise/Detailed command log (if History Log preference enabled) |
| photoshop:TextLayers | Layer names and text content (LEAKED in JPEG exports from PSD) |
| photoshop:DocumentAncestors | Array of ancestor document IDs |
| XMP-crs:* | Camera Raw Settings (all adjustments applied in Adobe Camera Raw/Lightroom) |

### 2.6 Email-Specific Metadata

#### Key MAPI Properties
| Property | Hex ID | Type | Forensic Significance |
|----------|--------|------|----------------------|
| PR_TRANSPORT_MESSAGE_HEADERS | 0x007D | PT_STRING8 | Full RFC 2822 headers (Received chain, authentication results) |
| PR_CLIENT_SUBMIT_TIME | 0x0039 | PT_SYSTIME | When sender clicked Send |
| PR_MESSAGE_DELIVERY_TIME | 0x0E06 | PT_SYSTIME | When delivered to recipient store |
| PR_CREATION_TIME | 0x3007 | PT_SYSTIME | When message object was created |
| PR_LAST_MODIFICATION_TIME | 0x3008 | PT_SYSTIME | Last modification (should equal PR_CREATION_TIME if untampered) |
| PR_CONVERSATION_INDEX | 0x0071 | PT_BINARY | Thread position + embedded timestamp (first 5 bytes = creation time) |
| PR_SENDER_EMAIL_ADDRESS | 0x0C1F | PT_STRING8 | Sender email |
| PR_SENT_REPRESENTING_EMAIL_ADDRESS | 0x0065 | PT_STRING8 | Delegate sender |
| PR_INTERNET_MESSAGE_ID | 0x1035 | PT_STRING8 | RFC Message-ID |
| PR_IN_REPLY_TO_ID | 0x1042 | PT_STRING8 | Message this replies to |
| PR_MESSAGE_CLASS | 0x001A | PT_STRING8 | IPM.Note, IPM.Schedule.Meeting, etc. |

#### Transport Header Fields
| Header | Forensic Significance |
|--------|----------------------|
| Received: | Server hop path (read bottom-up); timestamps at each server |
| X-Originating-IP | Sender's IP (deprecated by Gmail/Outlook, still in some corporate) |
| X-Mailer / User-Agent | Email client identification |
| Message-ID | Unique ID (domain part reveals sending server) |
| DKIM-Signature | Cryptographic domain authentication |
| ARC-Authentication-Results | Chain of custody for forwarded messages |
| Authentication-Results | SPF/DKIM/DMARC verification at receiving server |
| Return-Path | Bounce address (may differ from From: in spoofing) |
| X-MS-Exchange-Organization-AuthSource | Exchange server that authenticated sender |
| X-MS-Exchange-Organization-SCL | Spam Confidence Level |

#### Forgery Detection via MAPI
- **PR_CREATION_TIME != PR_LAST_MODIFICATION_TIME** --> message was modified after delivery
- **PR_CLIENT_SUBMIT_TIME much earlier than PR_MESSAGE_DELIVERY_TIME** --> suspicious delay
- **PR_CONVERSATION_INDEX timestamp doesn't match PR_CLIENT_SUBMIT_TIME** --> thread manipulation
- **Missing or stripped transport headers** --> manual header removal attempt
- **Return-Path != From:** --> potential spoofing (but also legitimate for mailing lists)

---

## 3. Other Metadata Databases & Tools

### 3.1 Apache Tika

| Attribute | Detail |
|-----------|--------|
| Language | Java |
| Formats | 1,400+ |
| Focus | Content + metadata extraction |
| Metadata model | Dublin Core-based, normalizes across formats |
| Write support | No (read-only) |
| Key strength | Strongest for document formats (PDF, Office, email) |
| ExifTool integration | Can delegate to ExifTool as external parser (since Tika 1.9) |
| Additional features | Language detection, MIME type detection, full-text extraction |

**Formats Tika handles that ExifTool doesn't:**
- Email formats (EML, MSG, MBOX, PST)
- Full text extraction from all document types
- Scientific formats (HDF5, NetCDF)
- Source code files
- Database exports

### 3.2 FOCA (Fingerprinting Organizations with Collected Archives)

| Attribute | Detail |
|-----------|--------|
| Language | C# (.NET), Windows-only |
| Focus | OSINT metadata discovery from public documents |
| Formats | Office (DOC/XLS/PPT), PDF, OpenOffice, InDesign, SVG, images |
| Key extractions | Users, folders, printers, software versions, emails, OS info, server names, internal paths |
| Unique features | Automated web scraping, network infrastructure mapping, vulnerability detection from version info |

**FOCA-style metadata of interest for forensics:**
- Internal file paths revealing directory structures and usernames
- Printer names revealing physical locations
- Software versions revealing patch levels
- Email addresses embedded in document properties
- Network server names from document paths (\\\\server\\share\\...)

### 3.3 mat2 (Metadata Anonymisation Toolkit 2)

| Attribute | Detail |
|-----------|--------|
| Language | Python 3 |
| Focus | Metadata removal (what it removes = what it knows about) |
| Formats | AVI, BMP, CSS, EPUB, FLAC, GIF, JPEG, MP3/M4A, MP4, ODF suite, Opus/OGA, PDF, PNG, PPM, PPTX/XLSX/DOCX, SVG, TAR/ZIP (recursive), TIFF, torrent, WAV, WMV |
| Distribution | Included in Tails OS and Qubes-Whonix |
| Caveat | Cannot handle watermarking, steganography, or custom metadata systems |

### 3.4 Hachoir

| Attribute | Detail |
|-----------|--------|
| Language | Python 3.7+ |
| Focus | Binary file format parsing at bit level |
| Formats | 30+ (audio: MP3/WAV/OGG/MIDI/AIFF; image: BMP/GIF/JPEG/PNG/TIFF/XCF; archives; executables) |
| Key feature | Views binary files as tree of fields (down to individual bits) |
| Strengths | Handles invalid/truncated files, no external dependencies, lazy loading |

### 3.5 MediaInfo

| Attribute | Detail |
|-----------|--------|
| Focus | Technical stream-level audio/video metadata |
| Key strength | Codec details beyond ExifTool: profile/level, encoding settings, color space, HDR, scan type/order, stream sizes, chapter metadata |
| Export formats | MIXML, JSON, PBCore, EBUCore |
| Unique fields | Format profile (e.g., "Main@L4"), CABAC/ReFrames settings, writing library, encoding parameters, chroma subsampling, bit depth per component |

### 3.6 PRONOM (National Archives UK)

| Attribute | Detail |
|-----------|--------|
| Purpose | File format technical registry for digital preservation |
| Database | 1,300+ file format records |
| Identification | PUIDs (Persistent Unique Identifiers), internal byte signatures (70% of entries) |
| Tool | DROID (Digital Record Object Identification) for batch format identification |
| Integration | Archivematica, Preservica, Rosetta, Siegfried |

---

## 4. Format-Specific Metadata Specifications

### 4.1 Image Metadata Standards

#### EXIF (Exchangeable Image File Format)
- **Spec:** EXIF 2.32 (JEITA CP-3461, 2019) / EXIF 3.0 (CIPA DC-008-2023)
- **Standard tags:** ~200 defined in spec
- **Structure:** TIFF IFD (Image File Directory) -- linked list of tag entries
- **IFDs:** IFD0 (primary image), IFD1 (thumbnail), ExifIFD (camera settings), GPS IFD (location), InteropIFD (interoperability)
- **EXIF 3.0 changes:** UTF-8 support for text fields (was ASCII-only in 2.32), BodySerialNumber formalized
- **Found in:** JPEG (APP1), TIFF, PNG (eXIf chunk, since EXIF 2.32), HEIF, WebP, many RAW formats
- **Forensic note:** EXIF IFD structure is the foundation for understanding most image metadata

#### IPTC IIM (Information Interchange Model)
- **Spec:** IPTC IIM 4.2 (1999, but still widely used)
- **Structure:** Binary records and datasets (Record:Dataset notation, e.g., 2:05 = Object Name)
- **Tag count:** ~70 datasets across 8 records
- **Found in:** JPEG APP13 (Photoshop IRB), TIFF
- **Key records:** Record 1 (Envelope), Record 2 (Application, most used), Record 3 (pre-ObjectData)

#### IPTC Core + Extension
- **Spec:** IPTC Photo Metadata Standard 2024.1
- **Structure:** XMP-based (Iptc4xmpCore and Iptc4xmpExt namespaces)
- **Properties:** ~80 total (Creator, Description, Keywords, Rights, Location, Model Release, etc.)
- **Replaces:** IPTC IIM for modern usage

#### XMP (Extensible Metadata Platform)
- **Spec:** ISO 16684-1:2019, ISO 16684-2:2014
- **Structure:** XML/RDF serialization
- **Key namespaces:**
  - `dc:` (Dublin Core) -- creator, title, description, rights, subject, date
  - `xmp:` (XMP Basic) -- CreateDate, ModifyDate, MetadataDate, CreatorTool, Rating
  - `xmpMM:` (XMP Media Management) -- DocumentID, InstanceID, History, DerivedFrom
  - `xmpRights:` -- WebStatement, Marked, UsageTerms
  - `photoshop:` -- DateCreated, City, State, Country, Credit, Source, Instructions
  - `tiff:` -- TIFF properties mapped to XMP
  - `exif:` -- EXIF properties mapped to XMP
  - `exifEX:` -- EXIF 2.31+ properties mapped to XMP
  - `aux:` -- Additional EXIF-like properties
  - `crs:` -- Camera Raw Settings (every adjustment slider value)
  - `Iptc4xmpCore:` -- IPTC Core
  - `Iptc4xmpExt:` -- IPTC Extension
- **Found in:** JPEG APP1 (separate from EXIF APP1), PDF stream, TIFF tag, PNG iTXt, Office documents, sidecar .xmp files

#### ICC Profile
- **Spec:** ICC.1:2022 (v4.4)
- **Structure:** Binary header + tagged element table
- **Key metadata:** Profile size, preferred CMM, version, device class, color space, PCS, creation date, primary platform, profile creator, rendering intent
- **Found in:** JPEG APP2, TIFF tag, PNG iCCP chunk, PDF, PSD

#### PNG Metadata Chunks
| Chunk | Encoding | Forensic Significance |
|-------|----------|----------------------|
| tEXt | Latin-1 key + value | Simple key-value metadata |
| iTXt | UTF-8 key + value | International text metadata |
| zTXt | Compressed Latin-1 | Compressed text metadata |
| eXIf | EXIF blob | Full EXIF data (PNG spec 1.6.38+, EXIF 2.32+) |
| tIME | Binary | Last modification time (year, month, day, hour, minute, second) |
| iCCP | Binary | Embedded ICC profile |

### 4.2 Document Metadata Standards

#### OLE2 (MS Office 97-2003)
**Magic bytes:** D0 CF 11 E0 A1 B1 1A E1

**SummaryInformation Stream:**
| Property | FMTID Property ID | Forensic Significance |
|----------|-------------------|----------------------|
| Title | PIDSI_TITLE (0x02) | Document title |
| Subject | PIDSI_SUBJECT (0x03) | Subject/topic |
| Author | PIDSI_AUTHOR (0x04) | Document creator |
| Keywords | PIDSI_KEYWORDS (0x05) | Search keywords |
| Comments | PIDSI_COMMENTS (0x06) | Document comments |
| Template | PIDSI_TEMPLATE (0x07) | Template used |
| LastAuthor | PIDSI_LASTAUTHOR (0x08) | Last person to save |
| RevNumber | PIDSI_REVNUMBER (0x09) | Revision count |
| EditTime | PIDSI_EDITTIME (0x0A) | Total editing time (FILETIME duration) |
| LastPrinted | PIDSI_LASTPRINTED (0x0B) | Last print timestamp |
| CreateDtm | PIDSI_CREATE_DTM (0x0C) | Creation timestamp |
| LastSaveDtm | PIDSI_LASTSAVE_DTM (0x0D) | Last save timestamp |
| PageCount | PIDSI_PAGECOUNT (0x0E) | Page count |
| WordCount | PIDSI_WORDCOUNT (0x0F) | Word count |
| CharCount | PIDSI_CHARCOUNT (0x10) | Character count |
| Thumbnail | PIDSI_THUMBNAIL (0x11) | Document thumbnail |
| AppName | PIDSI_APPNAME (0x12) | Application name |
| DocSecurity | PIDSI_DOC_SECURITY (0x13) | Security flags |

**DocumentSummaryInformation Stream:**
| Property | Forensic Significance |
|----------|----------------------|
| Category | Document category |
| Manager | Manager name |
| Company | Organization name |
| LinksUpToDate | Whether hyperlinks are current |
| CharCountWithSpaces | Full character count |
| SharedDoc | Whether shared |
| HyperlinksChanged | Whether links were modified |
| ContentType | MIME content type |
| ContentStatus | Draft/Final/etc. |
| Language | Document language |
| DocVersion | Version string |

#### OOXML (MS Office 2007+)
ZIP archive containing:

**docProps/core.xml (Dublin Core + custom):**
```xml
<cp:coreProperties>
  <dc:title>Document Title</dc:title>
  <dc:subject>Subject</dc:subject>
  <dc:creator>Author Name</dc:creator>
  <cp:keywords>keyword1, keyword2</cp:keywords>
  <dc:description>Description</dc:description>
  <cp:lastModifiedBy>Last Editor</cp:lastModifiedBy>
  <cp:revision>42</cp:revision>
  <dcterms:created xsi:type="dcterms:W3CDTF">2024-01-15T10:30:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2024-03-20T14:22:00Z</dcterms:modified>
  <cp:lastPrinted>2024-02-10T09:00:00Z</cp:lastPrinted>
  <cp:category>Report</cp:category>
  <cp:contentStatus>Final</cp:contentStatus>
</cp:coreProperties>
```

**docProps/app.xml (Extended Properties):**
```xml
<Properties>
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Template>Normal.dotm</Template>
  <TotalTime>1440</TotalTime>
  <Pages>25</Pages>
  <Words>12500</Words>
  <Characters>71250</Characters>
  <Lines>595</Lines>
  <Paragraphs>167</Paragraphs>
  <Company>Acme Corp</Company>
  <Manager>John Smith</Manager>
  <DocSecurity>0</DocSecurity>
  <SharedDoc>false</SharedDoc>
  <HyperlinksChanged>false</HyperlinksChanged>
  <LinksUpToDate>false</LinksUpToDate>
</Properties>
```

**OOXML Revision Identifiers (rsid):**
- 32-bit hex values assigned per editing session
- Same rsid = content edited in same session (between saves)
- Can determine document source and track editing sessions forensically
- Stored in document.xml on individual runs/paragraphs

#### PDF Metadata

**Info Dictionary (trailer):**
| Key | Type | Forensic Significance |
|-----|------|----------------------|
| /Title | text string | Document title |
| /Author | text string | Author name |
| /Subject | text string | Subject |
| /Keywords | text string | Keywords |
| /Creator | text string | Creating application (e.g., "Microsoft Word") |
| /Producer | text string | PDF generation engine (e.g., "macOS Version 14.0") |
| /CreationDate | date string | D:YYYYMMDDHHmmSSOHH'mm -- includes timezone! |
| /ModDate | date string | Last modification -- timezone reveals location |
| /Trapped | name | /True, /False, /Unknown |

**XMP Metadata Stream:**
Stored as a metadata stream object. Can contain all standard XMP namespaces plus:
- `pdf:Producer` -- PDF engine
- `pdf:Keywords` -- Keywords
- `pdf:PDFVersion` -- PDF version
- `pdfaid:part` / `pdfaid:conformance` -- PDF/A compliance
- `xmpMM:History` -- Full save history (timestamped events with software agents)

#### OpenDocument (ODF)
ZIP containing meta.xml:
```xml
<office:document-meta>
  <office:meta>
    <dc:title>Title</dc:title>
    <dc:creator>Author</dc:creator>
    <dc:date>2024-03-20T14:22:00</dc:date>
    <meta:creation-date>2024-01-15T10:30:00</meta:creation-date>
    <meta:editing-duration>PT2H30M</meta:editing-duration>
    <meta:editing-cycles>42</meta:editing-cycles>
    <meta:generator>LibreOffice/7.6.4.1</meta:generator>
    <meta:initial-creator>Original Author</meta:initial-creator>
    <meta:print-date>2024-02-10T09:00:00</meta:print-date>
    <dc:subject>Subject</dc:subject>
    <dc:description>Description</dc:description>
    <meta:keyword>keyword1</meta:keyword>
  </office:meta>
</office:document-meta>
```

### 4.3 Video/Audio Metadata

#### MP4/MOV (ISO Base Media File Format)
```
ftyp        -- File type and compatibility brands
moov        -- Movie metadata container
  mvhd      -- Movie header (creation_time, modification_time, timescale, duration)
  trak[n]   -- Track container
    tkhd    -- Track header (creation_time, modification_time, track_id, duration, dimensions)
    mdia    -- Media container
      mdhd  -- Media header (creation_time, modification_time, timescale, duration, language)
      hdlr  -- Handler reference (media type)
      minf  -- Media information
  udta      -- User data container
    meta    -- Metadata container
      hdlr  -- Metadata handler
      ilst  -- iTunes metadata list
        ©nam -- Title
        ©ART -- Artist
        ©alb -- Album
        ©day -- Year
        ©cmt -- Comment
        ©gen -- Genre
        covr -- Cover art
        ©too -- Encoding tool
    CNMN    -- Canon model name (vendor-specific)
    CNDM    -- Canon date/time (vendor-specific)
    XMP_    -- XMP metadata packet
mdat        -- Media data (actual audio/video samples)
```

**QuickTime-specific timestamps:** Stored as uint32 seconds since January 1, 1904 (Mac epoch). Timezone is NOT stored -- assumed UTC but some cameras use local time.

#### AVI RIFF INFO Chunks
| Four-CC | Field | Forensic Significance |
|---------|-------|----------------------|
| INAM | Title | Video title |
| IART | Artist | Creator |
| ICMT | Comment | Comments |
| ICRD | DateCreated | Creation date |
| ISFT | Software | Creating software |
| IGNR | Genre | Content genre |
| ICOP | Copyright | Copyright notice |
| IENG | Engineer | Engineer |
| ITCH | Technician | Technician |
| ISRC | Source | Source material |

#### ID3v2 Key Frames
| Frame ID | v2.3 | v2.4 | Forensic Significance |
|----------|------|------|----------------------|
| TIT2 | Title | Title | Track title |
| TPE1 | Lead artist | Lead artist | Primary performer |
| TALB | Album | Album | Album name |
| TYER | Year | -- | Recording year |
| TDRC | -- | Recording time | ISO 8601 recording date (v2.4) |
| TDEN | -- | Encoding time | When encoded |
| TDRL | -- | Release time | Official release |
| TSSE | Encoding settings | Encoding settings | Encoder software+settings |
| TENC | Encoded by | Encoded by | Person/org that encoded |
| TXXX | User defined | User defined | Custom key-value pairs |
| APIC | Picture | Picture | Embedded artwork |
| GEOB | General object | General object | Arbitrary binary data |
| PRIV | Private | Private | Private frame (vendor-specific) |
| UFID | Unique file ID | Unique file ID | Database record link |
| PCNT | Play counter | Play counter | Times played |

#### FLAC Metadata Blocks
| Block Type | ID | Forensic Significance |
|-----------|-----|----------------------|
| STREAMINFO | 0 | Sample rate, channels, bits per sample, total samples, MD5 of raw audio |
| PADDING | 1 | Reserved space (may contain remnants of deleted metadata) |
| APPLICATION | 2 | Third-party application data (ID + payload) |
| SEEKTABLE | 3 | Seek points for random access |
| VORBIS_COMMENT | 4 | Key=value pairs (ARTIST, TITLE, ALBUM, DATE, TRACKNUMBER, etc.) |
| CUESHEET | 5 | CD table of contents |
| PICTURE | 6 | Embedded artwork |

#### WAV Broadcast Wave Format (BWF)
bext chunk fields:
| Field | Size | Forensic Significance |
|-------|------|----------------------|
| Description | 256 chars | Recording description |
| Originator | 32 chars | Creator |
| OriginatorReference | 32 chars | Unique reference |
| OriginationDate | 10 chars | YYYY-MM-DD |
| OriginationTime | 8 chars | HH:MM:SS |
| TimeReference | uint64 | Sample count since midnight (precise start time) |
| Version | uint16 | BWF version |
| UMID | 64 bytes | Unique Material Identifier (SMPTE 330M) |
| LoudnessValue | int16 | EBU R128 loudness |

### 4.4 Windows-Specific Metadata

#### NTFS Zone.Identifier ADS
```ini
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://mail.google.com/
HostUrl=https://example.com/malware.exe
HostIpAddress=93.184.216.34
```

| ZoneId | Zone | Forensic Significance |
|--------|------|----------------------|
| 0 | Local Machine | Generated locally |
| 1 | Local Intranet | From corporate intranet |
| 2 | Trusted Sites | From trusted site list |
| 3 | Internet | Downloaded from internet |
| 4 | Restricted Sites | From restricted zone |

**Forensic notes:**
- Stored as NTFS ADS, often resident in MFT (recoverable from deleted files)
- ReferrerUrl reveals the page that linked to the download
- HostUrl reveals the direct download URL
- Absence on executables is suspicious (may have been stripped to bypass SmartScreen)
- Some malware checks for Zone.Identifier as sandbox evasion

#### LNK (Shell Link) File Metadata
| Field | Forensic Significance |
|-------|----------------------|
| CreationTime | When LNK file was created |
| AccessTime | When LNK was last accessed |
| WriteTime | When LNK was last modified |
| TargetCreationTime | When target file was created |
| TargetAccessTime | When target was last accessed |
| TargetWriteTime | When target was last modified |
| FileSize | Target file size |
| DriveType | Fixed, removable, network, etc. |
| DriveSerialNumber | Volume serial number (identifies specific drive) |
| VolumeLabel | Volume label string |
| LocalBasePath | Full path to target on local system |
| NetName | UNC path for network targets |
| NetBIOSName | Machine name of host |
| MACAddress | Network interface MAC address (in some versions) |
| IconLocation | Path to icon file |
| CommandLineArguments | Arguments passed to target |
| WorkingDir | Working directory |
| MachineID (TrackerData) | NetBIOS name of machine where target was last known |
| Droid (TrackerData) | File/volume GUID pair for distributed link tracking |

**LNK forensic notes:**
- Persist after original file is deleted (proves file existed)
- Store target timestamps from time of last LNK update (historical snapshot)
- DriveSerialNumber identifies specific USB drives
- Same binary format used in Jump Lists (.automaticDestinations-ms)
- MachineID reveals the computer name where file was located

#### Thumbcache
Location: `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`

| Database | Thumbnail Size | Forensic Significance |
|----------|---------------|----------------------|
| thumbcache_32.db | 32px | Small icons |
| thumbcache_96.db | 96px | Medium icons (generated during browsing) |
| thumbcache_256.db | 256px | Large icons |
| thumbcache_1024.db | 1024px | Extra large (proves user viewed file at large size) |
| thumbcache_1280.db | 1280px | High resolution (strong evidence of viewing) |
| thumbcache_sr.db | Variable | Set for "super resolution" |
| thumbcache_idx.db | N/A | Index file linking thumbnails to paths |
| iconcache_*.db | Various | Application icon caches |

**Thumbcache forensic notes:**
- Thumbnails persist after original file deletion
- Higher resolution = stronger evidence of intentional viewing
- Correlate with Shellbag timestamps for folder access + file viewing timeline
- thumbcache_idx.db maps thumbnail IDs to file identifiers (path hashes)

---

## 5. Rust Ecosystem for Metadata

### 5.1 Comprehensive / Multi-Format Crates

| Crate | Pure Rust | EXIF | XMP | IPTC | GPS | MakerNotes | Video | Write | Maturity |
|-------|-----------|------|-----|------|-----|------------|-------|-------|----------|
| **exif-oxide** | Yes | Full | Full | Partial | Full | Canon/Nikon/Sony | Planned | Planned | Active, pre-1.0 |
| **nom-exif** | Yes | Full | No | No | Yes | No | MP4/MOV/MKV | No | Stable |
| **rexiv2** | No (FFI) | Full | Full | Full | Yes | Via Exiv2 | No | Yes | Mature |
| **xmp_toolkit** | No (C++) | No | Full | No | Via XMP | No | Via XMP | Yes | Stable |
| **kamadak-exif** | Yes | Full | No | No | Yes | Basic | No | No | Mature |

### 5.2 Format-Specific Crates

| Crate | Format | Read | Write | Notes |
|-------|--------|------|-------|-------|
| **id3** | MP3 ID3v1/v2 | Yes | Yes | Well-maintained, full ID3v2.4 |
| **audiotags** | MP3/FLAC/M4A | Yes | Yes | Unified API across audio formats |
| **symphonia** | MP3/FLAC/OGG/WAV/AAC | Yes | No | Codec-focused, extracts metadata |
| **lopdf** | PDF | Yes | Yes | Full PDF manipulation, PDF 2.0 support |
| **undoc** | DOCX/XLSX/PPTX | Yes | No | Metadata extraction + content |
| **ooxml** | XLSX | Yes | No | XLSX parsing only |
| **docx-rs** | DOCX | Yes | Yes | Parse and generate DOCX |
| **litchi** | OLE2/OOXML/ODF/iWork | Yes | No | Early development, broad format support |
| **calamine** | XLSX/XLS/ODS | Yes | No | Spreadsheet reading |
| **cfb** | OLE2 Compound Files | Yes | Yes | Low-level structured storage access |
| **lnk** | Windows LNK files | Yes | No | Basic LNK parsing |
| **image** | PNG/JPEG/GIF/etc. | Yes | Yes | Image codec, limited metadata |
| **little_exif** | JPEG/PNG/TIFF | Yes | Yes | Lightweight EXIF reader/writer |

### 5.3 Gap Analysis for Issen

**Well-covered:**
- EXIF/GPS extraction from images (kamadak-exif, nom-exif, exif-oxide)
- XMP reading/writing (xmp_toolkit)
- ID3 tags (id3 crate)
- PDF manipulation (lopdf)
- Basic OOXML text/metadata (undoc)

**Gaps requiring custom implementation or FFI:**
- MSG/PST email parsing (no mature Rust crate; use FFI to libpff or shell to readpst)
- OLE2 SummaryInformation/DocumentSummaryInformation extraction (cfb gives raw access, need property set parsing)
- Comprehensive MakerNotes (only exif-oxide has Canon/Nikon/Sony; 20+ other manufacturers missing)
- LNK file metadata (lnk crate exists but limited; may need custom parser)
- Windows thumbcache parsing (no Rust crate; need custom implementation)
- Zone.Identifier ADS reading (trivial to implement: read `:Zone.Identifier` stream as text)
- Video metadata from MP4/MOV atoms (nom-exif handles basic; need full udta/meta parsing)
- IPTC IIM binary parsing (rexiv2 via FFI; or implement from spec)
- Jump List parsing (no Rust crate; LNK-based, needs custom implementation)
- BWF/WAV metadata (no dedicated Rust crate; can parse bext chunk manually)
- MKV/WebM tag parsing (no dedicated Rust crate for metadata; matroska crate exists for demux)

### 5.4 Recommended Strategy for Issen

**Tier 1 (Use existing crates):**
- `kamadak-exif` or `exif-oxide` for EXIF/GPS from images
- `xmp_toolkit` for XMP across all formats
- `id3` for MP3 metadata
- `lopdf` for PDF metadata extraction
- `nom-exif` for video file metadata (MP4/MOV)

**Tier 2 (Wrap/extend existing crates):**
- `cfb` + custom property set parser for OLE2 document metadata
- `undoc` or custom ZIP+XML parser for OOXML metadata
- `lnk` + extensions for full LNK metadata

**Tier 3 (Custom implementation needed):**
- Email metadata parser (MSG/EML/PST) -- critical for outlook-forensic crate
- Thumbcache parser
- Jump List parser
- Zone.Identifier ADS reader (simple)
- MakerNotes beyond Canon/Nikon/Sony

**Tier 4 (External tool delegation):**
- ExifTool via subprocess for maximum tag coverage (fallback mode)
- MediaInfo via subprocess for detailed codec analysis
- Tika via subprocess for exotic document formats

---

## 6. Anti-Forensic Metadata Techniques

### 6.1 Common Manipulation Methods

| Technique | Tools Used | What's Changed |
|-----------|-----------|---------------|
| EXIF date manipulation | ExifTool, jhead, pyexiv2 | All timestamp tags rewritten |
| GPS stripping | mat2, ExifEraser, social media auto-strip | GPS IFD removed or zeroed |
| GPS spoofing | ExifTool, GPS faker apps | Fake coordinates injected |
| Full metadata sanitization | mat2, ExifEraser, ExifCleaner, ImageOptim | All non-essential metadata removed |
| Office metadata cleaning | File > Properties > "Remove Personal Information" | Author, company, revision history cleared |
| PDF metadata stripping | qpdf --linearize, ExifTool | Info Dict + XMP cleared |
| Email header manipulation | Direct MSG editing, custom SMTP | Transport headers modified/removed |

### 6.2 Detection Methods

#### Thumbnail vs. Main Image Mismatch
- Many editing tools update the main image but forget the embedded EXIF thumbnail
- Thumbnail shows original, main image shows edited version
- **Detection:** Extract IFD1 thumbnail, compare with downscaled main image
- **Significance:** Proves editing occurred even if all other metadata was cleaned

#### MakerNotes Integrity Analysis
| Check | Meaning if Failed |
|-------|------------------|
| MakerNotes completely absent | Stripped by editing tool (suspicious for camera that always writes them) |
| MakerNotes corrupted/unreadable | Offset-dependent format broken by tag insertion/removal |
| Serial number mismatch | MakerNote serial vs EXIF serial don't match (manual editing) |
| Expected tags missing | Camera model should produce specific tags that are absent |
| Encrypted sections intact but timestamps wrong | Selective editing (hard to edit encrypted MakerNotes) |

#### Timestamp Inconsistency Detection
| Comparison | Expected | Anomaly Indicates |
|------------|----------|-------------------|
| DateTimeOriginal vs FileModifyDate | File >= EXIF | File older = copied/backdated |
| DateTimeOriginal vs GPS DateTime | Small drift (< few seconds) | Large drift = separate manipulation |
| EXIF vs XMP timestamps | Should match exactly | Tool that only updated one source |
| CreateDate vs ModifyDate | Modify >= Create | Create after Modify = impossible without tampering |
| SubSecTime consistency | Sequential in burst | Non-sequential = post-manipulation |
| OffsetTime vs GPS location timezone | Should match | Timezone spoofing or relocation |

#### Software Tag Analysis
| Indicator | Meaning |
|-----------|---------|
| Software tag shows editor name | Image was processed (not necessarily malicious) |
| No Software tag + MakerNotes present | Normal camera output |
| No Software tag + no MakerNotes | Heavily sanitized |
| xmp:CreatorTool mismatch with Make/Model | Post-processing by different software |
| XMP Core version mismatch | Different tool modified XMP after creation |
| photoshop:TextLayers present in JPEG | Exported from PSD (reveals layer names) |

#### Compression Signature Analysis
| Technique | Forensic Value |
|-----------|---------------|
| JPEG quantization table matching | Tables should match known camera profiles |
| Double-compression detection | Re-saved JPEG shows double quantization artifacts |
| Huffman table analysis | Non-standard tables indicate reprocessing |
| JPEG Restart Marker interval | Camera-specific intervals change after editing |

#### Cross-Reference Validation
| Check | What to Compare |
|-------|----------------|
| EXIF + XMP + IPTC timestamps | All three should agree |
| PDF Info Dict + XMP stream | Should contain same values |
| File system timestamps + embedded metadata | FS times should be >= embedded dates |
| OOXML revision + content rsids | Revision count should match editing session count |
| Email PR_CREATION_TIME + PR_LAST_MODIFICATION_TIME | Should match if message was not tampered with |
| Email Conversation Index timestamp + Submit time | Embedded CI time should match submission |

---

## 7. Architecture Recommendations

### 7.1 Proposed Module Structure

```
crates/
  rapid-triage-metadata/        # Shared metadata extraction library
    src/
      lib.rs                    # Public API: extract_metadata(path) -> MetadataReport
      types.rs                  # Common metadata types (Timestamp, GeoLocation, Author, etc.)
      forensic_fields.rs        # Forensically-significant field definitions
      extractors/
        mod.rs                  # Extractor trait definition
        exif.rs                 # EXIF/TIFF IFD extraction (kamadak-exif or exif-oxide)
        xmp.rs                  # XMP extraction (xmp_toolkit)
        iptc.rs                 # IPTC IIM extraction
        gps.rs                  # GPS data normalization
        makernotes.rs           # MakerNotes extraction + manufacturer routing
        icc_profile.rs          # ICC profile metadata
        pdf.rs                  # PDF Info Dict + XMP (lopdf)
        office_ole2.rs          # OLE2 SummaryInfo/DocSummary (cfb + custom)
        office_ooxml.rs         # OOXML core.xml + app.xml (zip + xml)
        office_odf.rs           # OpenDocument meta.xml
        quicktime.rs            # MP4/MOV atom parsing (nom-exif)
        id3.rs                  # MP3 ID3 tags (id3 crate)
        flac.rs                 # FLAC metadata blocks + Vorbis comments
        riff.rs                 # AVI/WAV INFO chunks + BWF bext
        matroska.rs             # MKV/WebM tags
        email_msg.rs            # MSG MAPI properties
        email_eml.rs            # EML header parsing
        lnk.rs                  # Windows LNK file metadata
        zone_identifier.rs      # NTFS Zone.Identifier ADS
        thumbcache.rs           # Windows thumbcache parsing
      analysis/
        timestamp_analysis.rs   # Cross-format timestamp comparison + anomaly detection
        anti_forensics.rs       # Metadata tampering detection
        thumbnail_analysis.rs   # Thumbnail vs main image comparison
        device_tracking.rs      # Serial number + device identification
        geolocation.rs          # GPS analysis, timezone verification
        edit_history.rs         # XMP history reconstruction
      output/
        report.rs               # Structured forensic report generation
        timeline.rs             # Metadata-based timeline construction
```

### 7.2 Core Trait Design

```rust
pub trait MetadataExtractor {
    /// Supported MIME types for this extractor
    fn supported_types(&self) -> &[&str];

    /// Extract all metadata from the given reader
    fn extract(&self, reader: &mut dyn Read, mime_type: &str) -> Result<MetadataSet>;

    /// Extract only forensically-significant fields
    fn extract_forensic(&self, reader: &mut dyn Read, mime_type: &str) -> Result<ForensicMetadata>;
}

pub struct ForensicMetadata {
    pub timestamps: Vec<TimestampField>,
    pub device_info: Option<DeviceInfo>,
    pub geolocation: Option<GeoLocation>,
    pub authorship: Vec<AuthorField>,
    pub edit_history: Vec<EditEvent>,
    pub software_info: Vec<SoftwareInfo>,
    pub anomalies: Vec<MetadataAnomaly>,
    pub raw_tags: HashMap<String, TagValue>,
}
```

### 7.3 ExifTool Fallback Strategy

For maximum coverage, implement a two-tier extraction:
1. **Native Rust extractors** for common formats (fast, no external deps)
2. **ExifTool subprocess** as fallback for exotic formats or when comprehensive MakerNotes are needed

```rust
pub fn extract_metadata(path: &Path, opts: ExtractionOpts) -> Result<MetadataReport> {
    let mime = detect_mime(path)?;
    let native_result = native_extract(path, &mime)?;

    if opts.comprehensive && native_result.has_gaps() {
        let exiftool_result = exiftool_subprocess(path)?;
        native_result.merge(exiftool_result)
    } else {
        Ok(native_result)
    }
}
```

---

## Sources

### ExifTool
- [ExifTool GitHub Repository](https://github.com/exiftool/exiftool)
- [ExifTool Tag Names](https://exiftool.org/TagNames/)
- [ExifTool EXIF Tags](https://exiftool.org/TagNames/EXIF.html)
- [ExifTool Wikipedia](https://en.wikipedia.org/wiki/ExifTool)
- [ExifTool DeepWiki Architecture](https://deepwiki.com/exiftool/exiftool)
- [ExifTool MetaCPAN](https://metacpan.org/dist/Image-ExifTool/view/exiftool)

### Forensic Analysis
- [Metadata Investigation with ExifTool](https://www.cyberengage.org/post/metadata-investigation-exiftool-a-powerful-tool-in-digital-forensics)
- [Forensic Value of Exif Data (SCIEPublish)](https://www.sciepublish.com/article/pii/567)
- [FotoForensics Tutorial: Metadata Analysis](https://fotoforensics.com/tutorial.php?tt=meta)
- [Detect Fake EXIF Data (EXIFData.org)](https://exifdata.org/blog/detect-fake-exif-data-identifying-altered-photo-metadata)
- [Black Hat: Digital Image Counter-Forensics](https://blackhat.com/docs/us-17/wednesday/us-17-Mazurov-Brown-Protecting-Visual-Assets-Digital-Image-Counter-Forensics.pdf)
- [PDF Forensic Analysis and XMP (Meridian Discovery)](https://www.meridiandiscovery.com/articles/pdf-forensic-analysis-xmp-metadata/)
- [PDF Forensics & Metadata Conundrum (PDF Association)](https://pdfa.org/wp-content/uploads/2025/10/0-2-15_30-CherieEkholm-PDF_Forensics_and_the_Metadata_conundrum.pdf)
- [Email Headers Forensics](https://alyninc.com/2018/11/10/email-headers-what-can-they-tell-the-forensic-investigator/)
- [Email Forgery Analysis (Meridian Discovery)](https://www.meridiandiscovery.com/articles/email-forgery-analysis-in-computer-forensics/)
- [Email Conversation Index Forensics](https://www.meridiandiscovery.com/how-to/e-mail-conversation-index-metadata-computer-forensics/)

### Metadata Tools
- [Apache Tika](https://tika.apache.org/)
- [Tika + ExifTool Integration](https://wiki.apache.org/tika/EXIFToolParser)
- [FOCA GitHub](https://github.com/ElevenPaths/FOCA)
- [mat2 GitLab](https://0xacab.org/jvoisin/mat2)
- [Hachoir GitHub](https://github.com/vstinner/hachoir)
- [MediaInfo Fields](https://mediaarea.net/en/MediaInfo/Support/Fields)
- [PRONOM Wikipedia](https://en.wikipedia.org/wiki/PRONOM)
- [oletools GitHub](https://github.com/decalage2/oletools)

### Metadata Standards
- [IPTC Photo Metadata Standard](https://iptc.org/standards/photo-metadata/iptc-standard/)
- [Image Metadata Standards Overview](http://scottmeyers.blogspot.com/2022/01/image-metadata-standards-guidelines-and.html)
- [XMP Wikipedia](https://en.wikipedia.org/wiki/Extensible_Metadata_Platform)
- [EXIF Wikipedia](https://en.wikipedia.org/wiki/Exif)
- [ID3 Wikipedia](https://en.wikipedia.org/wiki/ID3)
- [Metadata in JPEG Files (Exiv2)](https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_JPEG_files)

### Rust Crates
- [exif-oxide (PhotoStructure)](https://github.com/photostructure/exif-oxide)
- [nom-exif](https://github.com/mindeng/nom-exif)
- [rexiv2](https://github.com/felixc/rexiv2)
- [xmp_toolkit](https://docs.rs/xmp_toolkit)
- [kamadak-exif](https://github.com/kamadak/exif-rs)
- [id3](https://github.com/polyfloyd/rust-id3)
- [lopdf](https://github.com/J-F-Liu/lopdf)
- [undoc](https://crates.io/crates/undoc)
- [litchi](https://github.com/DevExzh/litchi)

### Windows Forensics
- [Zone.Identifier Analysis (Digital Detective)](https://www.digital-detective.net/forensic-analysis-of-zone-identifier-stream/)
- [LNK File Forensics (Magnet)](https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/)
- [Thumbcache Forensics (Pen Test Partners)](https://www.pentestpartners.com/security-blog/thumbnail-forensics-dfir-techniques-for-analysing-windows-thumbcache/)
- [LNK ForensicsWiki](https://forensics.wiki/lnk/)
- [fmd Tool (Rust LNK/PE)](https://github.com/theflakes/fmd)
