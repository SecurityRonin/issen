# Privacy Policy

*Last updated: 2026-04-19*

## Summary

Issen is a local command-line tool. It does not collect, transmit, or store any personal data on remote servers.

## Google Drive Integration

When you use `rt gdrive auth login`, Issen:

1. Opens a browser window to Google's OAuth 2.0 authorization page.
2. Asks for the `drive.readonly` scope — read-only access to files you explicitly identify by URL or file ID.
3. Stores the resulting access and refresh tokens **locally** at `~/.config/issen/gdrive_token.json` on your machine.

No token or credential is ever sent to Security Ronin Ltd or any third party other than Google.

## Data Access

- Issen requests only the `drive.readonly` scope.
- It reads only the specific file(s) you supply on the command line.
- It does not index, list, or enumerate your Google Drive.
- File contents are processed in memory and written to your local manifest — nothing is uploaded.

## Telemetry

Issen has **no telemetry**. It makes no network requests except:
- OAuth token exchange with `oauth2.googleapis.com` (during `rt gdrive auth login`)
- File content download from `googleapis.com` (during `rt gdrive://FILE_ID`)

## Open Source

Issen is open source (Apache-2.0). You can audit every network call at [github.com/SecurityRonin/issen](https://github.com/SecurityRonin/issen).

## Contact

Privacy questions: [security@securityronin.com](mailto:security@securityronin.com)

---

[Terms of Service](terms.md) · [Home](index.md) · © 2026 Security Ronin Ltd
