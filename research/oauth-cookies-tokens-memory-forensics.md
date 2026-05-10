# Authentication & Session Artifact Recovery from Memory Dumps

Comprehensive reference for detecting, extracting, and analyzing OAuth tokens, session cookies,
nonces, and other authentication/session artifacts from volatile memory. Targeted at a Rust-based
memory forensics tool.

**Last updated:** 2026-03-30

---

## Table of Contents

1. [OAuth 2.0 Tokens in Memory](#1-oauth-20-tokens-in-memory)
2. [JWT (JSON Web Tokens)](#2-jwt-json-web-tokens)
3. [Session Cookies](#3-session-cookies)
4. [SAML Tokens](#4-saml-tokens)
5. [API Keys and Service Tokens](#5-api-keys-and-service-tokens)
6. [Kerberos Tickets](#6-kerberos-tickets)
7. [CSRF Tokens / Nonces](#7-csrf-tokens--nonces)
8. [TOTP/HOTP Secrets](#8-totphotp-secrets)
9. [Certificate Private Keys](#9-certificate-private-keys)
10. [Password Manager Vault Data](#10-password-manager-vault-data)

---

## 1. OAuth 2.0 Tokens in Memory

### 1.1 Access Token Formats

OAuth 2.0 does not mandate a specific access token format. In practice two forms dominate:

| Form | Description | Memory Signature |
|------|-------------|-----------------|
| **JWT (structured)** | Base64url-encoded JSON: `header.payload.signature` | Starts with `eyJ`, contains exactly two `.` delimiters |
| **Opaque (reference)** | Random string; the resource server must introspect it at the authorization server | High-entropy alphanumeric string, no `.` structure |

**JWT access tokens** are the most common in modern providers (Auth0, Azure AD, Google).
They appear in memory as ASCII strings starting with `eyJ` followed by base64url characters
and two dot separators.

### 1.2 Refresh Tokens

Refresh tokens are long-lived credentials that obtain new access tokens without user interaction.

- **Format:** Provider-specific; may be opaque random strings (Google: ~512 chars),
  JWT-formatted (some Azure AD flows), or versioned opaque strings
- **Lifetime:** Hours to indefinite (Google refresh tokens do not expire unless revoked;
  Azure AD default 90 days with sliding window)
- **Memory location:** Stored in HTTP client libraries, token caches, and application heaps.
  On Windows, also cached in `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache` (DPAPI-encrypted)

**Detection regex (opaque refresh tokens):**
```
# Generic high-entropy token near "refresh_token" context
refresh_token["':=\s]+([A-Za-z0-9_\-/.]{40,})
```

### 1.3 Authorization Codes

- **Lifetime:** Extremely short (typically 30-60 seconds, MUST be single-use per RFC 6749)
- **Format:** Provider-specific opaque string, typically 20-60 characters
- **Memory presence:** Transient; appears in HTTP request/response buffers during the
  authorization code exchange. Look in browser process memory and server process memory.

### 1.4 How OAuth Tokens Appear in HTTP Client/Server Process Memory

Tokens appear in several locations within process memory:

1. **HTTP Authorization headers:** `Authorization: Bearer eyJ...` in request buffers
2. **HTTP response bodies:** JSON payloads containing `"access_token": "eyJ..."`,
   `"refresh_token": "..."`, `"id_token": "eyJ..."`
3. **Token caches / credential stores:** Application-level caches (MSAL token cache,
   Google credential objects, etc.)
4. **Environment variables:** `$OAUTH_TOKEN`, `$ACCESS_TOKEN`, etc. persisting in process env
5. **TLS decrypted buffers:** Post-TLS plaintext in libraries like OpenSSL, Schannel

### 1.5 Provider-Specific Patterns

#### Google (OAuth 2.0 / Google Cloud)
- Access tokens: Short-lived JWT (~1 hour), starts with `ya29.` for legacy or `eyJ` for JWT
- Refresh tokens: Opaque, start with `1//` (OAuth2 v2)
- Service account keys: JSON file containing `"private_key": "-----BEGIN RSA PRIVATE KEY-----..."`
- Application Default Credentials: `~/.config/gcloud/application_default_credentials.json`
- **Regex:** `ya29\.[A-Za-z0-9_-]{50,}` (legacy access token format)
- **Regex:** `1//[A-Za-z0-9_-]{40,}` (refresh token)

#### Microsoft / Azure AD (Entra ID)
- Access tokens: JWT with `eyJ0eX` prefix (base64url of `{"typ"`)
- Refresh tokens: Opaque, long strings (can be >1000 chars)
- Primary Refresh Token (PRT): Stored in LSASS on domain-joined Windows machines
- WAM (Web Account Manager) tokens: Cached in `TokenBroker\Cache`, DPAPI-encrypted
- **Tool:** WAMBam for decrypting stored tokens from WAM cache
- **Memory search:** `eyJ0eX` signature for Azure AD JWTs in Office process memory

#### GitHub
- OAuth access tokens: Now use fine-grained tokens with `github_pat_` prefix
- Classic tokens: `ghp_[0-9a-zA-Z]{36}`
- OAuth app tokens: `gho_[0-9a-zA-Z]{36}`
- User-to-server tokens: `ghu_[0-9a-zA-Z]{36}`
- Server-to-server tokens: `ghs_[0-9a-zA-Z]{36}`
- Refresh tokens: `ghr_[0-9a-zA-Z]{36}`

#### AWS (STS Temporary Credentials)
- **Long-term access key:** Prefix `AKIA` + 16 chars from `[0-9A-Z]`
- **Temporary (STS) access key:** Prefix `ASIA` + 16 chars from `[A-Z2-7]` (base32-like)
- **Secret access key:** 40 characters, base64-like
- **Session token:** Variable length (typically <4096 bytes), base64-encoded
- **Regex (long-term):** `AKIA[0-9A-Z]{16}`
- **Regex (temporary):** `ASIA[A-Z2-7]{16}`
- **Environment variables:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- **Credential file:** `~/.aws/credentials`
- Note: Character set after AKIA/ASIA prefix uses only A-Z and 2-7 (no 0,1,8,9) — this is a
  base32-like encoding providing 5 bits per character

#### Other AWS ID Prefixes (Forensic Context)
| Prefix | Entity Type |
|--------|-------------|
| `AIDA` | IAM User ID |
| `AROA` | IAM Role ID |
| `AIPA` | Instance Profile ID |
| `AKIA` | Long-term Access Key |
| `ASIA` | Temporary (STS) Access Key |
| `ANPA` | Managed Policy |
| `ANVA` | Version in a Managed Policy |
| `APKA` | Public Key |
| `ASCA` | Certificate |

### 1.6 PKCE Code Verifiers and Code Challenges

PKCE (Proof Key for Code Exchange, RFC 7636) adds security to the OAuth authorization code flow.

- **Code verifier:** Random string, 43-128 characters, charset `[A-Za-z0-9\-._~]`
  - Generated with minimum 256 bits of entropy
  - Stored client-side in memory during the OAuth flow
- **Code challenge (plain):** Same as code verifier
- **Code challenge (S256):** `BASE64URL(SHA256(code_verifier))`
  - 43 characters, base64url-encoded
- **Server storage:** The authorization server saves the code challenge in its in-memory data grid
  associated with the authorization code
- **Detection:** Search for high-entropy strings of length 43-128 near OAuth-related strings
  like `code_challenge`, `code_verifier`, `code_challenge_method`

---

## 2. JWT (JSON Web Tokens)

### 2.1 Structure

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

Three segments separated by period (`.`) characters. All three segments are always base64url
encoded.

### 2.2 The `eyJ` Prefix

The header is a JSON object that always starts with `{`, which base64url-encodes to `eyJ`.
More specifically:

| JSON Start | Base64URL | Common In |
|-----------|-----------|-----------|
| `{"alg"` | `eyJhbGci` | Standard JWT header |
| `{"typ"` | `eyJ0eXAi` | Azure AD tokens (include type claim) |
| `{"kid"` | `eyJraWQi` | Tokens with key ID header |
| `{"enc"` | `eyJlbmMi` | JWE (encrypted) tokens |

### 2.3 Base64URL Encoding

Base64URL differs from standard Base64:
- Uses `-` instead of `+`
- Uses `_` instead of `/`
- Omits `=` padding

**Valid base64url characters:** `[A-Za-z0-9_-]`

### 2.4 Common Claim Fields (Payload)

| Claim | Description | Forensic Value |
|-------|-------------|---------------|
| `iss` | Issuer | Identifies the authorization server / IdP |
| `sub` | Subject | User or service principal identifier |
| `aud` | Audience | Target service / resource |
| `exp` | Expiration | Unix timestamp; determines if token is still valid |
| `iat` | Issued At | When token was created |
| `nbf` | Not Before | Token not valid before this time |
| `jti` | JWT ID | Unique token identifier (for replay prevention) |
| `scope` | Scope | Permissions granted (e.g., `openid profile email`) |
| `roles` | Roles | Application roles assigned |
| `tid` | Tenant ID | Azure AD tenant identifier |
| `oid` | Object ID | Azure AD object identifier for the user |
| `upn` | UPN | User Principal Name (Azure AD) |

### 2.5 Signing Algorithms

| Algorithm | Type | Key Size | Notes |
|-----------|------|----------|-------|
| `HS256` | HMAC + SHA-256 | Symmetric (shared secret) | Secret key in server memory |
| `RS256` | RSA + SHA-256 | 2048+ bit RSA | Private key on auth server |
| `ES256` | ECDSA + SHA-256 | P-256 curve | Shorter signatures |
| `PS256` | RSA-PSS + SHA-256 | 2048+ bit RSA | Probabilistic padding |
| `EdDSA` | Edwards-curve DSA | Ed25519 | Modern, compact |

**2026 JWT Algorithm Confusion CVEs (Q1 2026):**
A cluster of JWT algorithm-related vulnerabilities across multiple language ecosystems:

| CVE | Framework | Language | Description |
|-----|-----------|----------|-------------|
| CVE-2026-23993 | HarbourJwt | Go | Algorithm confusion |
| CVE-2026-22817 | Hono | TypeScript/JS | Algorithm confusion (CVSS 8.2) |
| CVE-2026-23552 | Keycloak | Java | Algorithm confusion |
| GHSA-88q6-jcjg-hvmw | jose-swift | Swift | Algorithm confusion |

**Forensic relevance:** When analyzing JWTs in memory, check for:
- Empty or missing third segment (unsigned `alg:none` tokens)
- Algorithm mismatches: if server uses RS256 but token shows HS256/HS384/HS512 (confusion attack)
- `kid` (Key ID) header field with SQL injection or path traversal payloads

### 2.6 JWK (JSON Web Key) Private Keys in Memory

JWK is a JSON representation of cryptographic keys. In memory, look for JSON objects containing:

```json
{
  "kty": "RSA",
  "n": "...",    // modulus (base64url)
  "e": "AQAB",  // exponent (base64url of 65537)
  "d": "...",    // private exponent
  "p": "...",    // first prime factor
  "q": "...",    // second prime factor
  "dp": "...",   // first factor CRT exponent
  "dq": "...",   // second factor CRT exponent
  "qi": "..."    // first CRT coefficient
}
```

**Detection:** Search for `"kty"` near `"RSA"` or `"EC"` in JSON structures. The presence of
`"d"` parameter indicates a **private** key.

### 2.7 Detection Regex Patterns

```
# Standard JWT detection (URL-safe encoding)
eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*

# Broad JWT detection (higher false positive rate, catches all base64 variants)
eyJ[A-Za-z0-9_/+-]*\.eyJ[A-Za-z0-9._/+-]*\.[A-Za-z0-9._/+-]*

# JWT with known header prefix patterns
eyJ(?:hbGci|0eXAi|raWQi|lbmMi)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*
```

### 2.8 False Positive Considerations

- Other base64-encoded JSON data starting with `eyJ` (e.g., JWE tokens, serialized config)
- Base64-encoded data that coincidentally starts with `eyJ` but is not a JWT
- Truncated tokens (missing segments) from fragmented memory pages
- Test/example tokens embedded in documentation or config files
- **Mitigation:** Verify three-segment structure, decode header to check for `alg` claim,
  validate that payload decodes to valid JSON with expected claims

### 2.9 Where JWTs Reside in Process Memory

1. **HTTP client libraries:** Request headers (`Authorization: Bearer <JWT>`)
2. **HTTP server frameworks:** Request parsing buffers, middleware caches
3. **Token caches:** MSAL, ADAL, Google Auth libraries maintain in-memory caches
4. **Browser process memory:** JavaScript runtime (`sessionStorage`, `localStorage`, cookies)
5. **Web server worker processes:** Apache, Nginx, IIS worker threads
6. **Reverse proxy buffers:** Envoy, HAProxy, Traefik
7. **Windows TokenBroker:** `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache` (DPAPI-protected)

---

## 3. Session Cookies

### 3.1 Cookie Jar Storage in Browser Process Memory

Browsers maintain cookie jars in memory for active sessions. Cookies are loaded from persistent
storage (SQLite databases on disk) into process memory when needed.

**MITRE ATT&CK T1539 (Steal Web Session Cookie):** Cookies can be found on disk, in the process
memory of the browser, and in network traffic to remote systems. Session cookies can be used to
bypass some multi-factor authentication protocols.

### 3.2 Session ID Formats by Framework

| Framework | Cookie Name | Format | Example |
|-----------|------------|--------|---------|
| **PHP** | `PHPSESSID` | Alphanumeric, 26-32 chars | `PHPSESSID=abc123def456...` |
| **Java/J2EE** | `JSESSIONID` | Hex or alphanumeric, 32 chars | `JSESSIONID=A1B2C3D4E5F6...` |
| **ASP.NET** | `ASP.NET_SessionId` | Alphanumeric, 24 chars (base64-like) | `ASP.NET_SessionId=abc123xyz...` |
| **ASP.NET Auth** | `.ASPXAUTH` | Base64-encoded encrypted ticket | `.ASPXAUTH=E3A5B7C9D1F2...` (long) |
| **ASP.NET AntiForgery** | `__RequestVerificationToken` | Base64, variable length | `__RequestVerificationToken=CfD...` |
| **Django** | `sessionid` | Hex string, 32 chars | `sessionid=abc123def456789...` |
| **Rails** | `_session_id` or `_AppName_session` | Signed/encrypted cookie (base64) | Long base64 string with `--` separator |
| **Express/Node** | `connect.sid` | `s:` prefix + signed value | `connect.sid=s%3Aabc123.signature` |
| **Flask** | `session` | Base64-encoded signed JSON | `session=eyJ...` (looks like JWT) |
| **ColdFusion** | `CFID` + `CFTOKEN` | Numeric | `CFID=12345;CFTOKEN=67890abc` |
| **Spring** | `JSESSIONID` | Same as J2EE | UUID or random hex |
| **Laravel** | `laravel_session` | Encrypted + MAC'd value | Long base64 string |

**Detection regex examples:**
```
# PHP session ID
PHPSESSID[=:]\s*[a-zA-Z0-9,-]{22,40}

# Java session ID
JSESSIONID[=:]\s*[A-F0-9]{32}

# ASP.NET session ID
ASP\.NET_SessionId[=:]\s*[a-zA-Z0-9]{20,30}

# Django session ID
sessionid[=:]\s*[a-f0-9]{32}

# Express signed session
connect\.sid[=:]\s*s(%3A|:)[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+
```

### 3.3 Session ID Security Requirements

Per OWASP, session identifiers must have at least 64 bits of entropy. A strong CSPRNG must be
used for generation. Session IDs should be at least 128 bits (16 bytes) long to prevent
brute-force guessing.

### 3.4 Secure/HttpOnly Cookie Flags and Memory

Cookie security flags affect where cookies are accessible:

- **HttpOnly:** Cookie not accessible via JavaScript (`document.cookie`), but still present in
  browser process memory and sent in HTTP headers
- **Secure:** Only sent over HTTPS, but still stored in memory in plaintext after TLS decryption
- **SameSite:** Controls cross-origin sending; no impact on memory presence
- **Important:** All cookies, regardless of flags, exist in plaintext in process memory once
  decrypted from TLS

### 3.5 Chrome Cookie Encryption and Decryption

Chrome stores cookies in an SQLite database (`Cookies` file in the user data directory).

#### Encryption evolution:
| Chrome Version | Encryption Method | Forensic Approach |
|---------------|-------------------|-------------------|
| **Pre-80** | DPAPI directly | Decrypt with user's DPAPI master key |
| **80-126** | AES-256-GCM, key encrypted with DPAPI | Decrypt DPAPI key from `Local State` JSON, then AES-GCM decrypt |
| **127+** | App-Bound Encryption (User-DPAPI + System-DPAPI) | Requires live system; elevation service decryption |

**Cookie database location (Windows):**
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
```

**Encryption key location:**
```
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
```
The `Local State` JSON file contains `os_crypt.encrypted_key` — a base64-encoded key
prefixed with `DPAPI` and encrypted with the user's DPAPI master key.

**Encrypted cookie format (v10/v11):**
```
[3-byte prefix: "v10" or "v11"] [12-byte nonce/IV] [ciphertext + 16-byte GCM tag]
```

**Chrome 127+ App-Bound Encryption:**
- Cookies encrypted with a key first protected by User-DPAPI, then by System-DPAPI
- Decryption delegated to COM elevation service running as SYSTEM
- Breaks traditional "dead-box" forensic workflow — requires live system or process injection
- Known bypass: C4 attack (CyberArk) exploits CBC padding oracle on DPAPI layer in CBC mode;
  by feeding tampered encrypted cookie blobs into Chrome's elevation service and analyzing
  whether the error was a padding failure or a signature mismatch, the attacker has a live
  oracle that can byte-by-byte decrypt SYSTEM-level DPAPI data
- Process hollowing techniques: create suspended browser process, inject decryption code
- Malicious browser extensions inherit the browser's trusted identity, bypassing App-Bound
  Encryption from within the authorized process

**Chrome 136+ Additional Protections:**
- `--remote-debugging-port` switch is ignored unless accompanied by `--user-data-dir`
  pointing to a non-standard directory, forcing the user to re-authenticate
- This closes the remote-debugging-based cookie theft vector used by infostealers
- Memory-based extraction (process injection into chrome.exe) remains the primary
  attack surface for post-136 cookie theft

### 3.6 Firefox Cookie Storage

Firefox uses NSS (Network Security Services) for encryption:
- Cookie database: `cookies.sqlite` in the profile directory
- Key storage: `key4.db` (contains master key, optionally protected by Primary Password)
- Offline forensics still works for Firefox (no App-Bound Encryption equivalent)

### 3.7 Set-Cookie Headers in HTTP Response Buffers

`Set-Cookie` response headers persist in HTTP response buffer memory of both web servers and
browsers. These contain the full cookie value, domain, path, and flags.

**Detection pattern:**
```
Set-Cookie:\s*[A-Za-z0-9_.-]+=[^;\r\n]+
```

---

## 4. SAML Tokens

### 4.1 SAML Assertion XML Structure

SAML assertions are XML documents containing authentication statements. In memory, they appear
as raw XML or base64-encoded XML.

**Key XML elements to search for:**
```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123"
    IssueInstant="2024-01-01T00:00:00Z"
    Version="2.0">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="..." NotOnOrAfter="...">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="...">
    ...
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

**Detection strings (case-sensitive):**
```
saml:Assertion
saml2:Assertion
urn:oasis:names:tc:SAML:2.0:assertion
urn:oasis:names:tc:SAML:2.0:protocol
<samlp:Response
<saml:Issuer
<saml:Subject
<saml:NameID
<saml:Conditions
<saml:AuthnStatement
<saml:AttributeStatement
```

### 4.2 SAML Response Base64 Blobs

SAML responses are transmitted via HTTP POST as base64-encoded form values:

```
SAMLResponse=PHNhbWxwOlJlc3BvbnNl...
```

The base64-decoded value is a full XML document containing the SAML assertion. **This is not
encrypted** — only encoded for transport. A captured base64 blob from memory can be decoded to
reveal the full assertion.

**Detection regex:**
```
SAMLResponse[=:]\s*[A-Za-z0-9+/=]{100,}
```

The base64 of `<samlp:Response` starts with `PHNhbWxwOlJlc3BvbnNl`, which is a useful
fixed-prefix search pattern.

### 4.3 X.509 Certificates in SAML

SAML assertions are signed with X.509 certificates. The signing certificate's public key is
embedded in the assertion:

```xml
<ds:X509Certificate>MIIDpDCCA...</ds:X509Certificate>
```

**The token-signing private key** is the critical asset. If an attacker obtains it, they can
forge arbitrary SAML assertions (Golden SAML attack).

### 4.4 Golden SAML Attack

Analogous to Kerberos Golden Ticket. If the token-signing private key is compromised:
- Attacker can forge SAML responses for any user, any role, any service provider
- Bypasses MFA (assertion already represents completed authentication)
- Works against any SP trusting the compromised IdP (Azure, AWS, vSphere, etc.)
- Discovered by CyberArk Labs

**Forensic indicators of Golden SAML:**
- Assertions signed by unexpected certificates
- Assertions with unusual attribute values or claim combinations
- Authentication events with no corresponding login event at the IdP (primary detection signal:
  TGS requests without corresponding TGT issuance at KDC)
- Timing anomalies between assertion creation and IdP logs
- First observed in the wild during the SolarWinds/Solorigate supply-chain attack (2020);
  attacker compromised AD FS token-signing certificate to forge SAML assertions at scale

**Event log correlation for Golden SAML detection:**

| Source | Event ID | Description |
|--------|----------|-------------|
| AD FS | 1200 | Federation Service issued a valid token |
| AD FS | 1202 | Federation Service validated a new credential |
| Domain Controller | 4769 | A Kerberos service ticket was requested |

When a forged SAML token is used, there will be **no event on the AD FS server** to correlate
with the service provider sign-in log -- this absence is the strongest detection signal.

**Certificate extraction vectors to monitor:**
- Exporting from the AD FS `ServiceSettings` table (most common technique, used by ADFSDump)
- Extracting the encrypted DKM (Distributed Key Manager) key from Active Directory
- Patching `CryptoApi` and memory protections in `lsass.exe` for live extraction

**Detection tooling:**
- Microsoft Entra ID Protection: Token Issuer Anomaly, Session Token Anomaly detections
- Microsoft Defender for Identity: suspicious AD FS DKM key read detection

### 4.5 Enterprise SSO Provider Patterns

| Provider | SAML Endpoint Pattern | Issuer Format |
|----------|----------------------|--------------|
| **Okta** | `https://{org}.okta.com/app/{app}/sso/saml` | `http://www.okta.com/{externalKey}` |
| **Azure AD** | `https://login.microsoftonline.com/{tenantId}/saml2` | `https://sts.windows.net/{tenantId}/` |
| **OneLogin** | `https://{subdomain}.onelogin.com/trust/saml2/http-post/sso/{appId}` | `https://app.onelogin.com/saml/metadata/{appId}` |
| **Google Workspace** | `https://accounts.google.com/o/saml2/idp` | `https://accounts.google.com/o/saml2?idpid={id}` |
| **PingIdentity** | `https://sso.connect.pingidentity.com/sso/sp/SSO.saml2` | Provider-specific |

### 4.6 Where SAML Tokens Reside in Memory

1. **Browser process memory:** POST form data containing `SAMLResponse`
2. **Web server process memory:** POST body parsing buffers
3. **SSO agent process memory:** Desktop SSO agents (Okta Verify, Azure AD Connect)
4. **IdP server memory:** Token generation and signing buffers
5. **Network proxy buffers:** TLS-terminating proxies may hold decoded SAML responses

---

## 5. API Keys and Service Tokens

### 5.1 Comprehensive API Key Pattern Reference

#### Cloud Providers

| Provider | Token Type | Prefix/Pattern | Regex |
|----------|-----------|----------------|-------|
| **AWS** | Access Key (long-term) | `AKIA` | `AKIA[0-9A-Z]{16}` |
| **AWS** | Access Key (temporary) | `ASIA` | `ASIA[A-Z2-7]{16}` |
| **AWS** | Secret Access Key | (no prefix) | `[A-Za-z0-9/+=]{40}` (near access key) |
| **Google Cloud** | Service Account Key | JSON with `"type": "service_account"` | Look for `"private_key_id"` and `"private_key"` fields |
| **Google Cloud** | OAuth Client Secret | `GOCSPX-` | `GOCSPX-[A-Za-z0-9_-]{28}` |
| **Azure** | Service Principal Secret | (UUID-like) | `[a-zA-Z0-9~._-]{34}` (in context of client_secret) |
| **Azure** | SAS Token | `sig=` | `sig=[A-Za-z0-9%/+=]+&se=[0-9]+&...` |

#### Source Control & CI/CD

| Provider | Token Type | Prefix | Regex |
|----------|-----------|--------|-------|
| **GitHub** | Personal Access Token | `ghp_` | `ghp_[0-9a-zA-Z]{36}` |
| **GitHub** | OAuth App Token | `gho_` | `gho_[0-9a-zA-Z]{36}` |
| **GitHub** | User-to-Server Token | `ghu_` | `ghu_[0-9a-zA-Z]{36}` |
| **GitHub** | Server-to-Server Token | `ghs_` | `ghs_[0-9a-zA-Z]{36}` |
| **GitHub** | Refresh Token | `ghr_` | `ghr_[0-9a-zA-Z]{36}` |
| **GitHub** | Fine-Grained PAT | `github_pat_` | `github_pat_[A-Za-z0-9_]{22,}` |
| **GitLab** | Personal Access Token | `glpat-` | `glpat-[A-Za-z0-9_-]{20,}` |
| **GitLab** | Pipeline Trigger | `glptt-` | `glptt-[A-Za-z0-9_-]{20,}` |
| **Bitbucket** | App Password | (no prefix) | Context-dependent |
| **npm** | Access Token | `npm_` | `npm_[A-Za-z0-9]{36}` |
| **PyPI** | API Token | `pypi-` | `pypi-[A-Za-z0-9_-]{50,}` |

#### Payment & Commerce

| Provider | Token Type | Prefix | Regex |
|----------|-----------|--------|-------|
| **Stripe** | Secret Key (live) | `sk_live_` | `sk_live_[A-Za-z0-9]{24,}` |
| **Stripe** | Secret Key (test) | `sk_test_` | `sk_test_[A-Za-z0-9]{24,}` |
| **Stripe** | Publishable Key (live) | `pk_live_` | `pk_live_[A-Za-z0-9]{24,}` |
| **Stripe** | Restricted Key (live) | `rk_live_` | `rk_live_[A-Za-z0-9]{24,}` |
| **PayPal** | Client ID | (no standard prefix) | Context-dependent |
| **Square** | Access Token | `sq0atp-` | `sq0atp-[A-Za-z0-9_-]{22,}` |
| **Square** | Application Secret | `sq0csp-` | `sq0csp-[A-Za-z0-9_-]{43,}` |

#### Communication & Messaging

| Provider | Token Type | Prefix | Regex |
|----------|-----------|--------|-------|
| **Slack** | Bot Token | `xoxb-` | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}` |
| **Slack** | User Token | `xoxp-` | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}` |
| **Slack** | App-Level Token | `xapp-` | `xapp-[0-9]-[A-Z0-9]+-[0-9]+-[A-Za-z0-9]+` |
| **Slack** | Export Token | `xoxe-` | `xoxe-[0-9]-[A-Za-z0-9]{146,}` |
| **Slack** | Workflow Token | `xwfp-` | `xwfp-[A-Za-z0-9]+` |
| **Slack** | Workspace Access | `xoxa-2` | `xoxa-2-[A-Za-z0-9-]+` |
| **Slack** | Workspace Refresh | `xoxr-` | `xoxr-[A-Za-z0-9-]+` |
| **Slack** | Session Token | `xoxs-` | `xoxs-[0-9]+-[0-9]+-[A-Za-z0-9-]+` |
| **Slack** | Webhook | `hooks.slack.com/services/T` | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` |
| **Twilio** | API Key | `SK` | `SK[a-f0-9]{32}` |
| **Twilio** | Account SID | `AC` | `AC[a-f0-9]{32}` |
| **SendGrid** | API Key | `SG.` | `SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}` |
| **Mailgun** | API Key | `key-` | `key-[a-f0-9]{32}` |
| **Discord** | Bot Token | (no standard prefix) | `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` |
| **Telegram** | Bot Token | (numeric:alphanum) | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` |

#### Infrastructure & Monitoring

| Provider | Token Type | Prefix | Regex |
|----------|-----------|--------|-------|
| **Datadog** | API Key | (no prefix) | `[a-f0-9]{32}` (context-dependent) |
| **New Relic** | License Key | (no prefix) | `[A-Za-z0-9]{40}` (context-dependent) |
| **PagerDuty** | API Key | (no prefix) | Context-dependent |
| **Heroku** | API Key | (UUID format) | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| **DigitalOcean** | PAT | `dop_v1_` | `dop_v1_[a-f0-9]{64}` |
| **Cloudflare** | API Token | (no prefix) | `[A-Za-z0-9_-]{40}` (context: `CF-Access-Token`) |

#### Docker & Container

| Provider | Token Type | Format | Notes |
|----------|-----------|--------|-------|
| **Docker Hub** | Registry Token | JWT Bearer | Transmitted as `Authorization: Bearer <JWT>` |
| **Docker Hub** | Credentials | Base64(user:pass) | Stored in `~/.docker/config.json`, base64 encoded (NOT encrypted) |
| **Docker Hub** | Refresh Token | Opaque | No expiration, reusable indefinitely |
| **Docker Hub** | PAT | `dckr_pat_` | `dckr_pat_[A-Za-z0-9_-]{24,}` |

### 5.2 Google Cloud Service Account JSON Keys

Service account keys are JSON files that may persist in process memory:

```json
{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "key-id-hex",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
  "client_email": "sa-name@project.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

**Detection strings:**
```
"type": "service_account"
"private_key_id"
.iam.gserviceaccount.com
```

### 5.3 False Positive Mitigation

- **Entropy analysis:** Genuine API keys have high entropy (>4.5 bits/char). Combine regex
  matching with entropy thresholds to reduce false positives.
- **Context validation:** Keys near keywords like `api_key`, `secret`, `token`, `password`,
  `authorization`, `bearer` are more likely genuine.
- **Length validation:** Most API keys have specific lengths; validate match length.
- **Character set validation:** Some keys use restricted charsets (e.g., AWS uses base32-like).
- **Structural validation:** Some keys have internal structure (e.g., Slack tokens have numeric
  segments separated by hyphens).
- **Live verification:** Make safe API calls to confirm liveness (e.g., `aws sts get-caller-identity`
  for AWS keys, test request for Stripe keys). TruffleHog v3 verifies credentials against 800+
  service APIs automatically.

**Shannon entropy thresholds by encoding:**

| Encoding | Recommended Threshold | Max Possible | Tool Default |
|----------|----------------------|-------------|-------------|
| **Hex** (0-9, a-f) | 3.0 | ~4.0 | `detect-secrets` HexHighEntropyString: 3.0 |
| **Base64** (A-Z, a-z, 0-9, +, /) | 4.5 | ~6.0 | `detect-secrets` Base64HighEntropyString: 4.5 |
| **ASCII (full)** | 5.0-5.5 | ~8.0 | -- |

**Entropy ranges and data classification:**

| Entropy Range | Typical Data |
|---------------|-------------|
| 0-1 | Repetitive data (null bytes, padding) |
| 3-5 | Normal text, source code, configuration files |
| 5-6 | Minified/lightly obfuscated code |
| 6-7.5 | Packed executables, heavy obfuscation, Base64-encoded content |
| 7.5-8 | Encryption, compression, or high-quality random data |

Source code has an upper bound entropy of ~5.25 vs ~4.0 for plain English. A maximally random
numeric string may not exceed source code entropy -- combine entropy with format-aware regex
and context signals for best results. Build the probability distribution from the string itself
(self-entropy) rather than a fixed character set for more accurate measurements.

### 5.4 Where API Keys Reside in Memory

1. **Environment variables:** `$API_KEY`, `$SECRET_KEY`, etc. in process environment block
2. **Configuration file content:** Parsed YAML/JSON/TOML configs loaded into memory
3. **HTTP request headers:** `Authorization: Bearer ...`, `X-API-Key: ...`
4. **SDK/client library objects:** AWS SDK credential chain, Google Cloud auth library
5. **Shell history:** Commands containing keys (bash/zsh history loaded in shell process memory)
6. **CI/CD runner memory:** Build processes with injected secrets

### 5.5 Reference Resources

- [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db): 1,600+ regex patterns
  in YAML format, supporting TruffleHog and Gitleaks
- [secret-regex-list](https://github.com/h33tlit/secret-regex-list): Curated JSON list of
  common provider patterns
- [YARA-Secrets](https://github.com/MrSuicideParrot/Yara-Secrets): YARA rules for detecting
  passwords, API keys, and tokens in files and memory
- [Nightfall Regex Library](https://help.nightfall.ai/detection_platform/regex_library):
  Commercial regex library with confidence-scored patterns

---

## 6. Kerberos Tickets

### 6.1 TGT and Service Ticket Overview

| Ticket Type | Purpose | Encrypted With | Typical Lifetime |
|-------------|---------|---------------|-----------------|
| **TGT** (Ticket-Granting Ticket) | Authenticate to KDC for service ticket requests | User's password hash (DES/AES) | 10 hours (default) |
| **Service Ticket (ST/TGS)** | Authenticate to a specific service | Service account's password hash | 10 hours (default) |

### 6.2 AS-REP and TGS-REP Structures

**AS-REP** (Authentication Service Reply): Contains the TGT, encrypted with the user's key.
Look for ASN.1 structures with Kerberos application tags:

- AS-REP: Application tag 11 (`0x6B`)
- TGS-REP: Application tag 13 (`0x6D`)
- AP-REQ: Application tag 14 (`0x6E`)
- AP-REP: Application tag 15 (`0x6F`)

**ASN.1 DER prefix for Kerberos tickets (hex):**
```
# AS-REP
6B [length bytes] 30 ...

# TGS-REP
6D [length bytes] 30 ...
```

### 6.3 Credential Cache (ccache) Format

#### File-based ccache (Linux: `/tmp/krb5cc_{UID}`)

**File header format:**
```
Offset  Size    Description
0x0000  2       File format version (0x0504 for format version 4)
0x0002  2       Header length (version 4 only)
0x0004  varies  Header tags (version 4 only)
...     varies  Default principal
...     varies  Credential entries (one per ticket)
```

**Each credential entry contains:**
- Client principal
- Server principal
- Key block (encryption type + key data)
- Authentication time, start time, end time, renew-till
- Ticket flags
- Addresses
- Authorization data
- Ticket data (the actual Kerberos ticket blob)
- Second ticket (for user-to-user authentication)

#### ccache Storage Types

| Type | Location | Forensic Access |
|------|----------|----------------|
| **FILE** | `/tmp/krb5cc_{UID}` | File on disk or in memory-mapped regions |
| **KEYRING** | Linux kernel keyring | Only accessible from kernel memory; process must use `keyctl` |
| **MEMORY** | Process heap | Destroyed when process exits; only in memory dumps |
| **API** | Windows LSASS | Via LSASS process memory dump |
| **KCM** | macOS/sssd daemon | Via KCM daemon process memory |

#### ccache vs kirbi Format

- **ccache:** Used by MIT Kerberos / Heimdal / Linux / macOS tools (Impacket, etc.)
- **kirbi:** Used by Mimikatz / Rubeus on Windows (base64-encoded ASN.1)
- **Conversion:** `ticket_converter` (Metasploit), `ticketConverter.py` (Impacket)

### 6.4 Kerberoasting: Extractable Service Ticket Hashes

Kerberoasting targets service accounts with SPNs (Service Principal Names). The attack flow:

1. Request TGS for SPN-associated service (any domain user can do this)
2. Extract the encrypted service ticket from memory or ccache
3. Crack offline — the ticket is encrypted with the service account's password hash

**Hashcat format for Kerberoast hashes:**
```
$krb5tgs$23$*user$realm$spn*$checksum$encrypted_data
```

**Detection regex for kirbi files in memory (base64-encoded):**
```
# Base64 of Kerberos ticket ASN.1 structures
doI[A-Za-z0-9+/]{4,}
```

**Tools:**
- **pypykatz:** Parses ccache files into hashcat-crackable format
- **Rubeus:** Windows tool for Kerberos abuse (kerberoast, asreproast, ticket extraction)
- **Impacket:** Python tools including `GetNPUsers.py`, `GetUserSPNs.py`

### 6.5 Windows LSASS Kerberos Ticket Cache

LSASS stores all active Kerberos tickets for logged-on users. Extraction methods:

| Method | Tool | Privileges Required |
|--------|------|-------------------|
| Direct memory read | Mimikatz `sekurlsa::tickets /export` | Local admin / SeDebugPrivilege |
| Process dump | Task Manager, ProcDump, comsvcs.dll | Local admin |
| Memory dump file | Volatility, pypykatz | Access to dump file |
| Snapshot/hibernate | VMware .vmem, hiberfil.sys | Access to file |

**Mimikatz `sekurlsa::tickets` output:**
- Exports `.kirbi` files named with LUID and group number
- Group 0 = TGS (service tickets)
- Group 1 = client tickets
- Group 2 = TGT

**LSA Protection (RunAsPPL):**
- Marks LSASS as a Protected Process Light (PPL)
- Blocks unauthorized memory reads and code injection
- Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` = `1`
- Bypasses exist (Mimikatz driver `mimidrv.sys`) but leave forensic traces in event logs

### 6.6 Detection Signatures

**Memory patterns for Kerberos tickets:**
```
# ASN.1 application tags (hex bytes) — first byte identifies message type
76 82    # KRB-CRED (APPLICATION 22) — kirbi file / Mimikatz dump format
6B 82    # AS-REP (APPLICATION 11) start
6D 82    # TGS-REP (APPLICATION 13) start
6E 82    # AP-REQ (APPLICATION 14) start
74 82    # KRB-ERROR (APPLICATION 30) start

# ccache file magic bytes
05 04    # ccache version 4 (most common modern format)
05 03    # ccache version 3
05 02    # ccache version 2
05 01    # ccache version 1 (native byte order)

# Keytab file magic bytes
05 02    # keytab version 2 (big-endian)
05 01    # keytab version 1 (native byte order)

# Kerberos realm strings
@DOMAIN.COM
@CORP.CONTOSO.COM
krbtgt/DOMAIN.COM

# Ticket encryption types (in ASN.1)
0x17 = RC4-HMAC (etype 23) — vulnerable to Kerberoasting
0x12 = AES256-CTS-HMAC-SHA1-96 (etype 18)
0x11 = AES128-CTS-HMAC-SHA1-96 (etype 17)

# ccache configuration entries (embedded in credential cache)
X-CACHECONF:     # realm field of config entries
krb5_ccache_conf_data    # first component of config entry server principal
```

**KRB-CRED ASN.1 structure (kirbi format, per RFC 4120):**
```asn1
KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    pvno        [0] INTEGER,          -- always 5
    msg-type    [1] INTEGER,          -- always 22
    tickets     [2] SEQUENCE OF Ticket,
    enc-part    [3] EncryptedData     -- EncKrbCredPart
}
```

**Golden/Silver ticket forensic indicators:**
- **Encryption type anomaly:** Forged tickets frequently use RC4 (etype 23) because older
  attack tools default to it. In AES-enforced environments, any RC4-encrypted ticket is
  a high-confidence indicator of forgery.
- **Abnormal ticket lifetimes:** TGT/TGS with end or renew-till values exceeding domain
  policy (e.g., >24 hours, or 10+ year Golden Tickets from Mimikatz defaults).
- **Non-existent principals:** Tickets for usernames or SPNs that don't exist in AD.
- **Key version number (kvno) inconsistency:** Unusual or stale kvno values may indicate
  forged tickets.
- **TGS without TGT:** Event 4769 (TGS request) without prior 4768 (TGT request) in
  Windows Security logs indicates an offline-forged TGT.

**Event log correlation (supplement memory analysis):**

| Event ID | Source | Description | Detection Use |
|----------|--------|-------------|---------------|
| 4768 | Security | TGT requested (AS-REQ) | Baseline for legitimate auth |
| 4769 | Security | Service ticket requested (TGS-REQ) | Correlate with 4768; orphan = forged TGT |
| 4624 | Security | Successful logon | Cross-reference with ticket issuance |
| 4771 | Security | Kerberos pre-auth failed | Detect AS-REP roasting attempts |

**False positive considerations:**
- Legitimate Kerberos traffic in service processes
- Old/expired tickets still in memory (check validity period)
- Kerberos-related config strings (krb5.conf contents)
- ccache configuration entries are not valid ticket encodings (check `X-CACHECONF:` realm)

---

## 7. CSRF Tokens / Nonces

### 7.1 Anti-CSRF Token Patterns

CSRF tokens protect against cross-site request forgery by embedding a secret value in forms
or headers that must match the server-side session state.

**Common delivery mechanisms:**
- Hidden form fields: `<input type="hidden" name="csrf_token" value="...">`
- Custom HTTP headers: `X-CSRF-Token`, `X-XSRF-TOKEN`
- Double-submit cookies: Token in both cookie and form field

### 7.2 Framework-Specific CSRF Token Formats

#### WordPress `wpnonce`

- **Format:** 10-character hex hash (e.g., `b05b7aedf8`)
- **Generation:** `wp_create_nonce($action)` — hash based on current time, action, user ID,
  and session token
- **Lifetime:** 24 hours (12 hours per "tick" — value of 1 means <12h, 2 means 12-24h)
- **Cookie name:** `_wpnonce` (URL parameter or form field)
- **Header:** `X-WP-Nonce` (for REST API / AJAX requests)

**Detection patterns:**
```
_wpnonce[=:]\s*[a-f0-9]{10}
X-WP-Nonce:\s*[a-f0-9]{10}
wp_nonce_field|wp_create_nonce|wp_verify_nonce
```

#### Django CSRF Token

- **Format:** 64-character masked token (changed per response for BREACH protection)
- **Cookie name:** `csrftoken` (configurable via `CSRF_COOKIE_NAME`)
- **Form field name:** `csrfmiddlewaretoken`
- **Header:** `X-CSRFToken` (for AJAX)
- **Internal structure:** The token is masked with a random value on each response.
  Validation compares unmasked secrets (not full tokens).
- **Rotation:** Token rotated on login; old tokens become invalid

**Detection patterns:**
```
csrfmiddlewaretoken[=:]\s*[A-Za-z0-9]{64}
csrftoken[=:]\s*[A-Za-z0-9]{64}
X-CSRFToken:\s*[A-Za-z0-9]{64}
```

#### ASP.NET Anti-Forgery Token

- **Format:** Base64-encoded encrypted/signed token
- **Cookie name:** `__RequestVerificationToken` or `.AspNetCore.Antiforgery.*`
- **Form field:** `__RequestVerificationToken`
- **Format prefix:** `CfD` (for ASP.NET Core data protection tokens)

**Detection patterns:**
```
__RequestVerificationToken[=:]\s*[A-Za-z0-9+/=_-]{50,}
```

#### Rails CSRF Token

- **Format:** Base64-encoded, 32-byte random value
- **Meta tag:** `<meta name="csrf-token" content="...">`
- **Form field:** `authenticity_token`
- **Header:** `X-CSRF-Token`

### 7.3 Content-Security-Policy Nonces

CSP nonces prevent inline script execution unless the script tag includes a matching nonce.

- **Format:** Random base64-encoded string, at least 128 bits (16 bytes) of cryptographic randomness
- **CSP header:** `Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic'`
- **HTML:** `<script nonce="{RANDOM}">...</script>`
- **Lifetime:** Single request only (new nonce per response)
- **Security note:** Nonce values are hidden from `getAttribute('nonce')` in DOM for security

**Detection patterns in memory:**
```
nonce-[A-Za-z0-9+/=]{22,}
nonce="[A-Za-z0-9+/=]{22,}"
```

### 7.4 OAuth State Parameters

The `state` parameter in OAuth flows prevents CSRF by binding the authorization request to the
user's session.

- **Format:** Opaque string, typically base64-encoded random value or JSON
- **Typical length:** 16-128 characters
- **Sent in:** Authorization request URL and callback URL

**Detection:**
```
[?&]state=[A-Za-z0-9_-]{16,}
```

### 7.5 Forensic Value of CSRF/Nonce Artifacts

- **CSRF tokens** link form submissions to specific user sessions — useful for attributing actions
- **CSP nonces** tie to specific HTTP responses — useful for timeline reconstruction
- **OAuth state values** correlate authorization requests with callbacks
- All are transient and may only exist in memory during active HTTP request/response cycles

---

## 8. TOTP/HOTP Secrets

### 8.1 TOTP Secret Key Format

TOTP (Time-based One-Time Password, RFC 6238) and HOTP (HMAC-based OTP, RFC 4226) use shared
secret keys.

- **Encoding:** Base32 (characters `A-Z` and `2-7`, case-insensitive)
- **Typical length:** 16-32 base32 characters (80-160 bits of entropy)
- **Raw key:** 10-20 bytes of random data
- **The secret is NOT encrypted** in the QR code or `otpauth://` URI — it is only base32-encoded

### 8.2 `otpauth://` URI Format

The standard URI format used by authenticator apps:

```
otpauth://totp/ISSUER:ACCOUNT?secret=BASE32SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
otpauth://hotp/ISSUER:ACCOUNT?secret=BASE32SECRET&issuer=ISSUER&counter=0&digits=6
```

**URI components:**
| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| `secret` | Base32-encoded shared secret | (required) | A-Z, 2-7 |
| `issuer` | Service name | (recommended) | String |
| `algorithm` | Hash algorithm | SHA1 | SHA1, SHA256, SHA512 |
| `digits` | OTP length | 6 | 6 or 8 |
| `period` | Time step (TOTP only) | 30 | Seconds |
| `counter` | Counter (HOTP only) | (required for HOTP) | Integer |

### 8.3 Google Authenticator Migration Format

Google Authenticator export uses a different URI scheme:

```
otpauth-migration://offline?data=BASE64_PROTOBUF_DATA
```

The `data` parameter contains a base64-encoded Protocol Buffer message containing all TOTP
secrets from the app. Tools like `extract_otp_secrets` can decode this.

### 8.4 Where TOTP/HOTP Secrets Reside in Memory

1. **Authenticator app process memory:** Google Authenticator, Authy, Microsoft Authenticator
   store secrets in their app heap while running
2. **Browser extension memory:** 1Password, Bitwarden browser extensions that support TOTP
3. **Password manager memory:** KeePass stores TOTP secrets in `TimeOtp-Secret-Base32` fields;
   1Password stores them as part of vault entries
4. **QR code renderer memory:** When generating QR codes for TOTP enrollment, the `otpauth://`
   URI persists in the generating process memory
5. **Clipboard:** Users may copy TOTP setup keys through clipboard
6. **Mobile device memory:** App sandbox memory (requires root/jailbreak or physical dump)

### 8.5 Detection Signatures

**Primary search patterns:**
```
# otpauth URI (highest confidence)
otpauth://(?:totp|hotp)/[^\s]{10,}

# otpauth migration URI
otpauth-migration://offline\?data=[A-Za-z0-9+/=]+

# Base32 secret (lower confidence, many false positives)
# Look for 16-32 char strings from the base32 alphabet
[A-Z2-7]{16,32}

# Base32 secret near context keywords
(?:secret|totp|hotp|otp|2fa|mfa)[=:"\s]+[A-Z2-7]{16,32}
```

**False positive considerations:**
- Base32 strings are common in many contexts (Kerberos, AWS IDs, etc.)
- Must validate with context: look for nearby `otpauth`, `totp`, `secret`, `2fa` keywords
- Length validation: TOTP secrets are typically exactly 16 or 32 base32 characters
- Character set: only uppercase A-Z and digits 2-7 (no 0, 1, 8, 9)

### 8.6 Security Implications

Recovered TOTP secrets allow:
- Generation of valid TOTP codes at any future time
- Complete bypass of TOTP-based MFA for the associated account
- Persistent access until the TOTP secret is rotated by the service

**Tools:**
- [`extract_otp_secrets`](https://github.com/scito/extract_otp_secrets): Extract OTP secrets
  from Google Authenticator QR exports
- [`oathtool`](https://www.nongnu.org/oath-toolkit/man-oathtool.html): Generate TOTP/HOTP codes
  from recovered secrets (supports base32 input with `-b` flag)

---

## 9. Certificate Private Keys

### 9.1 PEM Format Markers

PEM (Privacy-Enhanced Mail) format wraps DER-encoded binary data in base64 with
header/footer markers.

**Search strings for private keys in memory:**
```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

**Corresponding footer:**
```
-----END RSA PRIVATE KEY-----
-----END EC PRIVATE KEY-----
-----END PRIVATE KEY-----
-----END ENCRYPTED PRIVATE KEY-----
-----END DSA PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
-----END PGP PRIVATE KEY BLOCK-----
```

**Key type breakdown:**
| PEM Header | Format | Key Type |
|-----------|--------|----------|
| `BEGIN RSA PRIVATE KEY` | PKCS#1 | RSA only |
| `BEGIN EC PRIVATE KEY` | SEC 1 | EC only |
| `BEGIN PRIVATE KEY` | PKCS#8 | Any algorithm (RSA, EC, Ed25519, etc.) |
| `BEGIN ENCRYPTED PRIVATE KEY` | PKCS#8 encrypted | Any algorithm, password-protected |
| `BEGIN OPENSSH PRIVATE KEY` | OpenSSH format | Any (ssh-rsa, ssh-ed25519, ecdsa) |

### 9.2 PKCS#8 DER Format in Memory (No Markers)

PKCS#8 (RFC 5958) is a standard ASN.1 structure for private keys. In DER encoding (binary),
there are no PEM markers, making detection harder.

**ASN.1 structure of PKCS#8 PrivateKeyInfo:**
```
SEQUENCE {
  INTEGER 0                          -- version
  SEQUENCE {                         -- algorithm identifier
    OID ...                          -- algorithm OID
    [parameters]
  }
  OCTET STRING {                     -- private key data
    ...
  }
}
```

**DER hex patterns:**
```
# RSA PKCS#8 (unencrypted) — OID 1.2.840.113549.1.1.1
30 82 [2 bytes length] 02 01 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01

# EC P-256 PKCS#8 — OID 1.2.840.10045.3.1.7
30 [length] 02 01 00 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07

# EC P-384 PKCS#8 — OID 1.3.132.0.34
30 [length] 02 01 00 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22

# Ed25519 PKCS#8 — OID 1.3.101.112
30 [length] 02 01 00 30 05 06 03 2B 65 70
```

**PKCS#1 RSA key DER patterns:**
```
# RSA PKCS#1 private key start
30 82 [2 bytes length] 02 01 00 02 82 [2 bytes length]
```

### 9.3 PKCS#12/PFX Containers

PKCS#12 (.pfx, .p12) files bundle private key + certificate + chain.

**File magic bytes:** None standard; PFX files start with ASN.1 SEQUENCE containing OIDs
for PKCS#12 data types.

**Detection in memory:**
- Search for OID `1.2.840.113549.1.12` (PKCS#12) in DER encoding: `06 0A 2A 86 48 86 F7 0D 01 0C`
- Password for PFX may also be in memory near the PFX data

### 9.4 Windows Certificate Store Key Material

#### CAPI (Legacy Cryptographic API)
- **User keys:** `%APPDATA%\Microsoft\Crypto\RSA\{SID}\`
- **Machine keys:** `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys\`
- Protected with DPAPI

#### CNG (Cryptography: Next Generation)
- **User keys:** `%APPDATA%\Microsoft\Crypto\Keys\`
- **Machine keys:** `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys\`
- Protected with DPAPI
- Provider: Microsoft Software Key Storage Provider

#### LSASS and Key Material
- LSASS handles TLS handshakes via Schannel
- `bcryptprimitives.dll` implements user-mode CNG API
- Ephemeral TLS keys (e.g., P-256 ECDHE) reside in LSASS memory
- Private keys protected with DPAPI may be decrypted in LSASS during TLS operations

#### Mimikatz Crypto Module
- `crypto::capi`: Patches CAPI in current process to export "non-exportable" keys
- `crypto::cng`: Patches CNG Key Isolation service in LSASS to export keys
- `crypto::certificates /export`: Exports certificates with private keys

#### SharpDPAPI
- Navigates CAPI vs CNG key storage differences automatically
- With `/machine` flag: escalates to SYSTEM, dumps `DPAPI_SYSTEM` LSA secret, decrypts
  machine DPAPI masterkeys, then decrypts machine certificate private keys

### 9.5 Let's Encrypt / ACME Account Keys

ACME clients store account private keys for authenticating with the ACME server:

| Client | Key Format | Storage Location |
|--------|-----------|-----------------|
| **Certbot** | JWK (JSON Web Key) | `/etc/letsencrypt/accounts/{server}/{hash}/private_key.json` |
| **acme.sh** | PEM | `~/.acme.sh/{server}/account.key` |
| **Traefik** | JSON (in `acme.json`) | Configured path (e.g., `/etc/traefik/acme.json`) |
| **lego** | PEM | `.lego/accounts/{server}/{email}/keys/{email}.key` |

These keys are typically RSA 2048/4096 or ECDSA P-256/P-384. The private key persists in the
ACME client's process memory during certificate issuance and renewal.

### 9.6 Volatility `dumpcerts` Plugin

The Volatility `dumpcerts` plugin scans memory images for RSA private keys and X.509 certificates
by looking for ASN.1 DER-encoded structures.

**Capabilities:**
- Scan physical memory (finds keys in unallocated/freed memory)
- Scan virtual memory (attributes keys to specific processes)
- On the Stuxnet memory image: found 11 private keys and 295 certificates in services.exe,
  svchost.exe, and lsass.exe

**Other extraction tools:**
- `rsakeyfind`: Finds RSA keys in process memory using DER pattern matching
- `findaes`: Finds AES keys using key schedule analysis
- `CryKeX`: Linux memory cryptographic key extractor (entropy + structure analysis)

### 9.7 Detection Challenges

- **EC private keys** (especially P-256 at 32 bytes) are hard to distinguish from other
  pseudo-random values like GUIDs in memory
- **Keys may be encrypted** in memory (DPAPI-protected), matching the pattern but not
  directly usable
- **PEM headers spanning page boundaries** may be missed by simple string searches
- **DER keys without PEM wrappers** require binary pattern matching on ASN.1 structures

### 9.8 DEF CON 24 Research: CNG TLS/SSL from LSASS

Jake Kambic's DEF CON 24 research demonstrated extraction of CNG TLS/SSL artifacts from LSASS
memory, including ephemeral ECDHE private keys. Key findings:

- LSASS handles TLS handshake and key derivation
- Schannel uses `bcryptprimitives.dll` for CNG operations
- P-256 ephemeral private keys are 32 bytes, allocated via CNG
- Session keys and master secrets persist in LSASS memory after TLS session establishment

---

## 10. Password Manager Vault Data

### 10.1 Overview of Memory Security Research

Multiple studies have shown that password managers leave sensitive data in process memory,
including master passwords, vault encryption keys, and individual entry passwords.

**Key research:**
- **ISE (Independent Security Evaluators):** Examined 1Password, Dashlane, KeePass, LastPass
  on Windows 10. Found that each PM attempted to scrub secrets but residual buffers remained.
- **Pandora (2024):** Analyzed 18 PM implementations across Windows apps, browsers, and
  plugins. Found most plugins do not sweep credentials from browser process memory.
- **Password Managers in Digital Forensics (Diva Portal):** Comprehensive forensic analysis
  of PM artifacts including memory, disk, and registry.

### 10.2 1Password

**Memory artifacts:**
- 1Password4: At most a single entry exposed in "running unlocked" state; master password
  exists in obfuscated form but is easily recoverable
- 1Password7/8: Improved memory handling but decrypted vault entries still persist in
  process heap when vault is unlocked
- **Vault location (macOS):** `~/Library/Group Containers/2BUA8C4S2C.com.1password/`
- **Vault location (Windows):** `%LOCALAPPDATA%\1Password\`
- **Key derivation:** PBKDF2-HMAC-SHA256 or Argon2 from master password + secret key
- **Secret Key:** 34-character string (A3-XXXXXX-XXXXXX-...) combined with master password

**Forensic approach:**
- Dump 1Password process memory while vault is unlocked
- Search for JSON structures with keys like `"password"`, `"username"`, `"url"`
- Look for the Account Key (`A3-` prefix) in process memory

### 10.3 LastPass

**Memory artifacts:**
- Master password leaked into a string buffer during key derivation and **never scrubbed**,
  even when placed into locked state
- Once the decryption key is derived, the master password is overwritten with the literal
  string `"lastpass rocks"` — this itself is a forensic indicator
- Decrypted entries persist in memory even after locking

**Detection strings:**
```
lastpass rocks     # Sentinel string replacing master password
lastpass.com       # Domain references in vault entries
"encrypted_data"   # LastPass vault entry format
```

**Vault location:** `%LOCALAPPDATA%\LastPass\` (desktop) or browser extension storage

### 10.4 KeePass

**Critical vulnerability (CVE-2023-32784):**
- Master password can be reconstructed from process memory dump
- Works whether workspace is locked or not
- Works from page file (swap), hibernation file, or live memory dump
- Affects KeePass 2.x prior to 2.54

**Memory artifacts:**
- Master key material in process heap
- Database encryption key after derivation
- Individual entry data when accessed
- TOTP secrets in `TimeOtp-Secret-Base32` custom string fields
- HOTP secrets in `HmacOtp-Secret-Base32` custom string fields

**Vault location:** `.kdbx` file (user-specified)
**Key derivation:** AES-KDF or Argon2d (configurable iterations)

**Forensic tools:**
- Password Manager Forensics (PMF): Python tool for extracting master password and vault
  contents from KeePass memory dumps
- LaZagne: Open-source credential recovery tool supporting KeePass
- Passware Kit: Commercial GPU-accelerated master password brute-force

### 10.5 Bitwarden

**Critical vulnerability (CVE-2023-38840):**
- Master password stored in memory after vault is unlocked at least once
- Remains in memory for a period even after re-locking
- BW-Dump tool extracts master password by reading process memory for magic byte patterns

**Memory artifacts:**
- Master password in plaintext (after first unlock)
- Decrypted vault entries in process heap
- Encryption key derived from master password
- Browser extension: Bitwarden clears browser process memory after 10 minutes (one of the
  better-behaved PMs per Pandora research)

**Vault location:**
- Desktop: `%APPDATA%\Bitwarden\` (Windows), `~/.config/Bitwarden/` (Linux)
- Browser extension: Extension storage within browser profile
- Vault file: Encrypted JSON blob (AES-256-CBC with HMAC-SHA256)

**Key derivation:** PBKDF2-HMAC-SHA256 (default 600,000 iterations) or Argon2id

**Detection strings in memory:**
```
"organizationId"    # Bitwarden vault entry format
"collectionIds"     # Bitwarden organization features
"type":1            # Login type entry
"type":2            # Secure note
"type":3            # Card
"type":4            # Identity
```

### 10.6 General Forensic Approach for Password Managers

1. **Capture memory while PM is unlocked** (or recently locked — data persists)
2. **Identify PM process:** `1Password.exe`, `LastPass.exe`, `KeePass.exe`, `Bitwarden.exe`,
   or browser processes hosting PM extensions
3. **Dump process memory** using Volatility `memdump`/`memmap` or live tools (ProcDump, etc.)
4. **Search for master password indicators:**
   - KeePass: CVE-2023-32784 pattern (partial master password reconstruction)
   - LastPass: `"lastpass rocks"` sentinel string
   - Bitwarden: CVE-2023-38840 magic byte patterns
5. **Search for vault entries:** JSON structures with credential-like fields
6. **Search for encryption keys:** High-entropy byte sequences near PM data structures
7. **Check for vault files:** Encrypted vault databases may also be carved from memory

### 10.7 Forensic Tools

| Tool | Capabilities | License |
|------|-------------|---------|
| **PMF** (Password Manager Forensics) | KeePass & Bitwarden: master password extraction, vault decryption, brute-force | Open source |
| **BW-Dump** | Bitwarden master password from locked vault (CVE-2023-38840) | Open source (PoC) |
| **LaZagne** | Multi-PM credential recovery including KeePass | Open source |
| **Passware Kit** | 1Password, KeePass, Enpass, LastPass, Dashlane + macOS/iOS Keychain | Commercial |
| **Elcomsoft DPR** | Bitwarden, Dropbox Passwords, Enpass, Kaspersky, Keeper, Roboform, Sticky Password, Zoho Vault | Commercial |
| **Volatility** | Generic process memory analysis (dump + strings) | Open source |

### 10.8 Mitigations That Affect Forensic Recovery

- **Full disk encryption:** Prevents offline memory dump access from hibernation/pagefile
- **Key files on removable media:** Master password alone insufficient without key file
- **Close (not lock) PM:** Forces memory cleanup in most implementations
- **Memory encryption:** Some PMs encrypt vault data in memory (limited effectiveness)
- **Strong master password:** Makes brute-force against encrypted vault impractical

---

## Appendix A: YARA Rules for Memory Forensics

> **Note:** YARA-X, the Rust rewrite of YARA by Victor Alvarez, reached its first stable
> release in June 2025 and is now the recommended successor. The original YARA is in
> maintenance mode. YARA-X supports the same rule syntax with improved performance and
> the `base64` / `base64wide` string modifiers for detecting Base64-encoded content
> (directly applicable to SAML tokens, JWT payloads, and Kerberos ticket blobs in memory).
> For a Rust-based tool, YARA-X can be embedded natively via its Rust API.

### A.1 JWT Detection Rule

```yara
rule JWT_Token {
    meta:
        description = "Detects JSON Web Tokens in memory"
        author = "Issen"
        reference = "https://github.com/ticarpi/jwt_tool"

    strings:
        $jwt_alg = /eyJhbGci[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
        $jwt_typ = /eyJ0eXAi[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
        $jwt_kid = /eyJraWQi[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/

    condition:
        any of them
}
```

### A.2 AWS Credential Detection Rule

```yara
rule AWS_Credentials {
    meta:
        description = "Detects AWS access keys and credentials in memory"
        author = "Issen"

    strings:
        $aws_long_term = /AKIA[0-9A-Z]{16}/
        $aws_temporary = /ASIA[A-Z2-7]{16}/
        $aws_env_key = "AWS_ACCESS_KEY_ID"
        $aws_env_secret = "AWS_SECRET_ACCESS_KEY"
        $aws_env_session = "AWS_SESSION_TOKEN"

    condition:
        any of them
}
```

### A.3 Private Key Detection Rule

```yara
rule Private_Key_PEM {
    meta:
        description = "Detects PEM-encoded private keys in memory"
        author = "Issen"

    strings:
        $rsa_key = "-----BEGIN RSA PRIVATE KEY-----"
        $ec_key = "-----BEGIN EC PRIVATE KEY-----"
        $pkcs8_key = "-----BEGIN PRIVATE KEY-----"
        $enc_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $dsa_key = "-----BEGIN DSA PRIVATE KEY-----"
        $openssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----"

    condition:
        any of them
}
```

### A.4 API Key Detection Rule

```yara
rule API_Keys_Common {
    meta:
        description = "Detects common API keys and tokens in memory"
        author = "Issen"

    strings:
        $github_pat = /ghp_[0-9a-zA-Z]{36}/
        $github_oauth = /gho_[0-9a-zA-Z]{36}/
        $github_u2s = /ghu_[0-9a-zA-Z]{36}/
        $github_s2s = /ghs_[0-9a-zA-Z]{36}/
        $github_refresh = /ghr_[0-9a-zA-Z]{36}/
        $github_fine = /github_pat_[A-Za-z0-9_]{22,}/
        $gitlab_pat = /glpat-[A-Za-z0-9_\-]{20}/
        $stripe_live = /sk_live_[A-Za-z0-9]{24}/
        $stripe_test = /sk_test_[A-Za-z0-9]{24}/
        $slack_bot = /xoxb-[0-9]{10,13}-[0-9]{10,13}/
        $slack_user = /xoxp-[0-9]{10,13}-[0-9]{10,13}/
        $slack_app = /xapp-[0-9]-[A-Z0-9]+-[0-9]+/
        $sendgrid = /SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}/
        $twilio = /SK[a-f0-9]{32}/
        $npm_token = /npm_[A-Za-z0-9]{36}/
        $pypi_token = /pypi-[A-Za-z0-9_\-]{50,}/
        $digitalocean = /dop_v1_[a-f0-9]{64}/

    condition:
        any of them
}
```

### A.5 SAML Assertion Detection Rule

```yara
rule SAML_Assertion {
    meta:
        description = "Detects SAML assertions and responses in memory"
        author = "Issen"

    strings:
        $saml_assertion = "saml:Assertion"
        $saml2_assertion = "saml2:Assertion"
        $saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
        $saml_proto = "urn:oasis:names:tc:SAML:2.0:protocol"
        $saml_response = "samlp:Response"
        $saml_b64_prefix = "PHNhbWxwOlJlc3BvbnNl"
        $saml_form = "SAMLResponse"

    condition:
        any of them
}
```

### A.6 TOTP/OTP Secret Detection Rule

```yara
rule TOTP_Secrets {
    meta:
        description = "Detects TOTP/HOTP secrets and otpauth URIs in memory"
        author = "Issen"

    strings:
        $otpauth_totp = "otpauth://totp/"
        $otpauth_hotp = "otpauth://hotp/"
        $otpauth_migration = "otpauth-migration://offline"
        $totp_secret_field = /(?:secret|totp_secret|otp_secret)[=:"]\s*[A-Z2-7]{16,32}/

    condition:
        any of them
}
```

### A.7 Session Cookie Detection Rule

```yara
rule Session_Cookies {
    meta:
        description = "Detects web framework session cookies in memory"
        author = "Issen"

    strings:
        $php_session = /PHPSESSID[=:]\s*[a-zA-Z0-9]{22,40}/
        $java_session = /JSESSIONID[=:]\s*[A-F0-9]{32}/
        $aspnet_session = /ASP\.NET_SessionId[=:]\s*[a-zA-Z0-9]{20,30}/
        $aspnet_auth = ".ASPXAUTH"
        $django_session = /sessionid[=:]\s*[a-f0-9]{32}/
        $express_session = /connect\.sid[=:]\s*s[%:]/
        $laravel_session = "laravel_session"
        $flask_session = "session=" nocase
        $rails_auth = "authenticity_token"

    condition:
        any of them
}
```

### A.8 Password Manager Artifacts Rule

```yara
rule Password_Manager_Artifacts {
    meta:
        description = "Detects password manager artifacts in memory"
        author = "Issen"

    strings:
        $lastpass_sentinel = "lastpass rocks"
        $keepass_db_header = { 03 D9 A2 9A 67 FB 4B B5 }
        $bitwarden_org = "organizationId"
        $bitwarden_coll = "collectionIds"
        $onepassword_key = /A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}/
        $keepass_totp = "TimeOtp-Secret-Base32"
        $keepass_hotp = "HmacOtp-Secret-Base32"

    condition:
        any of them
}
```

### A.9 Kerberos Ticket Detection Rule

```yara
rule Kerberos_Tickets {
    meta:
        description = "Detects Kerberos ticket artifacts in memory"
        author = "Issen"

    strings:
        $krbtgt = "krbtgt/" nocase
        $ccache_magic = { 05 04 }
        $kirbi_prefix = /doI[A-Za-z0-9+\/]{20,}/
        $asrep_tag = { 6B 82 }
        $tgsrep_tag = { 6D 82 }
        $apreq_tag = { 6E 82 }

    condition:
        any of them
}
```

---

## Appendix B: Rust Implementation Patterns

### B.1 Efficient Multi-Pattern Scanning with Aho-Corasick

For a Rust memory forensics tool, use the `aho-corasick` crate for simultaneous multi-pattern
string matching across memory buffers:

```rust
use aho_corasick::AhoCorasick;

let patterns = &[
    "eyJhbGci",                              // JWT with alg header
    "eyJ0eXAi",                              // JWT with typ header
    "AKIA",                                   // AWS long-term key
    "ASIA",                                   // AWS STS key
    "ghp_",                                   // GitHub PAT
    "ghs_",                                   // GitHub server token
    "sk_live_",                               // Stripe live key
    "sk_test_",                               // Stripe test key
    "xoxb-",                                  // Slack bot token
    "xoxp-",                                  // Slack user token
    "SG.",                                    // SendGrid API key
    "-----BEGIN RSA PRIVATE KEY-----",        // RSA PEM key
    "-----BEGIN PRIVATE KEY-----",            // PKCS#8 PEM key
    "-----BEGIN EC PRIVATE KEY-----",         // EC PEM key
    "otpauth://totp/",                        // TOTP URI
    "otpauth://hotp/",                        // HOTP URI
    "saml:Assertion",                         // SAML assertion
    "SAMLResponse",                           // SAML response form field
    "PHPSESSID",                              // PHP session
    "JSESSIONID",                             // Java session
    "ASP.NET_SessionId",                      // ASP.NET session
    "lastpass rocks",                         // LastPass sentinel
    "krbtgt/",                                // Kerberos TGT service
    "\"type\": \"service_account\"",          // GCP service account key
];

let ac = AhoCorasick::new(patterns).unwrap();
```

### B.2 Regex-Based Token Extraction

Use the `regex` crate for structured token extraction after initial Aho-Corasick hit detection:

```rust
use regex::Regex;

// JWT extraction
let jwt_re = Regex::new(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
).unwrap();

// AWS access key extraction
let aws_key_re = Regex::new(r"(AKIA|ASIA)[A-Z2-7]{16}").unwrap();

// GitHub token extraction
let github_re = Regex::new(r"gh[pousr]_[0-9a-zA-Z]{36}").unwrap();

// Stripe key extraction
let stripe_re = Regex::new(r"[sr]k_(live|test)_[A-Za-z0-9]{24,}").unwrap();
```

### B.3 Base64URL Decoding for JWT Inspection

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn decode_jwt_part(part: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = URL_SAFE_NO_PAD.decode(part)?;
    Ok(String::from_utf8(bytes)?)
}

fn parse_jwt(token: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header = decode_jwt_part(parts[0]).ok()?;
    let payload = decode_jwt_part(parts[1]).ok()?;
    Some((header, payload))
}
```

### B.4 Binary Pattern Scanning for DER-Encoded Keys

```rust
/// ASN.1 DER patterns for RSA PKCS#8 keys
const RSA_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x82,  // SEQUENCE (2-byte length)
];

const RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
    // OID 1.2.840.113549.1.1.1 (rsaEncryption)
];

const EC_P256_OID: &[u8] = &[
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
];

/// Scan memory buffer for DER-encoded RSA keys
fn scan_for_der_rsa_keys(buffer: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    for i in 0..buffer.len().saturating_sub(RSA_OID.len()) {
        if buffer[i..].starts_with(RSA_OID) {
            // Walk backwards to find the containing SEQUENCE
            // ... (implementation details)
            offsets.push(i);
        }
    }
    offsets
}
```

---

## Appendix C: Memory Locations by Process Type

### C.1 Browser Processes

| Browser | Process Name | Key Memory Regions |
|---------|-------------|-------------------|
| Chrome | `chrome.exe` / `Google Chrome Helper` | Cookie jar, session storage, localStorage, extension memory |
| Firefox | `firefox.exe` / `firefox` | Cookie jar, session store, certificate database |
| Edge | `msedge.exe` | Same as Chrome (Chromium-based) |
| Safari | `Safari` / `com.apple.WebKit.WebContent` | Keychain integration, cookie jar |

### C.2 Server Processes

| Server | Process Name | Key Memory Regions |
|--------|-------------|-------------------|
| Apache | `httpd` / `apache2` | Request/response buffers, mod_auth_openidc tokens |
| Nginx | `nginx` | Request buffers, upstream response cache |
| IIS | `w3wp.exe` | ASP.NET session state, authentication tokens |
| Node.js | `node` | Express session store, passport.js tokens |

### C.3 Authentication Infrastructure

| Component | Process Name | Key Memory Regions |
|-----------|-------------|-------------------|
| LSASS | `lsass.exe` | Kerberos tickets, NTLM hashes, TLS keys, certificate private keys |
| AD FS | `Microsoft.IdentityServer.ServiceHost.exe` | SAML token-signing keys, issued assertions |
| Azure AD Connect | `AzureADConnect.exe` | Sync credentials, service account tokens |
| Okta Agent | OktaAgent-related processes | SSO tokens, SAML assertions |

### C.4 Password Managers

| PM | Process Name | Key Memory Regions |
|----|-------------|-------------------|
| 1Password | `1Password.exe` / `1Password` | Vault encryption key, decrypted entries, Account Key |
| LastPass | `LastPass.exe` / browser extension | Decryption key, "lastpass rocks" sentinel, decrypted entries |
| KeePass | `KeePass.exe` | Master key material (CVE-2023-32784), database key, TOTP secrets |
| Bitwarden | `Bitwarden.exe` / browser extension | Master password (CVE-2023-38840), decrypted vault |

---

## Appendix D: References and Resources

### Tools
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) - Memory forensics framework
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Windows credential extraction
- [pypykatz](https://github.com/skelsec/pypykatz) - Python implementation of Mimikatz
- [jwt_tool](https://github.com/ticarpi/jwt_tool) - JWT testing and cracking toolkit
- [WAMBam](https://blog.xpnsec.com/wam-bam/) - Windows WAM token extraction
- [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db) - 1,600+ regex patterns
- [YARA-Secrets](https://github.com/MrSuicideParrot/Yara-Secrets) - YARA rules for secrets
- [extract_otp_secrets](https://github.com/scito/extract_otp_secrets) - OTP secret extraction
- [Password Manager Forensics (PMF)](https://github.com/shaehni/password-manager-forensics) - PM forensic extraction
- [BW-Dump](https://github.com/markuta/bw-dump) - Bitwarden master password extraction (CVE-2023-38840)
- [CryKeX](https://github.com/cryptolok/CryKeX) - Linux memory cryptographic key extractor
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) - DPAPI credential extraction
- [YARA-X](https://github.com/VirusTotal/yara-x) - YARA rewritten in Rust (stable June 2025, successor to YARA)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - 800+ secret detectors with live verification
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Git repo secret scanning (~60 rules)
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Pre-commit hook with entropy analysis (Yelp)
- [secret-scan](https://github.com/marcuspat/secret-scan) - Rust-based scanner, 50+ secret patterns
- [kerberos_asn1](https://docs.rs/kerberos_asn1) - Rust crate for Kerberos ASN.1 encoding/decoding

### Research Papers and Articles
- [ISE: Password Managers Under the Hood](https://www.ise.io/casestudies/password-manager-hacking/) - Memory security evaluation
- [Pandora: Keep Your Memory Dump Shut (2024)](https://arxiv.org/html/2404.00423v1) - PM memory leak analysis
- [Golden SAML Attack (CyberArk)](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps) - SAML token forging
- [Golden SAML Revisited: Solorigate Connection (CyberArk)](https://www.cyberark.com/resources/threat-research-blog/golden-saml-revisited-the-solorigate-connection) - SolarWinds-era Golden SAML in the wild
- [Detection and Hunting of Golden SAML Attack (Sygnia)](https://www.sygnia.co/threat-reports-and-advisories/golden-saml-attack/) - AD FS event log correlation
- [DEF CON 24: CNG TLS/SSL from LSASS](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Jkambic-Cunning-With-Cng-Soliciting-Secrets-From-Schannel-WP.pdf) - TLS key extraction
- [Volatility Labs: RSA Private Keys](https://volatility-labs.blogspot.com/2013/05/movp-ii-21-rsa-private-keys-and.html) - dumpcerts plugin
- [All Your Private Keys Are Belong to Us](https://www.trapkit.de/articles/all-your-private-keys-are-belong-to-us/) - Key extraction from process memory
- [Persistence of Memory: Cryptographic Key Forensics](https://www.sciencedirect.com/science/article/pii/S1742287609000486) - Key identification methods
- [AWS Security Credential Formats](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/) - AWS key prefix reference
- [AWS Access Key ID Formats](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html) - AKIA/ASIA prefix analysis
- [Browser Forensics in 2026: App-Bound Encryption](https://blog.elcomsoft.com/2026/01/browser-forensics-in-2026-app-bound-encryption-and-live-triage/) - Chrome App-Bound Encryption impact
- [C4 Bomb: Chrome's AppBound Cookie Encryption](https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption) - AppBound bypass
- [Dough No! Revisiting Cookie Theft (SpecterOps 2025)](https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/) - Post-ABE cookie theft techniques
- [Behind GitHub's New Authentication Token Formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) - CRC32 checksum, token prefix design
- [Keys on Doormats: Exposed API Credentials (2025)](https://arxiv.org/html/2603.12498v1) - 1,748 verified credentials across 9,804 websites
- [Breaking Password Managers (Passware 2025)](https://blog.passware.com/breaking-password-managers-how-easy-is-it-and-whats-inside/) - Commercial PM forensic capabilities
- [Breaking Into Password Managers (Elcomsoft 2025)](https://blog.elcomsoft.com/2025/09/breaking-into-password-managers-from-bitwarden-to-zoho-vault/) - 8 new PM targets
- [Kirbi to Hashcat: ASN.1 Kerberos Ticket Decoding](https://github.com/schen0x/kirbi2hashcat) - Binary kirbi format with RFC references
- [Detecting Forged Kerberos Tickets (ADSecurity)](https://adsecurity.org/?p=1515) - Golden/Silver ticket detection
- [Credential Cache File Format (MIT Kerberos)](https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html) - Official ccache specification
- [Shannon Entropy for Detecting Encrypted/Obfuscated Data](https://ghostkit.net/techniques/shannon-entropy-analysis) - Entropy ranges and data classification
- [Password Managers in Digital Forensics (2024)](https://www.diva-portal.org/smash/get/diva2:1784441/FULLTEXT01.pdf) - PMF framework thesis
- [IETF Draft: otpauth URI Specification](https://datatracker.ietf.org/doc/html/draft-linuxgemini-otpauth-uri-02) - Formal otpauth:// URI spec

### Standards and RFCs
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token (JWT)
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JSON Web Key (JWK)
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) - OAuth 2.0 Authorization Framework
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE for OAuth Public Clients
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) - TOTP: Time-Based One-Time Password
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) - HOTP: HMAC-Based One-Time Password
- [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958) - PKCS#8 Asymmetric Key Packages
- [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) - The Kerberos Network Authentication Service (V5)
- [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516) - JSON Web Encryption (JWE)
- [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) - OASIS SAML 2.0 Assertions and Protocols

### MITRE ATT&CK
- [T1539](https://attack.mitre.org/techniques/T1539/) - Steal Web Session Cookie
- [T1550.003](https://attack.mitre.org/techniques/T1550/003/) - Pass the Ticket
- [T1558.003](https://attack.mitre.org/techniques/T1558/003/) - Kerberoasting
- [T1558.005](https://attack.mitre.org/techniques/T1558/005/) - Steal or Forge Kerberos Tickets: Ccache Files
- [T1558.001](https://attack.mitre.org/techniques/T1558/001/) - Golden Ticket
- [T1606.002](https://attack.mitre.org/techniques/T1606/002/) - Forge Web Credentials: SAML Tokens

### Session Management
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
