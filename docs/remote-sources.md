# Remote Sources

Issen ingests evidence from 48 URI schemes via [Apache OpenDAL](https://opendal.apache.org/). Every scheme uses the same interface — `rt ingest --source <URI>` — regardless of backend. The `rt-remote-io` crate handles all authentication, streaming, and path resolution transparently.

```bash
rt ingest --source s3://dfir-bucket/case/collection.tar.gz --output case.duckdb
rt ingest --source sftp://analyst@10.0.1.5/evidence/ --output case.duckdb
rt ingest --source gdrive://1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms
```

---

## Cloud Object Storage

Most enterprise acquisitions land in object storage. These backends are read/write.

### AWS S3 — `s3://bucket/key`

Compatible with AWS S3, MinIO, Cloudflare R2, Wasabi, and any S3-compatible endpoint.

```bash
rt ingest --source s3://dfir-evidence/2026-04-19/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | Yes | IAM secret key |
| `AWS_DEFAULT_REGION` | No | Defaults to `us-east-1` |
| `AWS_SESSION_TOKEN` | No | For temporary STS credentials |
| `AWS_ENDPOINT_URL` | No | Override for MinIO / R2 / Wasabi |

### Google Cloud Storage — `gcs://bucket/object`

```bash
rt ingest --source gcs://my-dfir-bucket/collections/host-001.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | Path to service account JSON |

Alternatively, Application Default Credentials (ADC) work if `gcloud auth application-default login` has been run.

### Azure Blob Storage — `azblob://container/blob`

```bash
rt ingest --source azblob://evidence/2026-04-19/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `AZURE_STORAGE_ACCOUNT` | Yes | Storage account name |
| `AZURE_STORAGE_ACCESS_KEY` | Yes | Account key |

### Azure Data Lake Gen2 — `azdls://filesystem/path`

For enterprise data lakes using hierarchical namespace.

```bash
rt ingest --source azdls://forensics/cases/2026-04-19/
```

| Env var | Required | Description |
|---------|----------|-------------|
| `AZURE_STORAGE_ACCOUNT` | Yes | Storage account name |
| `AZURE_STORAGE_ACCESS_KEY` | Yes | Account key |
| `AZDLS_ENDPOINT` | No | Defaults to `https://<account>.dfs.core.windows.net` |

### Azure Files — `azfile://share/path`

SMB file shares via REST API.

```bash
rt ingest --source azfile://dfir-share/collections/host-001/
```

| Env var | Required | Description |
|---------|----------|-------------|
| `AZURE_STORAGE_ACCOUNT` | Yes | Storage account name |
| `AZURE_STORAGE_ACCESS_KEY` | Yes | Account key |
| `AZFILE_ENDPOINT` | No | Defaults to `https://<account>.file.core.windows.net` |

### Backblaze B2 — `b2://bucket/key`

Cost-effective cold storage for large evidence sets.

```bash
rt ingest --source b2://dfir-cold/archives/host-001.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `BACKBLAZE_APPLICATION_KEY_ID` | Yes | Application key ID |
| `BACKBLAZE_APPLICATION_KEY` | Yes | Application key |

### Tencent Cloud COS — `cos://bucket/key`

```bash
rt ingest --source cos://dfir-bucket/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `TENCENTCLOUD_SECRET_ID` | Yes | |
| `TENCENTCLOUD_SECRET_KEY` | Yes | |
| `TENCENTCLOUD_REGION` | No | Defaults to `ap-guangzhou` |
| `COS_ENDPOINT` | No | Override endpoint |

### Huawei Cloud OBS — `obs://bucket/key`

```bash
rt ingest --source obs://dfir-bucket/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `HUAWEI_ACCESS_KEY_ID` | Yes | |
| `HUAWEI_SECRET_ACCESS_KEY` | Yes | |
| `HUAWEI_REGION` | No | Defaults to `cn-north-4` |
| `OBS_ENDPOINT` | No | Override endpoint |

### Alibaba Cloud OSS — `oss://bucket/key`

```bash
rt ingest --source oss://dfir-bucket/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | Yes | |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | Yes | |
| `ALIBABA_CLOUD_REGION` | No | Defaults to `cn-hangzhou` |
| `OSS_ENDPOINT` | No | Override endpoint |

### OpenStack Swift — `swift://container/path`

Common in private cloud environments (OpenStack, Ceph RADOS Gateway).

```bash
rt ingest --source swift://evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `SWIFT_ENDPOINT` | Yes | Swift proxy endpoint |
| `SWIFT_TOKEN` | Yes | Auth token |

### Upyun — `upyun://bucket/key`

```bash
rt ingest --source upyun://dfir-bucket/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `UPYUN_OPERATOR` | Yes | Operator name |
| `UPYUN_PASSWORD` | Yes | Operator password |

---

## Cloud Drives

### Google Drive — `gdrive://file-id`

Supports both file IDs and share URLs. Authentication uses OAuth2 (interactive browser flow) or a service account.

```bash
# By file ID
rt ingest --source gdrive://1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms

# By full share URL
rt ingest --source "gdrive://https://drive.google.com/file/d/1BxiMVs0.../view"
```

Authentication priority:
1. `GOOGLE_APPLICATION_CREDENTIALS` — service account JSON (recommended for automation)
2. `GDRIVE_CLIENT_ID` + `GDRIVE_CLIENT_SECRET` — OAuth2 (browser popup on first run, token cached in `~/.config/issen/gdrive-token.json`)
3. Saved token from previous OAuth2 session

### Microsoft OneDrive — `onedrive://path`

```bash
rt ingest --source onedrive://Documents/Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `ONEDRIVE_ACCESS_TOKEN` | Yes | OAuth2 bearer token |

Obtain a token via `az account get-access-token --resource https://graph.microsoft.com` or the Microsoft identity platform.

### Dropbox — `dropbox://path`

```bash
rt ingest --source dropbox://Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `DROPBOX_ACCESS_TOKEN` | Yes | OAuth2 access token |

### Aliyun Drive — `aliyun-drive://path`

```bash
rt ingest --source aliyun-drive://evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `ALIYUN_DRIVE_ACCESS_TOKEN` | Yes | OAuth2 access token |

### Yandex Disk — `yandex-disk://path`

```bash
rt ingest --source yandex-disk://Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `YANDEX_DISK_ACCESS_TOKEN` | Yes | OAuth2 access token |

### pCloud — `pcloud://path`

```bash
rt ingest --source pcloud://Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `PCLOUD_USERNAME` | Yes | |
| `PCLOUD_PASSWORD` | Yes | |
| `PCLOUD_ENDPOINT` | No | Defaults to `https://api.pcloud.com` |

### Koofr — `koofr://path`

```bash
rt ingest --source koofr://Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `KOOFR_EMAIL` | Yes | |
| `KOOFR_PASSWORD` | Yes | App password (not account password) |
| `KOOFR_ENDPOINT` | No | Defaults to `https://app.koofr.net` |

### Seafile — `seafile://server/repo/path`

```bash
rt ingest --source seafile://files.example.com/Evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `SEAFILE_USERNAME` | Yes | |
| `SEAFILE_PASSWORD` | Yes | |
| `SEAFILE_REPO` | No | Default repo if not in URI |

---

## Developer / ML / Infra

### GitHub — `github://owner/repo/path`

Read-only access to repository file trees. Useful for ingesting scripts, configs, or forensic artifacts stored in repositories.

```bash
rt ingest --source github://SecurityRonin/evidence-repo/cases/2026-04-19/
```

| Env var | Required | Description |
|---------|----------|-------------|
| `GITHUB_TOKEN` | No | Required for private repos or higher rate limits |

### HuggingFace — `huggingface://owner/repo/path`

Ingest datasets or model artifacts stored on HuggingFace Hub.

```bash
rt ingest --source huggingface://SecurityRonin/forensic-datasets/malware-samples/
```

| Env var | Required | Description |
|---------|----------|-------------|
| `HUGGINGFACE_TOKEN` | No | Required for private repos |

### Vercel Blob — `vercel-blob://key`

```bash
rt ingest --source vercel-blob://evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `BLOB_READ_WRITE_TOKEN` | Yes | From Vercel project settings |

### Vercel Build Artifacts — `vercel-artifacts://key`

```bash
rt ingest --source vercel-artifacts://build-cache-key
```

| Env var | Required | Description |
|---------|----------|-------------|
| `VERCEL_ARTIFACTS_TOKEN` | Yes | |

### GitHub Actions Cache — `ghac://key`

For CI-based forensic workflows where evidence is cached between runs.

```bash
rt ingest --source ghac://evidence-snapshot
```

Auth is automatic within GitHub Actions via `ACTIONS_CACHE_URL` and `ACTIONS_RUNTIME_TOKEN`.

| Env var | Required | Description |
|---------|----------|-------------|
| `GHAC_VERSION` | No | Cache API version, defaults to `v1` |

### Databricks DBFS — `dbfs://path`

```bash
rt ingest --source dbfs://mnt/evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `DATABRICKS_HOST` | Yes | Workspace URL |
| `DATABRICKS_TOKEN` | Yes | Personal access token |

---

## Distributed / Big Data

### Alluxio — `alluxio://host:port/path`

Unified data access layer over HDFS, S3, Azure.

```bash
rt ingest --source alluxio://alluxio-master:19998/evidence/
```

No credentials needed by default; Alluxio manages upstream auth.

### WebHDFS — `webhdfs://namenode:port/path`

HDFS access via REST API. Works with CDH, HDP, and vanilla Hadoop. No client libraries required.

```bash
rt ingest --source webhdfs://namenode:50070/user/forensics/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `WEBHDFS_USER` | No | Hadoop username (proxies as this user) |

### HDFS Native — `hdfs://namenode:port/path`

Pure-Rust HDFS client — **no JVM, no `JAVA_HOME`, no Hadoop installation required**. Implements the HDFS RPC protocol directly.

```bash
rt ingest --source hdfs://namenode:9000/user/forensics/evidence.tar.gz
```

Kerberos is not currently supported by the native client; use `webhdfs://` in Kerberized environments.

### LakeFS — `lakefs://repo/branch/path`

Data versioning layer over S3/GCS/Azure — useful when evidence is version-controlled.

```bash
rt ingest --source lakefs://forensics/main/cases/2026-04-19/
```

| Env var | Required | Description |
|---------|----------|-------------|
| `LAKEFS_ACCESS_KEY_ID` | Yes | |
| `LAKEFS_SECRET_ACCESS_KEY` | Yes | |
| `LAKEFS_ENDPOINT` | No | Defaults to `http://localhost:8000` |

---

## Decentralized

### IPFS — `ipfs://CID/path`

Read-only. Content-addressed and immutable — ideal for evidence integrity verification.

```bash
rt ingest --source ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `IPFS_GATEWAY` | No | Defaults to local node `http://127.0.0.1:8080` |

### IPFS MFS — `ipmfs:///path`

Mutable File System — read and write via local IPFS node.

```bash
rt ingest --source ipmfs:///forensics/evidence.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `IPFS_ENDPOINT` | No | Defaults to `http://127.0.0.1:5001` |

---

## Network KV / Databases

These backends treat keys as file paths. Useful when evidence metadata is stored in a live database.

### Redis — `redis://host:port/key` / `rediss://host:port/key`

`rediss://` is Redis over TLS.

```bash
rt ingest --source redis://localhost:6379/evidence:host-001
rt ingest --source rediss://redis.internal:6380/evidence:host-001
```

Credentials embedded in URI: `redis://user:password@host:port/key`

### Memcached — `memcached://host:port/key`

```bash
rt ingest --source memcached://cache:11211/evidence-key
```

### etcd — `etcd://host:port/key`

```bash
rt ingest --source etcd://etcd-host:2379/forensics/evidence
```

### TiKV — `tikv://pd-host:port/key`

Distributed transactional KV.

```bash
rt ingest --source tikv://pd-host:2379/evidence-key
```

### MongoDB — `mongodb://[user:pass@]host/database/collection/key`

```bash
rt ingest --source mongodb://admin:secret@mongo:27017/forensics/evidence/host-001
```

### MongoDB GridFS — `gridfs://[user:pass@]host/database/bucket/key`

For large binary blobs stored in GridFS.

```bash
rt ingest --source gridfs://mongo:27017/forensics/evidence/collection.tar.gz
```

### MySQL / MariaDB — `mysql://[user:pass@]host/database/key`

```bash
rt ingest --source mysql://analyst:secret@mysql:3306/forensics/evidence
```

### PostgreSQL — `postgresql://[user:pass@]host/database/key`

```bash
rt ingest --source postgresql://analyst:secret@pg:5432/forensics/evidence
```

### SQLite — `sqlite:///path/to/db.sqlite/key`

```bash
rt ingest --source sqlite:///cases/2026-04-19/case.db/evidence
```

### Cloudflare KV — `cloudflare-kv://namespace-id/key`

```bash
rt ingest --source cloudflare-kv://abc123def456/evidence:host-001
```

| Env var | Required | Description |
|---------|----------|-------------|
| `CLOUDFLARE_ACCOUNT_ID` | Yes | |
| `CLOUDFLARE_API_TOKEN` | Yes | |

### Cloudflare D1 — `d1://database-id/key`

SQLite-compatible database via REST API.

```bash
rt ingest --source d1://abc123def456/evidence-key
```

| Env var | Required | Description |
|---------|----------|-------------|
| `CLOUDFLARE_ACCOUNT_ID` | Yes | |
| `CLOUDFLARE_API_TOKEN` | Yes | |

---

## Filesystem / Network Protocols

### Local filesystem — `file:///abs/path`

```bash
rt ingest --source file:///cases/2026-04-19/collection.tar.gz
```

Equivalent to passing the path directly without `--source`.

### HTTP / HTTPS — `http://host/path`, `https://host/path`

**Read-only.** Evidence accessible via a plain HTTP server.

```bash
rt ingest --source https://evidence-portal.example.com/cases/host-001.tar.gz
```

### WebDAV — `webdav://host/path`

Read/write. Common in enterprise NAS, Nextcloud, SharePoint.

```bash
rt ingest --source webdav://nas.corp.example.com/forensics/collection.tar.gz
```

### SFTP — `sftp://[user@]host[:port]/path`

Authenticates via SSH agent (default), key file, or known-hosts policy.

```bash
rt ingest --source sftp://analyst@10.0.1.5/evidence/collection.tar.gz
```

| Env var | Required | Description |
|---------|----------|-------------|
| `RT_SFTP_KEY_PATH` | No | Path to private key file |
| `RT_SFTP_KNOWN_HOSTS_STRATEGY` | No | `strict` (default) / `add` / `accept` |

### FTP / FTPS — `ftp://user:pass@host/path`, `ftps://user:pass@host/path`

`ftps://` is FTP over TLS. Credentials are embedded in the URI.

```bash
rt ingest --source ftp://analyst:secret@ftp.corp.example.com/evidence/
```

### In-memory — `mem://path`

For testing and pipeline integration. Data is not persisted.

```bash
rt ingest --source mem://test/evidence.tar.gz
```

---

## Read vs. Write

| Category | Read | Write |
|----------|------|-------|
| All object storage (S3, GCS, Azure, B2, …) | ✓ | ✓ |
| Cloud drives (OneDrive, Dropbox, GDrive, …) | ✓ | ✓ |
| SFTP, FTP, WebDAV | ✓ | ✓ |
| HDFS native, WebHDFS | ✓ | ✓ |
| Network KV / databases | ✓ | ✓ |
| IPFS (`ipfs://`) | ✓ | — (content-addressed, immutable) |
| IPFS MFS (`ipmfs://`) | ✓ | ✓ |
| GitHub (`github://`) | ✓ | — (git tree accessor) |
| HTTP / HTTPS | ✓ | — (GET only) |

---

## Implementation

All backends are implemented in the `rt-remote-io` crate using [Apache OpenDAL](https://opendal.apache.org/) 0.55. The `operator_for_uri` function parses any of the 48 URI schemes and returns a unified `Operator` — callers never need to know which backend is in use.

```rust
use rt_remote_io::operator::operator_for_uri;

let (op, path) = operator_for_uri("s3://my-bucket/evidence/collection.tar.gz")?;
let bytes = op.read(&path).await?;
```

See the [API docs](https://securityronin.github.io/issen/rt_remote_io/) for the full interface.
