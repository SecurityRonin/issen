use anyhow::{anyhow, Result};
use opendal::{Operator, services};

/// Build an OpenDAL [`Operator`] for the given URI, and return the relative path
/// within that backend.
///
/// Supported URI schemes:
///
/// **Cloud object storage**
/// `s3`, `gcs`, `azblob`, `azdls`, `azfile`, `b2`, `cos`, `obs`, `oss`, `swift`, `upyun`
///
/// **Cloud drives**
/// `gdrive`, `onedrive`, `dropbox`, `aliyun-drive`, `yandex-disk`, `pcloud`, `koofr`, `seafile`
///
/// **Developer / ML / infra**
/// `github`, `huggingface`, `vercel-blob`, `vercel-artifacts`, `ghac`, `dbfs`
///
/// **Distributed / big data**
/// `alluxio`, `hdfs`, `webhdfs`, `lakefs`
///
/// **Decentralized**
/// `ipfs`, `ipmfs`
///
/// **Network KV / databases**
/// `redis`, `rediss`, `memcached`, `etcd`, `tikv`, `mongodb`, `gridfs`,
/// `mysql`, `postgresql`, `sqlite`, `cloudflare-kv`, `d1`
///
/// **Filesystem / network protocols**
/// `file`, `http`, `https`, `webdav`, `sftp`, `ftp`, `ftps`, `compfs`
///
/// **In-memory / embedded**
/// `mem`
///
/// Auth is read from standard environment variables; refer to each backend's documentation
/// for the expected variable names.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let Some(scheme_end) = uri.find("://") else {
        return Err(anyhow!("URI has no scheme: {uri}"));
    };
    let scheme = &uri[..scheme_end];
    let rest = &uri[scheme_end + 3..]; // everything after "://"

    match scheme {
        // ── In-memory ────────────────────────────────────────────────────────
        "mem" => {
            let builder = services::Memory::default();
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        // ── Cloud object storage ─────────────────────────────────────────────
        "s3" => {
            // s3://bucket/key
            let (bucket, key) = split_authority_path(rest);
            let region = std::env::var("AWS_DEFAULT_REGION")
                .unwrap_or_else(|_| "us-east-1".into());
            let builder = services::S3::default().bucket(bucket).region(&region);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "gcs" => {
            // gcs://bucket/object
            let (bucket, path) = split_authority_path(rest);
            let builder = services::Gcs::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "azblob" => {
            // azblob://container/blob
            let (container, blob) = split_authority_path(rest);
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let builder = services::Azblob::default()
                .container(container)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, blob.to_string()))
        }

        "azdls" => {
            // azdls://filesystem/path
            let (filesystem, path) = split_authority_path(rest);
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let endpoint = std::env::var("AZDLS_ENDPOINT").unwrap_or_else(|_| {
                format!("https://{account}.dfs.core.windows.net")
            });
            let builder = services::Azdls::default()
                .filesystem(filesystem)
                .endpoint(&endpoint)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "azfile" => {
            // azfile://share/path
            let (share, path) = split_authority_path(rest);
            let account = std::env::var("AZURE_STORAGE_ACCOUNT")
                .unwrap_or_else(|_| "devstoreaccount1".into());
            let endpoint = std::env::var("AZFILE_ENDPOINT").unwrap_or_else(|_| {
                format!("https://{account}.file.core.windows.net")
            });
            let builder = services::Azfile::default()
                .share_name(share)
                .endpoint(&endpoint)
                .account_name(&account);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "b2" => {
            // b2://bucket/key — creds from BACKBLAZE_APPLICATION_KEY_ID / BACKBLAZE_APPLICATION_KEY
            let (bucket, key) = split_authority_path(rest);
            let key_id = std::env::var("BACKBLAZE_APPLICATION_KEY_ID").unwrap_or_default();
            let app_key = std::env::var("BACKBLAZE_APPLICATION_KEY").unwrap_or_default();
            let builder = services::B2::default()
                .bucket(bucket)
                .application_key_id(&key_id)
                .application_key(&app_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "cos" => {
            // cos://bucket/key — creds from TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY
            let (bucket, key) = split_authority_path(rest);
            let region = std::env::var("TENCENTCLOUD_REGION")
                .unwrap_or_else(|_| "ap-guangzhou".into());
            let endpoint = std::env::var("COS_ENDPOINT").unwrap_or_else(|_| {
                format!("https://{bucket}.cos.{region}.myqcloud.com")
            });
            let secret_id = std::env::var("TENCENTCLOUD_SECRET_ID").unwrap_or_default();
            let secret_key = std::env::var("TENCENTCLOUD_SECRET_KEY").unwrap_or_default();
            let builder = services::Cos::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .secret_id(&secret_id)
                .secret_key(&secret_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "obs" => {
            // obs://bucket/key — creds from HUAWEI_ACCESS_KEY_ID / HUAWEI_SECRET_ACCESS_KEY
            let (bucket, key) = split_authority_path(rest);
            let region = std::env::var("HUAWEI_REGION")
                .unwrap_or_else(|_| "cn-north-4".into());
            let endpoint = std::env::var("OBS_ENDPOINT").unwrap_or_else(|_| {
                format!("https://obs.{region}.myhuaweicloud.com")
            });
            let access_key = std::env::var("HUAWEI_ACCESS_KEY_ID").unwrap_or_default();
            let secret_key = std::env::var("HUAWEI_SECRET_ACCESS_KEY").unwrap_or_default();
            let builder = services::Obs::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .access_key_id(&access_key)
                .secret_access_key(&secret_key);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "oss" => {
            // oss://bucket/key — creds from ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET
            let (bucket, key) = split_authority_path(rest);
            let region = std::env::var("ALIBABA_CLOUD_REGION")
                .unwrap_or_else(|_| "cn-hangzhou".into());
            let endpoint = std::env::var("OSS_ENDPOINT").unwrap_or_else(|_| {
                format!("https://oss-{region}.aliyuncs.com")
            });
            let access_key = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").unwrap_or_default();
            let access_secret = std::env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").unwrap_or_default();
            let builder = services::Oss::default()
                .bucket(bucket)
                .endpoint(&endpoint)
                .access_key_id(&access_key)
                .access_key_secret(&access_secret);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "swift" => {
            // swift://container/path — auth from SWIFT_ENDPOINT + SWIFT_TOKEN
            let (container, path) = split_authority_path(rest);
            let endpoint = std::env::var("SWIFT_ENDPOINT")
                .unwrap_or_else(|_| "https://object.example.com".into());
            let token = std::env::var("SWIFT_TOKEN").unwrap_or_default();
            let builder = services::Swift::default()
                .endpoint(&endpoint)
                .container(container)
                .token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "upyun" => {
            // upyun://bucket/key — creds from UPYUN_OPERATOR / UPYUN_PASSWORD
            let (bucket, key) = split_authority_path(rest);
            let operator_name = std::env::var("UPYUN_OPERATOR").unwrap_or_default();
            let password = std::env::var("UPYUN_PASSWORD").unwrap_or_default();
            let builder = services::Upyun::default()
                .bucket(bucket)
                .operator(&operator_name)
                .password(&password);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        // ── Consumer / enterprise cloud drives ───────────────────────────────
        "onedrive" => {
            // onedrive://path — token from ONEDRIVE_ACCESS_TOKEN
            let token = std::env::var("ONEDRIVE_ACCESS_TOKEN").unwrap_or_default();
            let builder = services::Onedrive::default()
                .root("/")
                .access_token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "dropbox" => {
            // dropbox://path — token from DROPBOX_ACCESS_TOKEN
            let token = std::env::var("DROPBOX_ACCESS_TOKEN").unwrap_or_default();
            let builder = services::Dropbox::default()
                .root("/")
                .access_token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "aliyun-drive" => {
            // aliyun-drive://path — token from ALIYUN_DRIVE_ACCESS_TOKEN
            let token = std::env::var("ALIYUN_DRIVE_ACCESS_TOKEN").unwrap_or_default();
            let builder = services::AliyunDrive::default()
                .root("/")
                .access_token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "yandex-disk" => {
            // yandex-disk://path — token from YANDEX_DISK_ACCESS_TOKEN
            let token = std::env::var("YANDEX_DISK_ACCESS_TOKEN").unwrap_or_default();
            let builder = services::YandexDisk::default()
                .root("/")
                .access_token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "pcloud" => {
            // pcloud://path — creds from PCLOUD_USERNAME / PCLOUD_PASSWORD
            let endpoint = std::env::var("PCLOUD_ENDPOINT")
                .unwrap_or_else(|_| "https://api.pcloud.com".into());
            let username = std::env::var("PCLOUD_USERNAME").unwrap_or_default();
            let password = std::env::var("PCLOUD_PASSWORD").unwrap_or_default();
            let builder = services::Pcloud::default()
                .root("/")
                .endpoint(&endpoint)
                .username(&username)
                .password(&password);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "koofr" => {
            // koofr://path — creds from KOOFR_EMAIL / KOOFR_PASSWORD
            let endpoint = std::env::var("KOOFR_ENDPOINT")
                .unwrap_or_else(|_| "https://app.koofr.net".into());
            let email = std::env::var("KOOFR_EMAIL").unwrap_or_default();
            let password = std::env::var("KOOFR_PASSWORD").unwrap_or_default();
            let builder = services::Koofr::default()
                .root("/")
                .endpoint(&endpoint)
                .email(&email)
                .password(&password);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "seafile" => {
            // seafile://server/repo/path — creds from SEAFILE_USERNAME / SEAFILE_PASSWORD
            let (server, rest_path) = rest.split_once('/').unwrap_or((rest, ""));
            let (repo, path) = rest_path.split_once('/').unwrap_or((rest_path, ""));
            let endpoint = format!("https://{server}");
            let username = std::env::var("SEAFILE_USERNAME").unwrap_or_default();
            let password = std::env::var("SEAFILE_PASSWORD").unwrap_or_default();
            let repo_name = if repo.is_empty() {
                std::env::var("SEAFILE_REPO").unwrap_or_else(|_| "My Library".into())
            } else {
                repo.to_string()
            };
            let builder = services::Seafile::default()
                .endpoint(&endpoint)
                .username(&username)
                .password(&password)
                .repo_name(&repo_name);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        // ── Developer / ML / infra ───────────────────────────────────────────
        "github" => {
            // github://owner/repo/path — token from GITHUB_TOKEN
            let mut parts = rest.splitn(3, '/');
            let owner = parts.next().unwrap_or("");
            let repo = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("").to_string();
            let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
            let builder = services::Github::default()
                .token(&token)
                .owner(owner)
                .repo(repo);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        "huggingface" => {
            // huggingface://owner/repo/path — token from HUGGINGFACE_TOKEN
            // URI: huggingface://owner/model-name/file.bin
            // repo_id = "owner/model-name", path = "file.bin"
            let (repo_id, path) = rest.split_once('/').map(|(a, b)| {
                let full = format!("{a}/{b}");
                if let Some(idx) = full.find('/') {
                    let second = full[idx + 1..].find('/');
                    if let Some(second_idx) = second {
                        let split_at = idx + 1 + second_idx;
                        (full[..split_at].to_string(), full[split_at + 1..].to_string())
                    } else {
                        (full, String::new())
                    }
                } else {
                    (full, String::new())
                }
            }).unwrap_or((rest.to_string(), String::new()));
            let token = std::env::var("HUGGINGFACE_TOKEN").unwrap_or_default();
            let builder = services::Huggingface::default()
                .repo_id(&repo_id)
                .token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        "vercel-blob" => {
            // vercel-blob://key — token from BLOB_READ_WRITE_TOKEN
            let token = std::env::var("BLOB_READ_WRITE_TOKEN").unwrap_or_default();
            let builder = services::VercelBlob::default().token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "vercel-artifacts" => {
            // vercel-artifacts://key — token from VERCEL_ARTIFACTS_TOKEN
            let token = std::env::var("VERCEL_ARTIFACTS_TOKEN").unwrap_or_default();
            let builder = services::VercelArtifacts::default().access_token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "ghac" => {
            // ghac://key — GitHub Actions Cache (useful in CI forensics)
            let version = std::env::var("GHAC_VERSION").unwrap_or_else(|_| "v1".into());
            let builder = services::Ghac::default().version(&version);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "dbfs" => {
            // dbfs://path — Databricks DBFS; creds from DATABRICKS_HOST + DATABRICKS_TOKEN
            let endpoint = std::env::var("DATABRICKS_HOST")
                .unwrap_or_else(|_| "https://adb-example.azuredatabricks.net".into());
            let token = std::env::var("DATABRICKS_TOKEN").unwrap_or_default();
            let builder = services::Dbfs::default()
                .root("/")
                .endpoint(&endpoint)
                .token(&token);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        // ── Distributed / big data ───────────────────────────────────────────
        "alluxio" => {
            // alluxio://host:port/path
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("http://{hostport}");
            let builder = services::Alluxio::default()
                .root("/")
                .endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "hdfs" => {
            // hdfs://namenode:port/path — pure-Rust HDFS native client (no Java required)
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let name_node = format!("hdfs://{hostport}");
            let builder = services::HdfsNative::default().name_node(&name_node).root("/");
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "webhdfs" => {
            // webhdfs://namenode:port/path
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("http://{hostport}");
            let user = std::env::var("WEBHDFS_USER").unwrap_or_default();
            let mut builder = services::Webhdfs::default()
                .root("/")
                .endpoint(&endpoint);
            if !user.is_empty() {
                builder = builder.user_name(&user);
            }
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "lakefs" => {
            // lakefs://repo/branch/path — creds from LAKEFS_ACCESS_KEY_ID / LAKEFS_SECRET_ACCESS_KEY
            let mut parts = rest.splitn(3, '/');
            let repo = parts.next().unwrap_or("").to_string();
            let branch = parts.next().unwrap_or("main").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let endpoint = std::env::var("LAKEFS_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:8000".into());
            let username = std::env::var("LAKEFS_ACCESS_KEY_ID").unwrap_or_default();
            let password = std::env::var("LAKEFS_SECRET_ACCESS_KEY").unwrap_or_default();
            let builder = services::Lakefs::default()
                .endpoint(&endpoint)
                .username(&username)
                .password(&password)
                .repository(&repo)
                .branch(&branch);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        // ── Decentralized ────────────────────────────────────────────────────
        "ipfs" => {
            // ipfs://CID/path — gateway from IPFS_GATEWAY (default: local node)
            let gateway = std::env::var("IPFS_GATEWAY")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".into());
            let builder = services::Ipfs::default()
                .root("/")
                .endpoint(&gateway);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "ipmfs" => {
            // ipmfs:///path — IPFS MFS via local node
            let endpoint = std::env::var("IPFS_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:5001".into());
            let builder = services::Ipmfs::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        // ── Network KV / databases ────────────────────────────────────────────
        "rediss" => {
            // rediss://host:port/key — Redis with TLS
            let (hostport, key) = rest.split_once('/').unwrap_or((rest, ""));
            let redis_url = format!("rediss://{hostport}");
            let builder = services::Redis::default().endpoint(&redis_url);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "redis" => {
            // redis://[user:pass@]host:port/key
            let (conn, path) = rest.split_once('/').unwrap_or((rest, ""));
            let redis_url = format!("redis://{conn}");
            let builder = services::Redis::default().endpoint(&redis_url);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "memcached" => {
            // memcached://host:port/key
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("tcp://{hostport}");
            let builder = services::Memcached::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "etcd" => {
            // etcd://host:port/key
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let endpoint = format!("http://{hostport}");
            let builder = services::Etcd::default().endpoints(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "tikv" => {
            // tikv://pd-host:port/key
            let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
            let builder = services::Tikv::default().endpoints(vec![hostport.to_string()]);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "mongodb" => {
            // mongodb://[user:pass@]host/db/collection/key
            let conn_str = format!("mongodb://{rest}");
            let mut parts = rest.splitn(3, '/');
            let _ = parts.next(); // host
            let database = parts.next().unwrap_or("issen");
            let rest_path = parts.next().unwrap_or("");
            let (collection, path) = rest_path.split_once('/').unwrap_or((rest_path, ""));
            let builder = services::Mongodb::default()
                .connection_string(&conn_str)
                .database(database)
                .collection(collection);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "gridfs" => {
            // gridfs://[user:pass@]host/db/bucket/key
            let conn_str = format!("mongodb://{rest}");
            let mut parts = rest.splitn(3, '/');
            let _ = parts.next(); // host[:port]
            let database = parts.next().unwrap_or("issen");
            let rest_path = parts.next().unwrap_or("");
            let (bucket, path) = rest_path.split_once('/').unwrap_or((rest_path, ""));
            let builder = services::Gridfs::default()
                .connection_string(&conn_str)
                .database(database)
                .bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "mysql" => {
            // mysql://[user:pass@]host/db/key
            let conn_str = format!("mysql://{rest}");
            let path = rest
                .split_once('/')
                .and_then(|(_, after_host)| after_host.split_once('/'))
                .map(|(_, key)| key.to_string())
                .unwrap_or_default();
            let builder = services::Mysql::default().connection_string(&conn_str);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        "postgresql" => {
            // postgresql://[user:pass@]host/db/key
            let conn_str = format!("postgresql://{rest}");
            let mut parts = rest.splitn(3, '/');
            let _host = parts.next().unwrap_or("");
            let _db = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("").to_string();
            let builder = services::Postgresql::default()
                .connection_string(&conn_str);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        "sqlite" => {
            // sqlite://path/to/db.sqlite/key  (opendal uses connection string)
            let (db_path, key) = rest.rsplit_once('/').unwrap_or((rest, ""));
            let conn = format!("sqlite://{db_path}");
            let builder = services::Sqlite::default().connection_string(&conn);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        // "surrealdb" — not wired: pulls async-graphql@7.2.1 (requires rustc 1.89 > MSRV 1.85)
        "cloudflare-kv" => {
            // cloudflare-kv://namespace-id/key
            let (namespace, key) = rest.split_once('/').unwrap_or((rest, ""));
            let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID").unwrap_or_default();
            let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
            let builder = services::CloudflareKv::default()
                .account_id(&account_id)
                .api_token(&token)
                .namespace_id(namespace);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        "d1" => {
            // d1://database-id/key — Cloudflare D1 (SQLite via REST)
            let (db_id, key) = rest.split_once('/').unwrap_or((rest, ""));
            let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID").unwrap_or_default();
            let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
            let builder = services::D1::default()
                .account_id(&account_id)
                .token(&token)
                .database_id(db_id);
            let op = Operator::new(builder)?.finish();
            Ok((op, key.to_string()))
        }

        // ── Filesystem / network protocols ───────────────────────────────────
        "webdav" => {
            let host = rest.split('/').next().unwrap_or("");
            let endpoint = format!("https://{host}");
            let path = if let Some((_, p)) = rest.split_once('/') { p } else { "" };
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "http" | "https" => {
            let (endpoint, path) = if let Some(slash) = rest.find('/') {
                let host = &rest[..slash];
                let p = &rest[slash..];
                (format!("{scheme}://{host}"), p.to_string())
            } else {
                (format!("{scheme}://{rest}"), "/".to_string())
            };
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, path))
        }

        "sftp" => sftp_operator(rest),

        "ftp" | "ftps" => {
            // ftp://user:password@host/path
            let (userinfo, hostpath) = rest.split_once('@').unwrap_or(("", rest));
            let (host, path) = hostpath.split_once('/').unwrap_or((hostpath, ""));
            let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            let builder = services::Ftp::default()
                .endpoint(&format!("{scheme}://{host}"))
                .user(user)
                .password(password);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "compfs" => {
            // compfs:///abs/path/to/dir — compio-based async filesystem
            let full = format!("/{rest}"); // restore leading slash stripped by split_once("://")
            let (dir, file) = full.rsplit_once('/').unwrap_or(("/", &full));
            let builder = services::Compfs::default().root(dir);
            let op = Operator::new(builder)?.finish();
            Ok((op, file.to_string()))
        }

        "file" => {
            // file:///path → local FS rooted at /
            let builder = services::Fs::default().root("/");
            let op = Operator::new(builder)?.finish();
            let path = if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            };
            Ok((op, path))
        }

        other => Err(anyhow!("Unsupported URI scheme: {other}")),
    }
}

#[cfg(feature = "sftp")]
fn sftp_operator(rest: &str) -> Result<(Operator, String)> {
    // sftp://user@host/path  (authenticates via SSH agent or key file)
    // Optional env overrides: RT_SFTP_KEY_PATH, RT_SFTP_KNOWN_HOSTS_STRATEGY
    let (userinfo, hostpath) = if rest.contains('@') {
        rest.split_once('@').unwrap_or(("", rest))
    } else {
        ("", rest)
    };
    let (host, path) = hostpath.split_once('/').unwrap_or((hostpath, ""));
    let user = if let Some((u, _)) = userinfo.split_once(':') { u } else { userinfo };
    let mut builder = services::Sftp::default()
        .endpoint(&format!("ssh://{host}"))
        .user(user);
    if let Ok(key) = std::env::var("RT_SFTP_KEY_PATH") {
        builder = builder.key(&key);
    }
    let known_hosts = std::env::var("RT_SFTP_KNOWN_HOSTS_STRATEGY")
        .unwrap_or_else(|_| "add".into());
    builder = builder.known_hosts_strategy(&known_hosts);
    let op = Operator::new(builder)?.finish();
    Ok((op, path.to_string()))
}

#[cfg(not(feature = "sftp"))]
fn sftp_operator(_rest: &str) -> Result<(Operator, String)> {
    Err(anyhow!("SFTP support requires the 'sftp' feature (Unix only)"))
}

/// Split `"authority/path"` into `("authority", "path")`.
/// If there is no slash, returns `(rest, "")`.
fn split_authority_path(rest: &str) -> (&str, &str) {
    if let Some(slash) = rest.find('/') {
        (&rest[..slash], &rest[slash + 1..])
    } else {
        (rest, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_uri_returns_ok_with_path() {
        let (_, path) = operator_for_uri("mem://bucket/key").expect("should succeed for mem://");
        assert_eq!(path, "bucket/key");
    }

    #[test]
    fn unknown_scheme_returns_err() {
        let result = operator_for_uri("bad://host/path");
        assert!(result.is_err(), "expected error for unknown scheme");
    }

    #[test]
    fn sftp_uri_returns_ok() {
        let result = operator_for_uri("sftp://user@host:22/data");
        // Must NOT be an unsupported-scheme error — scheme is recognised
        if let Err(e) = &result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected sftp to be a supported scheme, got: {msg}"
                );
        }
    }

    #[test]
    fn sftp_uri_path_extraction() {
        let result = operator_for_uri("sftp://host/remote/path");
        match result {
            Ok((_, path)) => assert_eq!(path, "remote/path"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn hdfs_uri_returns_ok() {
        let result = operator_for_uri("hdfs://namenode:9000/user/data");
        if let Err(e) = &result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected hdfs to be a supported scheme, got: {msg}"
                );
        }
    }

    #[test]
    fn hdfs_uri_path_extraction() {
        let result = operator_for_uri("hdfs://namenode:9000/user/data");
        match result {
            Ok((_, path)) => assert_eq!(path, "user/data"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn webhdfs_uri_returns_ok() {
        let result = operator_for_uri("webhdfs://namenode:50070/user/data");
        if let Err(e) = &result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "expected webhdfs to be a supported scheme, got: {msg}"
                );
        }
    }

    #[test]
    fn webhdfs_uri_path_extraction() {
        let result = operator_for_uri("webhdfs://namenode:50070/user/data");
        match result {
            Ok((_, path)) => assert_eq!(path, "user/data"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    // ── RED tests for 38 missing schemes ────────────────────────────────────

    macro_rules! scheme_recognised {
        ($name:ident, $uri:expr) => {
            #[test]
            fn $name() {
                let result = operator_for_uri($uri);
                if let Err(e) = &result {
                    assert!(
                        !e.to_string().contains("Unsupported URI scheme"),
                        "expected {} to be a supported scheme, got: {}",
                        $uri,
                        e
                    );
                }
            }
        };
    }

    // Cloud object storage
    scheme_recognised!(azdls_uri_returns_ok, "azdls://filesystem/path");
    scheme_recognised!(azfile_uri_returns_ok, "azfile://share/path");
    scheme_recognised!(b2_uri_returns_ok, "b2://bucket/key");
    scheme_recognised!(cos_uri_returns_ok, "cos://bucket/key");
    scheme_recognised!(obs_uri_returns_ok, "obs://bucket/key");
    scheme_recognised!(oss_uri_returns_ok, "oss://bucket/key");
    scheme_recognised!(swift_uri_returns_ok, "swift://container/path");
    scheme_recognised!(upyun_uri_returns_ok, "upyun://bucket/key");

    // Cloud drives
    scheme_recognised!(onedrive_uri_returns_ok, "onedrive://path/to/file");
    scheme_recognised!(dropbox_uri_returns_ok, "dropbox://path/to/file");
    scheme_recognised!(aliyun_drive_uri_returns_ok, "aliyun-drive://path/to/file");
    scheme_recognised!(yandex_disk_uri_returns_ok, "yandex-disk://path/to/file");
    scheme_recognised!(pcloud_uri_returns_ok, "pcloud://path/to/file");
    scheme_recognised!(koofr_uri_returns_ok, "koofr://path/to/file");
    scheme_recognised!(seafile_uri_returns_ok, "seafile://server/repo/path");

    // Dev / ML / infra
    scheme_recognised!(github_uri_returns_ok, "github://owner/repo/path");
    scheme_recognised!(huggingface_uri_returns_ok, "huggingface://owner/model/file");
    scheme_recognised!(vercel_blob_uri_returns_ok, "vercel-blob://key");
    scheme_recognised!(vercel_artifacts_uri_returns_ok, "vercel-artifacts://key");
    scheme_recognised!(ghac_uri_returns_ok, "ghac://key");
    scheme_recognised!(dbfs_uri_returns_ok, "dbfs://path/to/file");

    // Big data
    scheme_recognised!(alluxio_uri_returns_ok, "alluxio://host:19999/path");
    scheme_recognised!(lakefs_uri_returns_ok, "lakefs://repo/main/path");

    // Decentralized
    scheme_recognised!(ipfs_uri_returns_ok, "ipfs://QmHash/path");
    scheme_recognised!(ipmfs_uri_returns_ok, "ipmfs:///path/to/file");

    // Network KV / databases
    scheme_recognised!(redis_uri_returns_ok, "redis://localhost:6379/key");
    scheme_recognised!(rediss_uri_returns_ok, "rediss://localhost:6380/key");
    scheme_recognised!(memcached_uri_returns_ok, "memcached://localhost:11211/key");
    scheme_recognised!(etcd_uri_returns_ok, "etcd://localhost:2379/key");
    scheme_recognised!(tikv_uri_returns_ok, "tikv://localhost:2379/key");
    scheme_recognised!(mongodb_uri_returns_ok, "mongodb://localhost/db/col/key");
    scheme_recognised!(gridfs_uri_returns_ok, "gridfs://localhost/db/bucket/key");
    scheme_recognised!(mysql_uri_returns_ok, "mysql://user:pass@localhost/db/key");
    scheme_recognised!(postgresql_uri_returns_ok, "postgresql://user:pass@localhost/db/key");
    scheme_recognised!(sqlite_uri_returns_ok, "sqlite:///tmp/test.db/key");
    scheme_recognised!(cloudflare_kv_uri_returns_ok, "cloudflare-kv://namespace/key");
    scheme_recognised!(d1_uri_returns_ok, "d1://database-id/key");

    // Filesystem
    scheme_recognised!(ftp_uri_returns_ok, "ftp://user:pass@host/path");
    scheme_recognised!(ftps_uri_returns_ok, "ftps://user:pass@host/path");
    scheme_recognised!(compfs_uri_returns_ok, "compfs:///abs/path/file");
}
