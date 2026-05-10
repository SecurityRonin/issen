/// Returns true if the string looks like a remote URI (has a recognised scheme).
pub fn is_remote_uri(s: &str) -> bool {
    UriScheme::detect(s).is_some()
}

/// All URI schemes that rt-remote-io recognises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriScheme {
    // Cloud object storage
    S3,
    Gcs,
    AzBlob,
    AzDls,
    AzFile,
    B2,
    Cos,
    Obs,
    Oss,
    Swift,
    Upyun,
    // Consumer / enterprise cloud drives
    GDrive,
    OneDrive,
    Dropbox,
    AliyunDrive,
    YandexDisk,
    Pcloud,
    Koofr,
    Seafile,
    // Developer / ML / infra
    Github,
    Huggingface,
    VercelBlob,
    VercelArtifacts,
    Ghac,
    Dbfs,
    // Distributed / big data
    Alluxio,
    Hdfs,
    WebHdfs,
    Lakefs,
    // Decentralized
    Ipfs,
    Ipmfs,
    // Network KV / databases
    Redis,
    Rediss,
    Memcached,
    Etcd,
    Tikv,
    Mongodb,
    Gridfs,
    Mysql,
    Postgresql,
    Sqlite,
    CloudflareKv,
    D1,
    // Filesystem / network protocols
    WebDav,
    Http,
    Https,
    Sftp,
    Ftp,
    Ftps,
    Compfs,
    File,
    // In-memory
    Mem,
}

impl UriScheme {
    /// Detect the scheme from a URI string. Returns None for unrecognised schemes.
    pub fn detect(uri: &str) -> Option<Self> {
        let scheme = uri.split("://").next()?;
        if scheme == uri {
            // No "://" found.
            return None;
        }
        match scheme {
            // Cloud object storage
            "s3" => Some(Self::S3),
            "gcs" => Some(Self::Gcs),
            "azblob" => Some(Self::AzBlob),
            "azdls" => Some(Self::AzDls),
            "azfile" => Some(Self::AzFile),
            "b2" => Some(Self::B2),
            "cos" => Some(Self::Cos),
            "obs" => Some(Self::Obs),
            "oss" => Some(Self::Oss),
            "swift" => Some(Self::Swift),
            "upyun" => Some(Self::Upyun),
            // Consumer / enterprise cloud drives
            "gdrive" => Some(Self::GDrive),
            "onedrive" => Some(Self::OneDrive),
            "dropbox" => Some(Self::Dropbox),
            "aliyun-drive" => Some(Self::AliyunDrive),
            "yandex-disk" => Some(Self::YandexDisk),
            "pcloud" => Some(Self::Pcloud),
            "koofr" => Some(Self::Koofr),
            "seafile" => Some(Self::Seafile),
            // Developer / ML / infra
            "github" => Some(Self::Github),
            "huggingface" => Some(Self::Huggingface),
            "vercel-blob" => Some(Self::VercelBlob),
            "vercel-artifacts" => Some(Self::VercelArtifacts),
            "ghac" => Some(Self::Ghac),
            "dbfs" => Some(Self::Dbfs),
            // Distributed / big data
            "alluxio" => Some(Self::Alluxio),
            "hdfs" => Some(Self::Hdfs),
            "webhdfs" => Some(Self::WebHdfs),
            "lakefs" => Some(Self::Lakefs),
            // Decentralized
            "ipfs" => Some(Self::Ipfs),
            "ipmfs" => Some(Self::Ipmfs),
            // Network KV / databases
            "redis" => Some(Self::Redis),
            "rediss" => Some(Self::Rediss),
            "memcached" => Some(Self::Memcached),
            "etcd" => Some(Self::Etcd),
            "tikv" => Some(Self::Tikv),
            "mongodb" => Some(Self::Mongodb),
            "gridfs" => Some(Self::Gridfs),
            "mysql" => Some(Self::Mysql),
            "postgresql" => Some(Self::Postgresql),
            "sqlite" => Some(Self::Sqlite),
            "cloudflare-kv" => Some(Self::CloudflareKv),
            "d1" => Some(Self::D1),
            // Filesystem / network protocols
            "webdav" => Some(Self::WebDav),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "sftp" => Some(Self::Sftp),
            "ftp" => Some(Self::Ftp),
            "ftps" => Some(Self::Ftps),
            "compfs" => Some(Self::Compfs),
            "file" => Some(Self::File),
            // In-memory
            "mem" => Some(Self::Mem),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_remote_uri_recognised_schemes() {
        for uri in &[
            "s3://bucket/key",
            "gcs://bucket/obj",
            "azblob://container/blob",
            "http://example.com/file",
            "https://example.com/file",
            "mem://bucket/key",
            "file:///tmp/foo",
            "gdrive://file-id",
            "sftp://host/path",
            "hdfs://host/path",
            "webhdfs://host/path",
            // new schemes
            "azdls://filesystem/path",
            "azfile://share/path",
            "b2://bucket/key",
            "cos://bucket/key",
            "obs://bucket/key",
            "oss://bucket/key",
            "swift://container/path",
            "upyun://bucket/key",
            "onedrive://path",
            "dropbox://path",
            "aliyun-drive://path",
            "yandex-disk://path",
            "pcloud://path",
            "koofr://path",
            "seafile://server/repo/path",
            "github://owner/repo/path",
            "huggingface://owner/model/file",
            "vercel-blob://key",
            "vercel-artifacts://key",
            "ghac://key",
            "dbfs://path",
            "alluxio://host:19999/path",
            "lakefs://repo/main/path",
            "ipfs://QmHash/path",
            "ipmfs:///path",
            "redis://localhost:6379/key",
            "rediss://localhost:6380/key",
            "memcached://localhost:11211/key",
            "etcd://localhost:2379/key",
            "tikv://localhost:2379/key",
            "mongodb://localhost/db/col/key",
            "gridfs://localhost/db/bucket/key",
            "mysql://user:pass@localhost/db/key",
            "postgresql://user:pass@localhost/db/key",
            "sqlite:///tmp/test.db/key",
            "cloudflare-kv://namespace/key",
            "d1://database-id/key",
            "ftp://user:pass@host/path",
            "ftps://user:pass@host/path",
            "compfs:///abs/path/file",
        ] {
            assert!(is_remote_uri(uri), "expected true for {uri}");
        }
    }

    #[test]
    fn is_remote_uri_bare_path_is_false() {
        assert!(!is_remote_uri("/tmp/local/file"));
        assert!(!is_remote_uri("relative/path"));
        assert!(!is_remote_uri(""));
        assert!(!is_remote_uri("unknown://host/path"));
    }

    #[test]
    fn uri_scheme_detect_each_scheme() {
        assert_eq!(UriScheme::detect("s3://bucket/key"), Some(UriScheme::S3));
        assert_eq!(UriScheme::detect("gcs://bucket/obj"), Some(UriScheme::Gcs));
        assert_eq!(
            UriScheme::detect("azblob://container/blob"),
            Some(UriScheme::AzBlob)
        );
        assert_eq!(
            UriScheme::detect("gdrive://file-id"),
            Some(UriScheme::GDrive)
        );
        assert_eq!(UriScheme::detect("sftp://host/path"), Some(UriScheme::Sftp));
        assert_eq!(
            UriScheme::detect("webdav://host/path"),
            Some(UriScheme::WebDav)
        );
        assert_eq!(UriScheme::detect("hdfs://host/path"), Some(UriScheme::Hdfs));
        assert_eq!(
            UriScheme::detect("webhdfs://host/path"),
            Some(UriScheme::WebHdfs)
        );
        assert_eq!(
            UriScheme::detect("http://example.com/file"),
            Some(UriScheme::Http)
        );
        assert_eq!(
            UriScheme::detect("https://example.com/file"),
            Some(UriScheme::Https)
        );
        assert_eq!(
            UriScheme::detect("mem://bucket/key"),
            Some(UriScheme::Mem)
        );
        assert_eq!(UriScheme::detect("file:///tmp/foo"), Some(UriScheme::File));
        // new schemes
        assert_eq!(UriScheme::detect("azdls://fs/path"), Some(UriScheme::AzDls));
        assert_eq!(UriScheme::detect("azfile://share/path"), Some(UriScheme::AzFile));
        assert_eq!(UriScheme::detect("b2://bucket/key"), Some(UriScheme::B2));
        assert_eq!(UriScheme::detect("cos://bucket/key"), Some(UriScheme::Cos));
        assert_eq!(UriScheme::detect("obs://bucket/key"), Some(UriScheme::Obs));
        assert_eq!(UriScheme::detect("oss://bucket/key"), Some(UriScheme::Oss));
        assert_eq!(UriScheme::detect("swift://container/path"), Some(UriScheme::Swift));
        assert_eq!(UriScheme::detect("upyun://bucket/key"), Some(UriScheme::Upyun));
        assert_eq!(UriScheme::detect("onedrive://path"), Some(UriScheme::OneDrive));
        assert_eq!(UriScheme::detect("dropbox://path"), Some(UriScheme::Dropbox));
        assert_eq!(UriScheme::detect("aliyun-drive://path"), Some(UriScheme::AliyunDrive));
        assert_eq!(UriScheme::detect("yandex-disk://path"), Some(UriScheme::YandexDisk));
        assert_eq!(UriScheme::detect("pcloud://path"), Some(UriScheme::Pcloud));
        assert_eq!(UriScheme::detect("koofr://path"), Some(UriScheme::Koofr));
        assert_eq!(UriScheme::detect("seafile://server/repo/path"), Some(UriScheme::Seafile));
        assert_eq!(UriScheme::detect("github://owner/repo/path"), Some(UriScheme::Github));
        assert_eq!(UriScheme::detect("huggingface://owner/model/file"), Some(UriScheme::Huggingface));
        assert_eq!(UriScheme::detect("vercel-blob://key"), Some(UriScheme::VercelBlob));
        assert_eq!(UriScheme::detect("vercel-artifacts://key"), Some(UriScheme::VercelArtifacts));
        assert_eq!(UriScheme::detect("ghac://key"), Some(UriScheme::Ghac));
        assert_eq!(UriScheme::detect("dbfs://path"), Some(UriScheme::Dbfs));
        assert_eq!(UriScheme::detect("alluxio://host:19999/path"), Some(UriScheme::Alluxio));
        assert_eq!(UriScheme::detect("lakefs://repo/main/path"), Some(UriScheme::Lakefs));
        assert_eq!(UriScheme::detect("ipfs://QmHash/path"), Some(UriScheme::Ipfs));
        assert_eq!(UriScheme::detect("ipmfs:///path"), Some(UriScheme::Ipmfs));
        assert_eq!(UriScheme::detect("redis://localhost/key"), Some(UriScheme::Redis));
        assert_eq!(UriScheme::detect("rediss://localhost/key"), Some(UriScheme::Rediss));
        assert_eq!(UriScheme::detect("memcached://localhost/key"), Some(UriScheme::Memcached));
        assert_eq!(UriScheme::detect("etcd://localhost/key"), Some(UriScheme::Etcd));
        assert_eq!(UriScheme::detect("tikv://localhost/key"), Some(UriScheme::Tikv));
        assert_eq!(UriScheme::detect("mongodb://localhost/db/col/key"), Some(UriScheme::Mongodb));
        assert_eq!(UriScheme::detect("gridfs://localhost/db/bucket/key"), Some(UriScheme::Gridfs));
        assert_eq!(UriScheme::detect("mysql://user@localhost/db/key"), Some(UriScheme::Mysql));
        assert_eq!(UriScheme::detect("postgresql://user@localhost/db/key"), Some(UriScheme::Postgresql));
        assert_eq!(UriScheme::detect("sqlite:///tmp/test.db/key"), Some(UriScheme::Sqlite));
        assert_eq!(UriScheme::detect("cloudflare-kv://namespace/key"), Some(UriScheme::CloudflareKv));
        assert_eq!(UriScheme::detect("d1://database-id/key"), Some(UriScheme::D1));
        assert_eq!(UriScheme::detect("ftp://user@host/path"), Some(UriScheme::Ftp));
        assert_eq!(UriScheme::detect("ftps://user@host/path"), Some(UriScheme::Ftps));
        assert_eq!(UriScheme::detect("compfs:///abs/path"), Some(UriScheme::Compfs));
    }

    #[test]
    fn uri_scheme_detect_unknown_is_none() {
        assert_eq!(UriScheme::detect("unknown://host/path"), None);
        assert_eq!(UriScheme::detect("/tmp/local"), None);
        assert_eq!(UriScheme::detect(""), None);
    }
}
