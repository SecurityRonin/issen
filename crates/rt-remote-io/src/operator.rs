use anyhow::{anyhow, Result};
use opendal::{Operator, services};

/// Build an OpenDAL [`Operator`] for the given URI, and return the relative path
/// within that backend.
///
/// Supported URI schemes:
/// - `mem://` — in-process memory backend; path = everything after `mem://`
/// - `s3://` — AWS S3; authority = bucket, path = key
/// - `gcs://` — Google Cloud Storage; authority = bucket, path = object
/// - `azblob://` — Azure Blob Storage; authority = container, path = blob
/// - `webdav://` — WebDAV; authority+path = endpoint+remote path
/// - `http://` / `https://` — HTTP(S); full URI used as endpoint + path
/// - `file://` — Local filesystem; path portion used
///
/// Returns an error for unknown or unsupported schemes.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    let Some(scheme_end) = uri.find("://") else {
        return Err(anyhow!("URI has no scheme: {uri}"));
    };
    let scheme = &uri[..scheme_end];
    let rest = &uri[scheme_end + 3..]; // everything after "://"

    match scheme {
        "mem" => {
            // mem://bucket/key → operator root="/", path = "bucket/key"
            let builder = services::Memory::default();
            let op = Operator::new(builder)?.finish();
            Ok((op, rest.to_string()))
        }

        "s3" => {
            // s3://bucket/key
            let (bucket, path) = split_authority_path(rest);
            let builder = services::S3::default().bucket(bucket);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
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
            let (container, path) = split_authority_path(rest);
            let builder = services::Azblob::default().container(container);
            let op = Operator::new(builder)?.finish();
            Ok((op, path.to_string()))
        }

        "webdav" => {
            // webdav://host/path
            let endpoint = format!("http://{rest}");
            let builder = services::Webdav::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            Ok((op, "/".to_string()))
        }

        "http" | "https" => {
            // http://host/path → endpoint = scheme://host, path = /path
            let url = uri;
            let (endpoint, path) = if let Some(slash) = rest.find('/') {
                let host = &rest[..slash];
                let path = &rest[slash..];
                (format!("{scheme}://{host}"), path.to_string())
            } else {
                (format!("{scheme}://{rest}"), "/".to_string())
            };
            let builder = services::Http::default().endpoint(&endpoint);
            let op = Operator::new(builder)?.finish();
            let _ = url; // suppress unused warning
            Ok((op, path))
        }

        "file" => {
            // file:///path → local FS rooted at /
            let builder = services::Fs::default().root("/");
            let op = Operator::new(builder)?.finish();
            // rest after "file://" is "//path" for file:///path, or "/path" for file://host/path
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
}
