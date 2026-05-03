// rt-parser-srum — SRUM parser for RapidTriage
// Implementation is in the GREEN commit; only tests live here for RED.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn srum_parser_handles_srudb_dat_name() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("SRUDB.dat")));
    }

    #[test]
    fn srum_parser_handles_srudb_dat_case_insensitive() {
        let parser = SrumParser;
        assert!(parser.can_parse(Path::new("srudb.dat")));
        assert!(parser.can_parse(Path::new("SRUDB.DAT")));
        assert!(parser.can_parse(Path::new("Srudb.Dat")));
    }

    #[test]
    fn srum_parser_rejects_other_files() {
        let parser = SrumParser;
        assert!(!parser.can_parse(Path::new("system.log")));
        assert!(!parser.can_parse(Path::new("$MFT")));
        assert!(!parser.can_parse(Path::new("Security.evtx")));
        assert!(!parser.can_parse(Path::new("SRUDB.dat.bak")));
    }

    #[test]
    fn srum_parser_returns_empty_for_empty_file() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let parser = SrumParser;
        // empty file is not a valid ESE DB — parser must return Ok(vec![]) or Err
        // The srum-parser lib returns Err for invalid ESE; our wrapper must not panic.
        let result = parser.parse_path(tmp.path());
        // Acceptable: Ok(empty) or Err — must not panic.
        match result {
            Ok(events) => assert!(events.is_empty(), "empty file should yield no events"),
            Err(_) => {} // also acceptable — file is not a valid ESE DB
        }
    }
}
