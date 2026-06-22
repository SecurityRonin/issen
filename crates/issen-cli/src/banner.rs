//! Startup banner for the `issen` CLI.
//!
//! Original, license-clean ASCII art (a katana — *issen* / 一閃, "a single flash
//! of the blade") plus the wordmark and tagline from `assets/issen-banner.png`.
//! Shown via clap `before_help`, so `issen --help` / `issen help` lead with it.

/// The rendered startup banner (katana + wordmark + tagline + footer).
pub const BANNER: &str = "";

#[cfg(test)]
mod tests {
    #[test]
    fn banner_has_blade_wordmark_tagline_and_footer() {
        let b = super::BANNER;
        assert!(b.contains("issen"), "missing wordmark");
        assert!(b.contains(">"), "missing katana tip");
        assert!(b.contains("a single flash of the blade"), "missing motto");
        assert!(
            b.contains("One command. One output. The full attack narrative."),
            "missing tagline"
        );
        assert!(
            b.contains("Fast forensic triage for incident responders."),
            "missing subtitle"
        );
        assert!(
            b.contains("securityronin.github.io/issen"),
            "missing footer url"
        );
        assert!(
            b.contains("albert@securityronin.com"),
            "missing footer email"
        );
    }

    #[test]
    fn banner_is_wired_into_cli_help() {
        use clap::CommandFactory;
        let help = crate::Cli::command().render_long_help().to_string();
        assert!(
            help.contains("a single flash of the blade"),
            "banner not shown in --help output"
        );
    }
}
