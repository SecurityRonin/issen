pub mod builtin_remote;
pub mod c2;
pub mod firewall;
pub mod hardware;
pub mod lateral_movement;
pub mod tunneling;
pub mod webshell;

use crate::model::{Finding, RemoteAccessCategory};
use crate::providers::ArtifactProvider;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scanner error: {0}")]
    Internal(String),
}

pub trait CategoryScanner: Send + Sync {
    fn category(&self) -> RemoteAccessCategory;
    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError>;
}

/// Return all available category scanners.
pub fn all_scanners() -> Vec<Box<dyn CategoryScanner>> {
    vec![
        Box::new(builtin_remote::BuiltinRemoteScanner::new()),
        Box::new(lateral_movement::LateralMovementScanner::new()),
        Box::new(tunneling::TunnelingScanner::new()),
        Box::new(c2::C2Scanner::new()),
        Box::new(webshell::WebShellScanner::new()),
        Box::new(firewall::FirewallScanner::new()),
        Box::new(hardware::HardwareScanner::new()),
    ]
}
