// ---------------------------------------------------------------------------
// Auto-update module
//
// Provides version checking against GitHub Releases, self-update for
// standalone binaries, and background polling.
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_url: String,
    pub release_notes: String,
    pub published_at: String,
    pub assets: Vec<ReleaseAsset>,
    pub install_type: String,
    pub can_self_update: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub download_url: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct InstallResult {
    pub success: bool,
    pub restart_required: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InstallType {
    Nix,
    CargoDev,
    Standalone,
    Unknown,
}

impl InstallType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallType::Nix => "nix",
            InstallType::CargoDev => "cargo_dev",
            InstallType::Standalone => "standalone",
            InstallType::Unknown => "unknown",
        }
    }

    pub fn can_self_update(&self) -> bool {
        matches!(self, InstallType::Standalone)
    }
}

// ---------------------------------------------------------------------------
// GitHub API response types (private)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    published_at: Option<String>,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

/// Compare two semver-like version strings (e.g. "0.1.2" vs "0.2.0").
/// Returns true if `latest` is strictly newer than `current`.
fn is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect()
    };

    let cur = parse(current);
    let lat = parse(latest);

    // Compare component by component, padding the shorter one with zeros
    let max_len = cur.len().max(lat.len());
    for i in 0..max_len {
        let c = cur.get(i).copied().unwrap_or(0);
        let l = lat.get(i).copied().unwrap_or(0);
        if l > c {
            return true;
        }
        if l < c {
            return false;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Install type detection
// ---------------------------------------------------------------------------

/// Detect how herald was installed by examining the binary path.
pub fn detect_install_type() -> InstallType {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return InstallType::Unknown,
    };

    let path_str = exe.to_string_lossy();

    if path_str.starts_with("/nix/store/") {
        InstallType::Nix
    } else if path_str.contains("/target/debug/") || path_str.contains("/target/release/") {
        InstallType::CargoDev
    } else if exe.exists() {
        InstallType::Standalone
    } else {
        InstallType::Unknown
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Version checking
// ---------------------------------------------------------------------------

const GITHUB_REPO: &str = "jereanon/herald";

/// Build a reqwest client with the required User-Agent header.
fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    let version = env!("CARGO_PKG_VERSION");
    reqwest::Client::builder()
        .user_agent(format!("herald/{}", version))
        .build()
}

/// Check for a new release on GitHub. Returns `UpdateInfo` with all relevant
/// data, or an error string if the check fails.
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    let client = http_client().map_err(|e| format!("failed to build HTTP client: {}", e))?;

    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let response = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("failed to fetch latest release: {}", e))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // No releases published yet — not an error, just nothing to update to
        let install_type = detect_install_type();
        return Ok(UpdateInfo {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version: env!("CARGO_PKG_VERSION").to_string(),
            update_available: false,
            release_url: format!("https://github.com/{}/releases", GITHUB_REPO),
            release_notes: String::new(),
            published_at: String::new(),
            assets: vec![],
            install_type: install_type.as_str().to_string(),
            can_self_update: install_type.can_self_update(),
        });
    }

    if !response.status().is_success() {
        return Err(format!(
            "GitHub API returned status {}",
            response.status()
        ));
    }

    let release: GitHubRelease = response
        .json()
        .await
        .map_err(|e| format!("failed to parse release JSON: {}", e))?;

    // Strip leading 'v' from tag name (e.g. "v0.2.0" -> "0.2.0")
    let latest_version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name)
        .to_string();

    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let update_available = is_newer(&current_version, &latest_version);

    let install_type = detect_install_type();

    let assets: Vec<ReleaseAsset> = release
        .assets
        .iter()
        .map(|a| ReleaseAsset {
            name: a.name.clone(),
            download_url: a.browser_download_url.clone(),
            size: a.size,
        })
        .collect();

    Ok(UpdateInfo {
        current_version,
        latest_version,
        update_available,
        release_url: release.html_url,
        release_notes: release.body.unwrap_or_default(),
        published_at: release.published_at.unwrap_or_default(),
        assets,
        install_type: install_type.as_str().to_string(),
        can_self_update: install_type.can_self_update(),
    })
}

// ---------------------------------------------------------------------------
// Phase 2: Self-update (binary replacement)
// ---------------------------------------------------------------------------

/// Determine the expected asset name for the current platform.
fn platform_asset_name() -> Result<String, String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => return Err(format!("unsupported architecture: {}", other)),
    };

    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => return Err(format!("unsupported OS: {}", other)),
    };

    Ok(format!("herald-{}-{}", arch, os))
}

/// Download the new binary and replace the current executable.
///
/// `update_info` must contain the release assets for the target version.
/// `data_dir` is the directory to use for staging the download.
pub async fn download_and_install(
    update_info: &UpdateInfo,
    data_dir: &Path,
) -> Result<InstallResult, String> {
    let install_type = detect_install_type();

    if !install_type.can_self_update() {
        return Ok(InstallResult {
            success: false,
            restart_required: false,
            message: format!(
                "Self-update is not supported for install type '{}'. {}",
                install_type.as_str(),
                match install_type {
                    InstallType::Nix => "Update through your Nix configuration.",
                    InstallType::CargoDev =>
                        "Rebuild from source with `cargo build`.",
                    _ => "Update manually.",
                }
            ),
        });
    }

    // Determine the expected asset name for this platform
    let asset_name = platform_asset_name()?;
    eprintln!("[update] looking for asset: {}", asset_name);

    // Find the matching asset in the release
    let asset = update_info
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| {
            format!(
                "no matching asset '{}' found in release (available: {})",
                asset_name,
                update_info
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    // Ensure data directory exists
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("failed to create data directory: {}", e))?;

    // Download the new binary to a staging path
    let staging_path = data_dir.join(format!("herald-update-{}", update_info.latest_version));
    eprintln!(
        "[update] downloading {} to {}",
        asset.download_url,
        staging_path.display()
    );

    let client = http_client().map_err(|e| format!("failed to build HTTP client: {}", e))?;

    let response = client
        .get(&asset.download_url)
        .send()
        .await
        .map_err(|e| format!("failed to download update: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "download failed with status {}",
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("failed to read download body: {}", e))?;

    std::fs::write(&staging_path, &bytes)
        .map_err(|e| format!("failed to write staging file: {}", e))?;

    eprintln!(
        "[update] downloaded {} bytes",
        bytes.len()
    );

    // --- SHA256 verification ---
    // Look for a checksums.sha256 asset and verify if available.
    // TODO: Implement SHA256 verification once a hashing crate is available.
    //       For now we log a warning and skip verification.
    let checksums_asset = update_info
        .assets
        .iter()
        .find(|a| a.name == "checksums.sha256");

    if checksums_asset.is_some() {
        eprintln!(
            "[update] WARNING: checksums.sha256 found but SHA256 verification is not yet \
             implemented — skipping integrity check"
        );
    } else {
        eprintln!("[update] no checksums.sha256 asset found, skipping integrity check");
    }

    // --- Binary replacement ---
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("failed to determine current executable path: {}", e))?;

    let backup_path = PathBuf::from(format!("{}.bak", current_exe.display()));

    eprintln!(
        "[update] replacing {} (backup: {})",
        current_exe.display(),
        backup_path.display()
    );

    // Rename the current binary to .bak
    std::fs::rename(&current_exe, &backup_path)
        .map_err(|e| format!("failed to create backup of current binary: {}", e))?;

    // Copy the downloaded binary to the original path
    if let Err(e) = std::fs::copy(&staging_path, &current_exe) {
        // Attempt to restore the backup
        eprintln!("[update] ERROR: failed to install new binary: {}", e);
        if let Err(restore_err) = std::fs::rename(&backup_path, &current_exe) {
            eprintln!(
                "[update] CRITICAL: failed to restore backup: {} — manual intervention required",
                restore_err
            );
        } else {
            eprintln!("[update] restored backup successfully");
        }
        return Err(format!("failed to install new binary: {}", e));
    }

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("failed to set executable permissions: {}", e))?;
    }

    // Clean up the staging file
    let _ = std::fs::remove_file(&staging_path);

    eprintln!(
        "[update] successfully installed v{} — restart required",
        update_info.latest_version
    );

    Ok(InstallResult {
        success: true,
        restart_required: true,
        message: format!(
            "Updated from v{} to v{}. Please restart herald to use the new version.",
            update_info.current_version, update_info.latest_version
        ),
    })
}

// ---------------------------------------------------------------------------
// Phase 3: Background polling
// ---------------------------------------------------------------------------

/// Background update checker that periodically queries GitHub for new releases
/// and caches the result for consumption by web handlers.
pub struct UpdateChecker {
    latest: Arc<RwLock<Option<UpdateInfo>>>,
    last_check: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
    github_repo: String,
}

impl UpdateChecker {
    /// Create a new `UpdateChecker` for the herald repository.
    pub fn new() -> Self {
        Self {
            latest: Arc::new(RwLock::new(None)),
            last_check: Arc::new(RwLock::new(None)),
            github_repo: GITHUB_REPO.to_string(),
        }
    }

    /// Return the cached update information, if any.
    pub async fn get_cached(&self) -> Option<UpdateInfo> {
        self.latest.read().await.clone()
    }

    /// Return the timestamp of the last successful check.
    pub async fn last_check_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        *self.last_check.read().await
    }

    /// Perform a one-shot check and update the cache. Returns the result.
    pub async fn check_now(&self) -> Result<UpdateInfo, String> {
        let info = check_for_update().await?;

        *self.latest.write().await = Some(info.clone());
        *self.last_check.write().await = Some(chrono::Utc::now());

        if info.update_available {
            eprintln!(
                "[update] new version available: v{} -> v{} ({})",
                info.current_version, info.latest_version, info.release_url
            );
        } else {
            eprintln!(
                "[update] up to date (v{})",
                info.current_version
            );
        }

        Ok(info)
    }

    /// Spawn a background tokio task that checks for updates at the given
    /// interval (in seconds). The task runs until the process exits.
    ///
    /// The first check runs immediately, then repeats every `interval_secs`.
    pub fn start_background_check(&self, interval_secs: u64) {
        let latest = self.latest.clone();
        let last_check = self.last_check.clone();
        let repo = self.github_repo.clone();

        tokio::spawn(async move {
            eprintln!(
                "[update] background checker started (interval: {}s, repo: {})",
                interval_secs, repo
            );

            loop {
                match check_for_update().await {
                    Ok(info) => {
                        if info.update_available {
                            eprintln!(
                                "[update] new version available: v{} -> v{} ({})",
                                info.current_version, info.latest_version, info.release_url
                            );
                        }
                        *latest.write().await = Some(info);
                        *last_check.write().await = Some(chrono::Utc::now());
                    }
                    Err(e) => {
                        eprintln!("[update] background check failed: {}", e);
                        // Keep the previous cached result, just log the error
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        // Basic cases
        assert!(is_newer("0.0.1", "0.0.2"));
        assert!(is_newer("0.0.1", "0.1.0"));
        assert!(is_newer("0.0.1", "1.0.0"));
        assert!(is_newer("1.0.0", "1.0.1"));
        assert!(is_newer("1.0.0", "1.1.0"));
        assert!(is_newer("1.0.0", "2.0.0"));

        // Same version
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.0.1", "0.0.1"));

        // Older
        assert!(!is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.2.0", "0.1.9"));
        assert!(!is_newer("2.0.0", "1.99.99"));

        // Different lengths
        assert!(is_newer("1.0", "1.0.1"));
        assert!(!is_newer("1.0.1", "1.0"));
    }

    #[test]
    fn test_install_type_as_str() {
        assert_eq!(InstallType::Nix.as_str(), "nix");
        assert_eq!(InstallType::CargoDev.as_str(), "cargo_dev");
        assert_eq!(InstallType::Standalone.as_str(), "standalone");
        assert_eq!(InstallType::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_can_self_update() {
        assert!(!InstallType::Nix.can_self_update());
        assert!(!InstallType::CargoDev.can_self_update());
        assert!(InstallType::Standalone.can_self_update());
        assert!(!InstallType::Unknown.can_self_update());
    }

    #[test]
    fn test_platform_asset_name() {
        // Just verify it returns something valid on the current platform
        let result = platform_asset_name();
        assert!(result.is_ok());
        let name = result.unwrap();
        assert!(name.starts_with("herald-"));
        assert!(name.contains("x86_64") || name.contains("aarch64"));
        assert!(name.contains("linux") || name.contains("darwin"));
    }
}
