//! Retires the files the ECC Zcash SDKs left behind before the move to
//! zingolib.
//!
//! The old SDKs named every wallet file after the wallet alias, so a wallet
//! that opens here without a `zingo-wallet.dat` has its old files deleted,
//! after one copy of the Sapling parameters is taken into the new cache
//! instead of being downloaded again.
//!
//! iOS kept everything at the Documents root, with each SDK under its own
//! prefix, so a sweep of the Zcash prefix also finds wallets that were
//! deleted before the update and never open again. Android kept the files
//! in a directory the Pirate Chain SDK shares, under the same names, so only
//! files named after an alias that opens here are touched there, and the
//! shared parameters and Tor directory stay.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use zingolib::wallet::sapling_params::SaplingParamFile;

static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

/// The sweep and a wallet opening can reach the same files at once.
static RETIRE_LOCK: Mutex<()> = Mutex::new(());

const NETWORKS: [&str; 2] = ["mainnet", "testnet"];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Layout {
    Ios,
    Android,
}

impl Layout {
    fn current() -> Option<Self> {
        if cfg!(target_os = "ios") {
            Some(Self::Ios)
        } else if cfg!(target_os = "android") {
            Some(Self::Android)
        } else {
            None
        }
    }
}

/// The ZcashLightClientKit names, after `ZcashSdk_<network>_<alias>`.
/// SQLite sidecars come before their database so the longest name matches
/// first when the sweep recovers an alias. Since SDK 0.21 every name except
/// the cache database also starts with `c_<alias>_`; see `ios_prefixes`.
const IOS_SUFFIXES: [&str; 13] = [
    "data.db-journal",
    "data.db-wal",
    "data.db-shm",
    "data.db",
    "caches.db-journal",
    "caches.db-wal",
    "caches.db-shm",
    "caches.db",
    "fs_cache",
    "tor",
    "general_storage",
    // Written by SDK releases before 2.0.
    "pending.db-journal",
    "pending.db",
];

/// The zcash-android-sdk database names, after `<alias>_<network>_`.
const ANDROID_DATABASES: [&str; 3] = ["data.sqlite3", "cache.sqlite3", "pending_transactions.sqlite3"];
const SQLITE_SIDECARS: [&str; 4] = ["", "-journal", "-wal", "-shm"];

/// Names the directory the old SDK kept its files in: the Documents root on
/// iOS, `co.electricoin.zcash` under the no-backup files directory on
/// Android. Call after the document directory is set. On iOS this also
/// starts the sweep on a background thread.
#[cfg_attr(not(feature = "uniffi-backend"), allow(dead_code))]
pub fn set_directory(directory: PathBuf) {
    if DIRECTORY.set(directory.clone()).is_err() {
        return;
    }
    if Layout::current() == Some(Layout::Ios) {
        std::thread::spawn(move || {
            let aliases = sweep_aliases(&directory);
            for alias in aliases {
                retire_logged(&directory, Layout::Ios, &alias);
            }
        });
    }
}

/// Retires the old files of one wallet. Runs only when the wallet has no
/// zingolib file yet, and never fails the open: a file that cannot be
/// removed now is tried again on a later launch.
pub fn retire_alias(alias: &str) {
    let (Some(directory), Some(layout)) = (DIRECTORY.get(), Layout::current()) else {
        return;
    };
    retire_logged(directory, layout, alias);
}

fn retire_logged(directory: &Path, layout: Layout, alias: &str) {
    let _turn = RETIRE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let report = retire(directory, layout, alias);
    if report.removed > 0 || report.adopted > 0 || !report.errors.is_empty() {
        eprintln!(
            "[zcash] retired ECC SDK files for {alias}: {} removed, {} params reused, errors {:?}",
            report.removed, report.adopted, report.errors
        );
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub removed: usize,
    pub adopted: usize,
    pub errors: Vec<String>,
}

pub fn retire(directory: &Path, layout: Layout, alias: &str) -> Report {
    let mut report = Report::default();
    match layout {
        Layout::Ios => {
            for prefix in ios_prefixes(alias) {
                // The parameters go first: the wallet files are useless
                // without them, but the parameters save a download.
                for file in SaplingParamFile::ALL {
                    let path = directory.join(format!("{prefix}{alias}{}", file.file_name()));
                    adopt(file, &path, true, &mut report);
                    remove(&path, &mut report);
                }
                for network in NETWORKS {
                    for suffix in IOS_SUFFIXES {
                        remove(
                            &directory.join(format!("{prefix}ZcashSdk_{network}_{alias}{suffix}")),
                            &mut report,
                        );
                    }
                }
            }
        }
        Layout::Android => {
            // Shared with the Pirate Chain SDK, so copied and left in place.
            for file in SaplingParamFile::ALL {
                adopt(file, &directory.join(file.file_name()), false, &mut report);
            }
            let prefix = if alias.ends_with('_') {
                alias.to_string()
            } else {
                format!("{alias}_")
            };
            for network in NETWORKS {
                for database in ANDROID_DATABASES {
                    for sidecar in SQLITE_SIDECARS {
                        remove(
                            &directory.join(format!("{prefix}{network}_{database}{sidecar}")),
                            &mut report,
                        );
                    }
                }
                remove(&directory.join(format!("{prefix}{network}_fs_cache")), &mut report);
            }
        }
    }
    report
}

/// The aliases behind every Zcash SDK entry at the iOS Documents root.
pub fn sweep_aliases(directory: &Path) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return aliases;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(alias) = ios_alias(name) {
            aliases.insert(alias.to_string());
        }
    }
    aliases
}

/// SDK releases before 0.21 used the bare names. Later ones put the alias in
/// front again (`ZcashSynchronizerAlias.custom` joins `c_<alias>` and the
/// name with `_`), except on the cache database.
fn ios_prefixes(alias: &str) -> [String; 2] {
    [String::new(), format!("c_{alias}_")]
}

fn ios_alias(name: &str) -> Option<&str> {
    if let Some(alias) = ios_bare_alias(name) {
        return Some(alias);
    }
    let (outer, inner) = name.strip_prefix("c_")?.split_once('_')?;
    (ios_bare_alias(inner)? == outer).then_some(outer)
}

fn ios_bare_alias(name: &str) -> Option<&str> {
    let rest = NETWORKS
        .iter()
        .find_map(|network| name.strip_prefix(&format!("ZcashSdk_{network}_")))?;
    let alias = IOS_SUFFIXES
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))?;
    (!alias.is_empty()).then_some(alias)
}

fn adopt(file: SaplingParamFile, path: &Path, consume: bool, report: &mut Report) {
    if !path.exists() {
        return;
    }
    match crate::sapling_params::adopt(file, path, consume) {
        Ok(true) => report.adopted += 1,
        Ok(false) => {}
        Err(e) => report.errors.push(format!("{}: {e}", path.display())),
    }
}

fn remove(path: &Path, report: &mut Report) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    let result = if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match result {
        Ok(()) => report.removed += 1,
        Err(e) => report.errors.push(format!("{}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALIAS: &str = "0A1B2C";

    fn touch(directory: &Path, name: &str) {
        std::fs::write(directory.join(name), b"x").unwrap();
    }

    fn names(directory: &Path) -> BTreeSet<String> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    #[test]
    fn ios_retires_only_the_alias_zcash_files() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        for name in [
            // The names SDK 2.x writes, as found on a simulator.
            "c_0A1B2C_ZcashSdk_mainnet_0A1B2Cdata.db",
            "c_0A1B2C_ZcashSdk_mainnet_0A1B2Cdata.db-journal",
            "c_0A1B2C_0A1B2Csapling-spend.params",
            "c_0A1B2C_0A1B2Csapling-output.params",
            "ZcashSdk_mainnet_0A1B2Ccaches.db",
            // The bare names of SDK releases before 0.21.
            "ZcashSdk_mainnet_0A1B2Cdata.db",
            "ZcashSdk_mainnet_0A1B2Cdata.db-wal",
            "ZcashSdk_testnet_0A1B2Cdata.db",
            "0A1B2Csapling-spend.params",
            // Another Zcash wallet, a Pirate wallet and its parameters.
            "c_FFFF_ZcashSdk_mainnet_FFFFdata.db",
            "c_EEEE_PirateSdk_mainnet_EEEEpirate_data.db",
            "c_EEEE_EEEEsapling-spend.params",
            "native",
        ] {
            touch(dir, name);
        }
        for name in [
            "c_0A1B2C_ZcashSdk_mainnet_0A1B2Cfs_cache",
            "c_0A1B2C_ZcashSdk_mainnet_0A1B2Ctor",
            "ZcashSdk_mainnet_0A1B2Cfs_cache",
        ] {
            std::fs::create_dir(dir.join(name)).unwrap();
            touch(&dir.join(name), "inner");
        }

        let report = retire(dir, Layout::Ios, ALIAS);

        assert_eq!(report.removed, 12, "{report:?}");
        assert_eq!(
            names(dir),
            BTreeSet::from(
                [
                    "c_FFFF_ZcashSdk_mainnet_FFFFdata.db",
                    "c_EEEE_PirateSdk_mainnet_EEEEpirate_data.db",
                    "c_EEEE_EEEEsapling-spend.params",
                    "native",
                ]
                .map(String::from)
            )
        );
    }

    #[test]
    fn ios_sweep_finds_zcash_aliases_only() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        for name in [
            "ZcashSdk_mainnet_0A1B2Cdata.db-wal",
            "ZcashSdk_testnet_77general_storage",
            "c_55_ZcashSdk_mainnet_55fs_cache",
            "ZcashSdk_mainnet_data.db",
            "ZcashSdk_mainnet_88unknown",
            "c_66_ZcashSdk_mainnet_67data.db",
            "c_EEEE_PirateSdk_mainnet_EEEEpirate_data.db",
            "c_99_99sapling-spend.params",
        ] {
            touch(dir, name);
        }
        assert_eq!(
            sweep_aliases(dir),
            BTreeSet::from(["0A1B2C", "55", "77"].map(String::from))
        );
    }

    /// Needs real parameter files, so it runs only when
    /// `ZCASH_TEST_PARAMS_DIR` names a directory holding them.
    #[test]
    fn ios_moves_verified_params_into_the_cache() {
        let Some(source) = std::env::var_os("ZCASH_TEST_PARAMS_DIR") else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        let cache = dir.join("native/zcash/sapling-params");
        crate::sapling_params::set_directory(cache.clone()).unwrap();
        for file in SaplingParamFile::ALL {
            std::fs::copy(
                Path::new(&source).join(file.file_name()),
                dir.join(format!("c_{ALIAS}_{ALIAS}{}", file.file_name())),
            )
            .unwrap();
        }
        touch(dir, "c_0A1B2C_ZcashSdk_mainnet_0A1B2Cdata.db");

        let report = retire(dir, Layout::Ios, ALIAS);

        assert_eq!((report.adopted, report.removed), (2, 1), "{report:?}");
        assert!(report.errors.is_empty(), "{report:?}");
        assert_eq!(names(dir), BTreeSet::from(["native".to_string()]));
        for file in SaplingParamFile::ALL {
            let bytes = std::fs::read(cache.join(file.file_name())).unwrap();
            assert!(file.verify(&bytes).is_ok());
        }
    }

    #[test]
    fn android_keeps_shared_files() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        for name in [
            "0A1B2C_mainnet_data.sqlite3",
            "0A1B2C_mainnet_data.sqlite3-journal",
            "0A1B2C_mainnet_cache.sqlite3",
            "0A1B2C_testnet_pending_transactions.sqlite3-wal",
            // Pirate shares the directory and the parameter names.
            "EEEE_mainnet_data.sqlite3",
            "sapling-spend.params",
            "sapling-output.params",
        ] {
            touch(dir, name);
        }
        std::fs::create_dir(dir.join("0A1B2C_mainnet_fs_cache")).unwrap();
        std::fs::create_dir(dir.join("tor")).unwrap();

        let report = retire(dir, Layout::Android, ALIAS);

        assert_eq!(report.removed, 5, "{report:?}");
        assert_eq!(
            names(dir),
            BTreeSet::from(
                [
                    "EEEE_mainnet_data.sqlite3",
                    "sapling-spend.params",
                    "sapling-output.params",
                    "tor",
                ]
                .map(String::from)
            )
        );
    }
}
