// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Provenance written next to a recorded profile: the host, its CPU and
//! cache topology, and the settings the recording ran with. Footprint and
//! overlap numbers only mean something relative to the cache sizes and
//! sampling settings they were measured under, so those travel with the
//! samples.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROFILE_META_FILE: &str = "meta.json";
pub const PERF_MAPS_DIR: &str = "maps";

const SYSFS_CPU_ROOT: &str = "/sys/devices/system/cpu";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheInfo {
    pub level: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub size_bytes: u64,
    /// Number of distinct cache instances of this level and type on the host.
    pub instances: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuInfo {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model: Option<String>,
    pub nr_cpus_online: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInfo {
    pub modes: Vec<String>,
    pub timeout_s: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ldlat: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_freq_hz: Option<u64>,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub tool: String,
    pub version: String,
    pub recorded_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kernel: Option<String>,
    pub cpu: CpuInfo,
    pub caches: Vec<CacheInfo>,
    pub record: RecordInfo,
}

impl ProfileMeta {
    pub fn collect(record: RecordInfo) -> Self {
        let recorded_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            tool: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            recorded_at_unix,
            hostname: read_trimmed("/proc/sys/kernel/hostname"),
            kernel: read_trimmed("/proc/sys/kernel/osrelease"),
            cpu: collect_cpu_info(),
            caches: collect_caches(Path::new(SYSFS_CPU_ROOT)).unwrap_or_default(),
            record,
        }
    }

    pub fn write(&self, output_dir: &Path) -> Result<()> {
        let path = output_dir.join(PROFILE_META_FILE);
        let json = serde_json::to_string_pretty(self).context("failed to serialize meta.json")?;
        fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn collect_cpu_info() -> CpuInfo {
    let mut info = CpuInfo {
        nr_cpus_online: usize::try_from(unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) })
            .unwrap_or(0),
        ..Default::default()
    };
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "vendor_id" if info.vendor.is_none() => {
                    info.vendor = Some(value.trim().to_string())
                }
                "model name" if info.model.is_none() => info.model = Some(value.trim().to_string()),
                _ => {}
            }
            if info.vendor.is_some() && info.model.is_some() {
                break;
            }
        }
    }
    info
}

/// Parse a sysfs cache size such as `32768K`, `1M` or `49152`.
pub fn parse_cache_size(value: &str) -> Option<u64> {
    let value = value.trim();
    let (digits, multiplier) = match value.chars().last()? {
        'K' | 'k' => (&value[..value.len() - 1], 1024u64),
        'M' | 'm' => (&value[..value.len() - 1], 1024 * 1024),
        'G' | 'g' => (&value[..value.len() - 1], 1024 * 1024 * 1024),
        _ => (value, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}

/// Walk `<root>/cpu*/cache/index*` and summarize each (level, type) with its
/// size and the number of distinct instances.
pub fn collect_caches(root: &Path) -> Result<Vec<CacheInfo>> {
    let mut sizes: BTreeMap<(u32, String), u64> = BTreeMap::new();
    let mut ids: BTreeMap<(u32, String), BTreeSet<String>> = BTreeMap::new();

    for cpu_dir in list_dirs(root, "cpu")? {
        let cache_dir = cpu_dir.join("cache");
        if !cache_dir.is_dir() {
            continue;
        }
        for index_dir in list_dirs(&cache_dir, "index")? {
            let Some(level) = read_dir_value(&index_dir, "level").and_then(|v| v.parse().ok())
            else {
                continue;
            };
            let Some(kind) = read_dir_value(&index_dir, "type") else {
                continue;
            };
            let Some(size) = read_dir_value(&index_dir, "size").and_then(|v| parse_cache_size(&v))
            else {
                continue;
            };
            let key = (level, kind);
            sizes.entry(key.clone()).or_insert(size);
            let id = read_dir_value(&index_dir, "id")
                .or_else(|| read_dir_value(&index_dir, "shared_cpu_list"))
                .unwrap_or_default();
            ids.entry(key).or_default().insert(id);
        }
    }

    Ok(sizes
        .into_iter()
        .map(|((level, kind), size_bytes)| CacheInfo {
            instances: ids.get(&(level, kind.clone())).map_or(0, BTreeSet::len),
            level,
            kind,
            size_bytes,
        })
        .collect())
}

fn list_dirs(root: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(dirs),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read {}", root.display()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn read_dir_value(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Copy the perf map files JIT runtimes write to /tmp into the profile, so a
/// later perf script on another host can still symbolize their code.
pub fn copy_perf_map_files(output_dir: &Path) -> Result<usize> {
    let mut copied = 0;
    let entries = match fs::read_dir("/tmp") {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with("perf-") && name.ends_with(".map") && entry.path().is_file()) {
            continue;
        }
        let dst_dir = output_dir.join(PERF_MAPS_DIR);
        fs::create_dir_all(&dst_dir)
            .with_context(|| format!("failed to create {}", dst_dir.display()))?;
        if fs::copy(entry.path(), dst_dir.join(&name)).is_ok() {
            copied += 1;
        }
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_index(root: &Path, cpu: u32, index: u32, level: u32, kind: &str, size: &str, id: u32) {
        let dir = root
            .join(format!("cpu{cpu}"))
            .join("cache")
            .join(format!("index{index}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("level"), format!("{level}\n")).unwrap();
        fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
        fs::write(dir.join("size"), format!("{size}\n")).unwrap();
        fs::write(dir.join("id"), format!("{id}\n")).unwrap();
    }

    #[test]
    fn summarizes_cache_levels_and_instances() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        for cpu in 0..4u32 {
            write_index(root, cpu, 0, 1, "Data", "48K", cpu);
            write_index(root, cpu, 1, 1, "Instruction", "32K", cpu);
            write_index(root, cpu, 2, 2, "Unified", "1024K", cpu);
            write_index(root, cpu, 3, 3, "Unified", "32768K", cpu / 2);
        }
        fs::create_dir_all(root.join("cpufreq")).unwrap();

        let caches = collect_caches(root).unwrap();
        assert_eq!(
            caches,
            vec![
                CacheInfo {
                    level: 1,
                    kind: "Data".to_string(),
                    size_bytes: 48 * 1024,
                    instances: 4
                },
                CacheInfo {
                    level: 1,
                    kind: "Instruction".to_string(),
                    size_bytes: 32 * 1024,
                    instances: 4
                },
                CacheInfo {
                    level: 2,
                    kind: "Unified".to_string(),
                    size_bytes: 1024 * 1024,
                    instances: 4
                },
                CacheInfo {
                    level: 3,
                    kind: "Unified".to_string(),
                    size_bytes: 32 * 1024 * 1024,
                    instances: 2
                },
            ]
        );
    }
}
