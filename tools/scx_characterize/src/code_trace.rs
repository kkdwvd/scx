// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Turn perf script output for a branch stack capture into executed code
//! ranges in dso-relative space.
//!
//! Each cycles sample carries the last taken branches. The code between one
//! branch's target and the next branch's source ran straight through, so a
//! sample covers many more instructions than its own ip. The ranges are
//! translated through the mmap events perf emits so that file-backed text is
//! identified by dso and offset, which is the same across processes, while
//! JIT and anonymous text is identified per process by address.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

/// Longest straight-line stretch accepted between two consecutive branch
/// stack entries. Longer gaps are more likely to be a stack break than a
/// basic block.
pub const MAX_FALLTHROUGH_BYTES: u64 = 4096;

pub const KERNEL_DSO: &str = "[kernel]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeScriptLine {
    Sample {
        comm: String,
        pid: u32,
        tid: u32,
        time: String,
        cgroup: String,
        ip: u64,
        /// (from, to) pairs, most recent branch first.
        branches: Vec<(u64, u64)>,
    },
    Mmap {
        pid: i64,
        start: u64,
        len: u64,
        pgoff: u64,
        exec: bool,
        path: String,
    },
    Other,
}

/// A dso in a code trace, written once before its first use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeDsoRecord {
    pub kind: String,
    pub id: u32,
    pub path: String,
}

/// One cycles sample with the code it covered. `exec` holds
/// `[dso id, offset, length]` triples in dso-relative bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSampleRecord {
    pub kind: String,
    pub comm: String,
    pub tid: u32,
    pub pid: u32,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sample_time_ns: Option<u64>,
    pub cgroup: String,
    #[serde(default)]
    pub hint: u64,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip_dso: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip_off: Option<u64>,
    pub branches: usize,
    pub exec: Vec<(u32, u64, u64)>,
}

#[derive(Debug, Clone)]
struct Mapping {
    end: u64,
    pgoff: u64,
    dso: String,
}

/// Executable mappings per process plus the kernel's, built from perf's
/// mmap events in trace order.
#[derive(Debug, Default)]
pub struct AddressSpaceIndex {
    processes: HashMap<i64, BTreeMap<u64, Mapping>>,
}

const KERNEL_PID: i64 = -1;

impl AddressSpaceIndex {
    pub fn insert(&mut self, pid: i64, start: u64, len: u64, pgoff: u64, path: &str) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        let dso = dso_key(pid, path);
        let maps = self.processes.entry(pid).or_default();

        // Split or drop whatever the new mapping replaces.
        let overlapping: Vec<u64> = maps
            .range(..end)
            .filter(|&(&old_start, old)| old.end > start && old_start < end)
            .map(|(&old_start, _)| old_start)
            .collect();
        for old_start in overlapping {
            let old = maps.remove(&old_start).unwrap();
            if old_start < start {
                maps.insert(
                    old_start,
                    Mapping {
                        end: start,
                        pgoff: old.pgoff,
                        dso: old.dso.clone(),
                    },
                );
            }
            if old.end > end {
                maps.insert(
                    end,
                    Mapping {
                        end: old.end,
                        pgoff: old.pgoff + (end - old_start),
                        dso: old.dso,
                    },
                );
            }
        }

        maps.insert(start, Mapping { end, pgoff, dso });
    }

    /// Resolve a virtual address of `pid` to its dso and offset.
    pub fn resolve(&self, pid: i64, addr: u64) -> Option<(&str, u64)> {
        self.resolve_in(pid, addr)
            .or_else(|| self.resolve_in(KERNEL_PID, addr))
    }

    fn resolve_in(&self, pid: i64, addr: u64) -> Option<(&str, u64)> {
        let maps = self.processes.get(&pid)?;
        let (&start, mapping) = maps.range(..=addr).next_back()?;
        if addr >= mapping.end {
            return None;
        }
        Some((mapping.dso.as_str(), mapping.pgoff + (addr - start)))
    }

    /// Translate a virtual range of `pid` into a dso-relative range when it
    /// lies within one mapping.
    pub fn translate(&self, pid: i64, start: u64, end: u64) -> Option<(&str, u64, u64)> {
        let (dso, off) = self.resolve(pid, start)?;
        let (dso_end, off_end) = self.resolve(pid, end - 1)?;
        if dso != dso_end || off_end < off {
            return None;
        }
        Some((dso, off, off_end - off + 1))
    }
}

fn dso_key(pid: i64, path: &str) -> String {
    let path = path.trim();
    if pid == KERNEL_PID {
        if path.starts_with("[kernel") {
            return KERNEL_DSO.to_string();
        }
        return path.to_string();
    }
    if path.is_empty()
        || path.starts_with("//anon")
        || path.starts_with("[anon")
        || path.starts_with("/memfd:")
        || path.starts_with("[heap]")
        || path.starts_with("[stack")
    {
        return format!("[anon:{pid}]");
    }
    path.to_string()
}

/// Assigns dense ids to dso keys in order of first use.
#[derive(Debug, Default)]
pub struct DsoTable {
    ids: HashMap<String, u32>,
}

impl DsoTable {
    /// Returns the id and, the first time a key is seen, the record to emit.
    pub fn intern(&mut self, key: &str) -> (u32, Option<CodeDsoRecord>) {
        if let Some(&id) = self.ids.get(key) {
            return (id, None);
        }
        let id = self.ids.len() as u32;
        self.ids.insert(key.to_string(), id);
        (
            id,
            Some(CodeDsoRecord {
                kind: "dso".to_string(),
                id,
                path: key.to_string(),
            }),
        )
    }
}

fn sample_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?P<comm>.*?)\s+(?P<pid>-?\d+)/(?P<tid>-?\d+)\s+(?P<time>\d+\.\d+):\s+(?P<cgroup>\S+)\s+(?P<ip>[0-9a-fA-F]+)\s*(?P<br>.*)$",
        )
        .unwrap()
    })
}

fn mmap_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"PERF_RECORD_MMAP2?\s+(?P<pid>-?\d+)/(?P<tid>-?\d+):\s+\[0x(?P<start>[0-9a-fA-F]+)\(0x(?P<len>[0-9a-fA-F]+)\)\s+@\s+(?P<pgoff>0x[0-9a-fA-F]+|[0-9a-fA-F]+)[^\]]*\]:\s+(?P<prot>\S+)\s*(?P<path>.*)$",
        )
        .unwrap()
    })
}

fn branch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"0x(?P<from>[0-9a-fA-F]+)/0x(?P<to>[0-9a-fA-F]+)/").unwrap())
}

fn parse_hex(value: &str) -> Option<u64> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(value, 16).ok()
}

pub fn parse_code_script_line(line: &str) -> Option<CodeScriptLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("PERF_RECORD_") {
        let Some(caps) = mmap_re().captures(trimmed) else {
            return Some(CodeScriptLine::Other);
        };
        return Some(CodeScriptLine::Mmap {
            pid: caps["pid"].parse().ok()?,
            start: parse_hex(&caps["start"])?,
            len: parse_hex(&caps["len"])?,
            pgoff: parse_hex(&caps["pgoff"])?,
            exec: caps["prot"].contains('x'),
            path: caps["path"].trim().to_string(),
        });
    }

    let caps = sample_re().captures(trimmed)?;
    let branches = branch_re()
        .captures_iter(&caps["br"])
        .filter_map(|b| Some((parse_hex(&b["from"])?, parse_hex(&b["to"])?)))
        .collect();
    Some(CodeScriptLine::Sample {
        comm: caps["comm"].to_string(),
        pid: caps["pid"].parse().ok()?,
        tid: caps["tid"].parse().ok()?,
        time: caps["time"].to_string(),
        cgroup: caps["cgroup"].to_string(),
        ip: parse_hex(&caps["ip"])?,
        branches,
    })
}

/// Virtual ranges `[start, end)` a sample executed: the branch sources and
/// targets themselves, the straight-line code between consecutive entries,
/// and the stretch from the latest target to the sampled ip.
pub fn executed_ranges(ip: u64, branches: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut ranges = Vec::with_capacity(branches.len() * 2 + 1);
    ranges.push((ip, ip + 1));

    let mut push_fallthrough = |from_target: u64, to_source: u64| {
        if to_source >= from_target && to_source - from_target <= MAX_FALLTHROUGH_BYTES {
            ranges.push((from_target, to_source + 1));
        }
    };

    if let Some(&(_, latest_target)) = branches.first() {
        push_fallthrough(latest_target, ip);
    }
    for window in branches.windows(2) {
        let (newer_from, _) = window[0];
        let (_, older_to) = window[1];
        push_fallthrough(older_to, newer_from);
    }
    for &(from, to) in branches {
        ranges.push((from, from + 1));
        ranges.push((to, to + 1));
    }

    merge_ranges(ranges)
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_samples_and_mmaps_and_translates_executed_ranges() {
        let mmap = parse_code_script_line(
            "   worker  100/100  1.000010: PERF_RECORD_MMAP2 100/100: [0x7f0000000000(0x1000) @ 0x2000 <buildid>]: r-xp /usr/lib/libx.so",
        );
        let Some(CodeScriptLine::Mmap {
            pid,
            start,
            len,
            pgoff,
            exec,
            path,
        }) = mmap
        else {
            panic!("expected an mmap line");
        };
        assert!(exec);
        let mut index = AddressSpaceIndex::default();
        index.insert(pid, start, len, pgoff, &path);
        index.insert(100, 0x7f0000010000, 0x1000, 0, "//anon");
        index.insert(
            KERNEL_PID,
            0xffffffff81000000,
            0x1000000,
            0xffffffff81000000,
            "[kernel.kallsyms]_text",
        );

        let sample = parse_code_script_line(
            "   worker  100/101  1.000020: /cg 7f0000000120 0x7f0000000100/0x7f00000000f0/M/-/-/0//NON_SPEC_CORRECT_PATH 0x7f0000000050/0x7f00000000e0/P/-/-/0//NON_SPEC_CORRECT_PATH",
        );
        let Some(CodeScriptLine::Sample {
            tid, ip, branches, ..
        }) = sample
        else {
            panic!("expected a sample line");
        };
        assert_eq!(tid, 101);
        assert_eq!(
            branches,
            vec![
                (0x7f0000000100, 0x7f00000000f0),
                (0x7f0000000050, 0x7f00000000e0)
            ]
        );

        // ip at 0x120 after a branch to 0xf0: 0xf0..=0x120 ran straight; the
        // older branch landed at 0xe0 and the newer left from 0x100, so
        // 0xe0..=0x100 ran straight too; 0x50 is the oldest source.
        let ranges = executed_ranges(ip, &branches);
        assert_eq!(
            ranges,
            vec![
                (0x7f0000000050, 0x7f0000000051),
                (0x7f00000000e0, 0x7f0000000121)
            ]
        );
        assert_eq!(
            index.translate(100, ranges[1].0, ranges[1].1),
            Some(("/usr/lib/libx.so", 0x20e0, 0x41))
        );
        assert_eq!(
            index.resolve(100, 0x7f0000010010),
            Some(("[anon:100]", 0x10))
        );
        assert_eq!(
            index.resolve(100, 0xffffffff81000010),
            Some((KERNEL_DSO, 0xffffffff81000010))
        );
        assert_eq!(index.resolve(100, 0x7f0000001000), None);

        // A later mapping over the middle splits the old one.
        index.insert(100, 0x7f0000000400, 0x100, 0, "//anon");
        assert_eq!(
            index.resolve(100, 0x7f0000000500),
            Some(("/usr/lib/libx.so", 0x2500))
        );
        assert_eq!(
            index.resolve(100, 0x7f0000000450),
            Some(("[anon:100]", 0x50))
        );

        let gap = executed_ranges(0x1000, &[(0x2000, 0x3000), (0x4000, 0x9000)]);
        assert!(
            gap.iter().all(|(s, e)| e - s <= 1),
            "stretches longer than MAX_FALLTHROUGH_BYTES must be dropped: {gap:?}"
        );
    }
}
