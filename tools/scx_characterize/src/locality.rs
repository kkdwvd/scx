// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Footprints and sharing of data and code per thread class.
//!
//! Every sample is a draw from the lines a class touches. Observed distinct
//! lines understate the footprint, so the Chao1 estimator extends the count
//! by the unseen mass that singletons and doubletons imply, and Good-Turing
//! coverage says how much of the class's access mass the observed lines
//! account for. Sharing between two classes is measured on sample mass, not
//! set membership: the containment of a in b is the share of a's samples
//! that fell on lines b also touched, and the cosine compares the two mass
//! vectors. Reuse figures are intervals between successive samples of the
//! same line by the same entity, so they scale with the sampling period and
//! compare entities within one profile rather than measure true reuse time.

use crate::code_trace::{CodeDsoRecord, CodeSampleRecord};
use crate::process::PerfMemRecord;
use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LocalityGroupBy {
    /// Group samples by thread id
    Tid,
    /// Group samples by process id
    Pid,
    /// Group samples by command name
    Comm,
    /// Group samples by command name and hint value
    CommHint,
}

#[derive(Debug, Parser)]
pub struct ExtractLocalityOpts {
    /// Path to mem/perf.mem.jsonl for data footprints and sharing
    #[clap(long)]
    pub mem: Option<PathBuf>,

    /// Path to code/perf.code.jsonl for code footprints and sharing
    #[clap(long)]
    pub code: Option<PathBuf>,

    /// Entity grouping
    #[clap(long, value_enum, default_value = "comm")]
    pub group_by: LocalityGroupBy,

    /// Window sizes in milliseconds; 0 covers the whole trace
    #[clap(long, value_delimiter = ',', default_value = "0")]
    pub window_ms: Vec<u64>,

    /// Cache line size in bytes
    #[clap(long, default_value = "64")]
    pub line_bytes: u64,

    /// Page size in bytes
    #[clap(long, default_value = "4096")]
    pub page_bytes: u64,

    /// Minimum samples an entity needs in a window to be reported
    #[clap(long, default_value = "32")]
    pub min_samples: u64,

    /// Only the this many entities with the most samples take part in pairs
    #[clap(long, default_value = "64")]
    pub max_pair_entities: usize,

    /// Regex filter on command names
    #[clap(long)]
    pub comm_regex: Option<String>,

    /// Only print per-window summaries, not entities and pairs
    #[clap(long)]
    pub summary_only: bool,
}

/// A cache line in either space. Data lines are physical line numbers; code
/// lines carry the dso id in the high half so dsos never collide.
type LineKey = u128;

#[derive(Debug, Default)]
struct Footprint {
    lines: HashMap<LineKey, u32>,
    samples: u64,
}

#[derive(Debug, Clone, Serialize)]
struct FootprintStats {
    samples: u64,
    lines_observed: u64,
    lines_chao1: f64,
    line_coverage: f64,
    footprint_bytes_observed: u64,
    footprint_bytes_chao1: f64,
    pages_observed: u64,
    pages_chao1: f64,
}

impl Footprint {
    fn observe(&mut self, line: LineKey) {
        *self.lines.entry(line).or_insert(0) += 1;
    }

    fn mass(&self) -> f64 {
        self.lines.values().map(|&c| c as f64).sum()
    }

    fn stats(&self, line_bytes: u64, lines_per_page: u64) -> FootprintStats {
        let (lines_chao1, line_coverage) = chao1_and_coverage(self.lines.values().copied());
        let mut pages: HashMap<LineKey, u32> = HashMap::new();
        for (&line, &count) in &self.lines {
            *pages.entry(line / lines_per_page as u128).or_insert(0) += count;
        }
        let (pages_chao1, _) = chao1_and_coverage(pages.values().copied());
        FootprintStats {
            samples: self.samples,
            lines_observed: self.lines.len() as u64,
            lines_chao1,
            line_coverage,
            footprint_bytes_observed: self.lines.len() as u64 * line_bytes,
            footprint_bytes_chao1: lines_chao1 * line_bytes as f64,
            pages_observed: pages.len() as u64,
            pages_chao1,
        }
    }
}

/// Chao1 richness estimate and Good-Turing sample coverage from per-item
/// counts: `S + f1^2 / (2 f2)`, or `S + f1 (f1 - 1) / 2` without doubletons,
/// and `1 - f1 / n`.
fn chao1_and_coverage(counts: impl Iterator<Item = u32>) -> (f64, f64) {
    let mut observed = 0u64;
    let mut n = 0u64;
    let mut f1 = 0u64;
    let mut f2 = 0u64;
    for count in counts {
        observed += 1;
        n += count as u64;
        match count {
            1 => f1 += 1,
            2 => f2 += 1,
            _ => {}
        }
    }
    if n == 0 {
        return (0.0, 0.0);
    }
    let unseen = if f2 > 0 {
        (f1 * f1) as f64 / (2 * f2) as f64
    } else {
        (f1 * f1.saturating_sub(1)) as f64 / 2.0
    };
    (observed as f64 + unseen, 1.0 - f1 as f64 / n as f64)
}

#[derive(Debug, Default)]
struct DataEntity {
    footprint: Footprint,
    loads: u64,
    stores: u64,
    levels: BTreeMap<String, u64>,
    beyond_llc: u64,
    store_lines: HashSet<LineKey>,
    last_seen_ns: HashMap<LineKey, u64>,
    reuse_times_ns: Vec<u64>,
    latency_sum: u64,
    latency_samples: u64,
}

#[derive(Debug, Default)]
struct CodeEntity {
    footprint: Footprint,
    dso_mass: HashMap<u32, u64>,
}

#[derive(Debug, Clone, Serialize)]
struct DsoShare {
    path: String,
    share: f64,
}

#[derive(Debug, Clone, Serialize)]
struct EntityRecord {
    kind: &'static str,
    space: &'static str,
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    entity: String,
    #[serde(flatten)]
    footprint: FootprintStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    loads: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stores: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    store_share: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    levels: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beyond_llc_share: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampled_reuse_fraction: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampled_reuse_p50_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampled_reuse_p90_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_mean_cycles: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_dsos: Option<Vec<DsoShare>>,
}

#[derive(Debug, Clone, Serialize)]
struct PairRecord {
    kind: &'static str,
    space: &'static str,
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    a: String,
    b: String,
    samples_a: u64,
    samples_b: u64,
    shared_lines: u64,
    line_jaccard: f64,
    /// Share of a's sample mass on lines b also touched, and the reverse.
    containment_ab: f64,
    containment_ba: f64,
    cosine: f64,
    shared_pages: u64,
    page_jaccard: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_shared_lines: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_shared_share: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryRecord {
    kind: &'static str,
    space: &'static str,
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    entities: usize,
    pairs: usize,
    samples: u64,
    union_lines: u64,
    union_pages: u64,
    mean_cosine: f64,
    max_cosine: f64,
}

type WindowKey = (u64, u64);

#[derive(Default)]
struct Windows<E> {
    by_window: BTreeMap<WindowKey, BTreeMap<String, E>>,
}

impl<E: Default> Windows<E> {
    fn entity(&mut self, window: WindowKey, entity: &str) -> &mut E {
        self.by_window
            .entry(window)
            .or_default()
            .entry(entity.to_string())
            .or_default()
    }
}

struct Windowing {
    trace_start_ns: u64,
    window_ms: Vec<u64>,
}

impl Windowing {
    fn keys(&self, time_ns: u64) -> impl Iterator<Item = WindowKey> + '_ {
        self.window_ms.iter().map(move |&window_ms| {
            if window_ms == 0 {
                return (0, self.trace_start_ns);
            }
            let window_ns = window_ms * 1_000_000;
            let offset = time_ns.saturating_sub(self.trace_start_ns);
            (
                window_ms,
                self.trace_start_ns + (offset / window_ns) * window_ns,
            )
        })
    }
}

pub fn cmd_extract_locality(opts: ExtractLocalityOpts) -> Result<()> {
    if opts.mem.is_none() && opts.code.is_none() {
        bail!("at least one of --mem or --code is required");
    }
    if opts.line_bytes == 0
        || opts.page_bytes == 0
        || !opts.page_bytes.is_multiple_of(opts.line_bytes)
    {
        bail!("--page-bytes must be a positive multiple of --line-bytes");
    }
    let comm_regex = opts
        .comm_regex
        .as_deref()
        .map(Regex::new)
        .transpose()
        .context("invalid --comm-regex")?;
    let lines_per_page = opts.page_bytes / opts.line_bytes;

    if let Some(mem_path) = &opts.mem {
        let records = load_mem_records(mem_path, comm_regex.as_ref())?;
        let windowing = windowing_for(records.iter().filter_map(|r| r.sample_time_ns), &opts)?;
        let mut windows: Windows<DataEntity> = Windows::default();
        for record in &records {
            let Some(time_ns) = record.sample_time_ns else {
                continue;
            };
            let Some(phys) = parse_hex(&record.phys_addr) else {
                continue;
            };
            let line = (phys / opts.line_bytes) as LineKey;
            let entity = entity_name(
                &opts.group_by,
                &record.comm,
                record.pid,
                record.tid,
                record.hint,
            );
            for key in windowing.keys(time_ns) {
                observe_data(windows.entity(key, &entity), record, line, time_ns);
            }
        }
        emit_space("data", &windows, &opts, lines_per_page, None)?;
    }

    if let Some(code_path) = &opts.code {
        let (dsos, records) = load_code_records(code_path, comm_regex.as_ref())?;
        let windowing = windowing_for(records.iter().filter_map(|r| r.sample_time_ns), &opts)?;
        let mut windows: Windows<CodeEntity> = Windows::default();
        let mut lines = Vec::new();
        for record in &records {
            let Some(time_ns) = record.sample_time_ns else {
                continue;
            };
            lines.clear();
            for &(dso, off, len) in &record.exec {
                let first = off / opts.line_bytes;
                let last = (off + len.max(1) - 1) / opts.line_bytes;
                for line in first..=last {
                    lines.push(((dso as u128) << 64) | line as u128);
                }
            }
            lines.sort_unstable();
            lines.dedup();
            let entity = entity_name(
                &opts.group_by,
                &record.comm,
                record.pid,
                record.tid,
                record.hint,
            );
            for key in windowing.keys(time_ns) {
                let agg = windows.entity(key, &entity);
                agg.footprint.samples += 1;
                for &line in &lines {
                    agg.footprint.observe(line);
                    *agg.dso_mass.entry((line >> 64) as u32).or_insert(0) += 1;
                }
            }
        }
        emit_space("code", &windows, &opts, lines_per_page, Some(&dsos))?;
    }

    Ok(())
}

fn windowing_for(
    times: impl Iterator<Item = u64>,
    opts: &ExtractLocalityOpts,
) -> Result<Windowing> {
    let trace_start_ns = times.min().context("no samples with timestamps")?;
    Ok(Windowing {
        trace_start_ns,
        window_ms: opts.window_ms.clone(),
    })
}

fn observe_data(agg: &mut DataEntity, record: &PerfMemRecord, line: LineKey, time_ns: u64) {
    agg.footprint.samples += 1;
    agg.footprint.observe(line);
    match record.mem_op.as_deref() {
        Some("store") => {
            agg.stores += 1;
            agg.store_lines.insert(line);
        }
        Some("load") => agg.loads += 1,
        _ => {}
    }
    if let Some(lvl) = record.mem_lvl.as_deref() {
        *agg.levels.entry(lvl.to_string()).or_insert(0) += 1;
        if beyond_llc(lvl, record.mem_remote.unwrap_or(false)) {
            agg.beyond_llc += 1;
        }
    }
    if let Some(weight) = record.weight.filter(|&w| w > 0) {
        agg.latency_sum += weight;
        agg.latency_samples += 1;
    }
    if let Some(last) = agg.last_seen_ns.insert(line, time_ns) {
        agg.reuse_times_ns.push(time_ns.saturating_sub(last));
    }
}

fn beyond_llc(lvl: &str, remote: bool) -> bool {
    remote || matches!(lvl, "ram" | "pmem" | "cxl" | "io" | "unc")
}

trait SpaceEntity {
    fn footprint(&self) -> &Footprint;
    fn fill(&self, record: &mut EntityRecord, dsos: Option<&HashMap<u32, String>>);
    fn store_lines(&self) -> Option<&HashSet<LineKey>>;
}

impl SpaceEntity for DataEntity {
    fn footprint(&self) -> &Footprint {
        &self.footprint
    }

    fn fill(&self, record: &mut EntityRecord, _dsos: Option<&HashMap<u32, String>>) {
        let samples = self.footprint.samples.max(1) as f64;
        record.loads = Some(self.loads);
        record.stores = Some(self.stores);
        record.store_share = Some(self.stores as f64 / samples);
        record.levels = Some(self.levels.clone());
        record.beyond_llc_share = Some(self.beyond_llc as f64 / samples);
        record.sampled_reuse_fraction = Some(self.reuse_times_ns.len() as f64 / samples);
        let mut reuse = self.reuse_times_ns.clone();
        reuse.sort_unstable();
        record.sampled_reuse_p50_ns = percentile(&reuse, 0.5);
        record.sampled_reuse_p90_ns = percentile(&reuse, 0.9);
        if self.latency_samples > 0 {
            record.latency_mean_cycles =
                Some(self.latency_sum as f64 / self.latency_samples as f64);
        }
    }

    fn store_lines(&self) -> Option<&HashSet<LineKey>> {
        Some(&self.store_lines)
    }
}

impl SpaceEntity for CodeEntity {
    fn footprint(&self) -> &Footprint {
        &self.footprint
    }

    fn fill(&self, record: &mut EntityRecord, dsos: Option<&HashMap<u32, String>>) {
        let total: u64 = self.dso_mass.values().sum();
        let mut shares: Vec<(u32, u64)> = self.dso_mass.iter().map(|(&d, &m)| (d, m)).collect();
        shares.sort_by(|a, b| b.1.cmp(&a.1));
        record.top_dsos = Some(
            shares
                .into_iter()
                .take(3)
                .map(|(dso, mass)| DsoShare {
                    path: dsos
                        .and_then(|d| d.get(&dso).cloned())
                        .unwrap_or_else(|| format!("dso:{dso}")),
                    share: mass as f64 / total.max(1) as f64,
                })
                .collect(),
        );
    }

    fn store_lines(&self) -> Option<&HashSet<LineKey>> {
        None
    }
}

fn percentile(sorted: &[u64], q: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() as f64 * q).ceil() as usize).clamp(1, sorted.len()) - 1;
    Some(sorted[idx])
}

fn emit_space<E: SpaceEntity>(
    space: &'static str,
    windows: &Windows<E>,
    opts: &ExtractLocalityOpts,
    lines_per_page: u64,
    dsos: Option<&HashMap<u32, String>>,
) -> Result<()> {
    for (&(window_ms, window_start_ns), entities) in &windows.by_window {
        let window_end_ns = if window_ms == 0 {
            u64::MAX
        } else {
            window_start_ns + window_ms * 1_000_000
        };
        let mut qualifying: Vec<(&String, &E)> = entities
            .iter()
            .filter(|(_, e)| e.footprint().samples >= opts.min_samples)
            .collect();
        qualifying.sort_by(|a, b| b.1.footprint().samples.cmp(&a.1.footprint().samples));

        let mut union_lines: HashSet<LineKey> = HashSet::new();
        let mut samples = 0u64;
        for (name, entity) in &qualifying {
            let footprint = entity.footprint();
            samples += footprint.samples;
            union_lines.extend(footprint.lines.keys().copied());
            if !opts.summary_only {
                let mut record = EntityRecord {
                    kind: "entity",
                    space,
                    window_ms,
                    window_start_ns,
                    window_end_ns,
                    entity: (*name).clone(),
                    footprint: footprint.stats(opts.line_bytes, lines_per_page),
                    loads: None,
                    stores: None,
                    store_share: None,
                    levels: None,
                    beyond_llc_share: None,
                    sampled_reuse_fraction: None,
                    sampled_reuse_p50_ns: None,
                    sampled_reuse_p90_ns: None,
                    latency_mean_cycles: None,
                    top_dsos: None,
                };
                entity.fill(&mut record, dsos);
                println!("{}", serde_json::to_string(&record)?);
            }
        }
        let union_pages: HashSet<LineKey> = union_lines
            .iter()
            .map(|&l| l / lines_per_page as u128)
            .collect();

        let pair_entities = &qualifying[..qualifying.len().min(opts.max_pair_entities)];
        let mut pairs = 0usize;
        let mut cosine_sum = 0.0;
        let mut cosine_max: f64 = 0.0;
        for i in 0..pair_entities.len() {
            for j in i + 1..pair_entities.len() {
                let (name_a, a) = pair_entities[i];
                let (name_b, b) = pair_entities[j];
                let pair = pair_metrics(
                    space,
                    (window_ms, window_start_ns, window_end_ns),
                    (name_a, a),
                    (name_b, b),
                    lines_per_page,
                );
                pairs += 1;
                cosine_sum += pair.cosine;
                cosine_max = cosine_max.max(pair.cosine);
                if !opts.summary_only {
                    println!("{}", serde_json::to_string(&pair)?);
                }
            }
        }

        let summary = SummaryRecord {
            kind: "summary",
            space,
            window_ms,
            window_start_ns,
            window_end_ns,
            entities: qualifying.len(),
            pairs,
            samples,
            union_lines: union_lines.len() as u64,
            union_pages: union_pages.len() as u64,
            mean_cosine: if pairs > 0 {
                cosine_sum / pairs as f64
            } else {
                0.0
            },
            max_cosine: cosine_max,
        };
        println!("{}", serde_json::to_string(&summary)?);
    }
    Ok(())
}

fn pair_metrics<E: SpaceEntity>(
    space: &'static str,
    (window_ms, window_start_ns, window_end_ns): (u64, u64, u64),
    (name_a, a): (&str, &E),
    (name_b, b): (&str, &E),
    lines_per_page: u64,
) -> PairRecord {
    let fa = a.footprint();
    let fb = b.footprint();
    let (small, large) = if fa.lines.len() <= fb.lines.len() {
        (fa, fb)
    } else {
        (fb, fa)
    };

    let mut shared_lines = 0u64;
    let mut dot = 0.0;
    let mut mass_a_shared = 0.0;
    let mut mass_b_shared = 0.0;
    for (line, &count_small) in &small.lines {
        if let Some(&count_large) = large.lines.get(line) {
            shared_lines += 1;
            dot += count_small as f64 * count_large as f64;
            let (ca, cb) = if std::ptr::eq(small, fa) {
                (count_small, count_large)
            } else {
                (count_large, count_small)
            };
            mass_a_shared += ca as f64;
            mass_b_shared += cb as f64;
        }
    }
    let norm = |f: &Footprint| {
        f.lines
            .values()
            .map(|&c| (c as f64).powi(2))
            .sum::<f64>()
            .sqrt()
    };
    let cosine = if shared_lines == 0 {
        0.0
    } else {
        dot / (norm(fa) * norm(fb))
    };
    let union_lines = fa.lines.len() as u64 + fb.lines.len() as u64 - shared_lines;

    let pages_a: HashSet<LineKey> = fa
        .lines
        .keys()
        .map(|&l| l / lines_per_page as u128)
        .collect();
    let pages_b: HashSet<LineKey> = fb
        .lines
        .keys()
        .map(|&l| l / lines_per_page as u128)
        .collect();
    let shared_pages = pages_a.intersection(&pages_b).count() as u64;
    let union_pages = pages_a.len() as u64 + pages_b.len() as u64 - shared_pages;

    let (write_shared_lines, write_shared_share) = match (a.store_lines(), b.store_lines()) {
        (Some(stores_a), Some(stores_b)) => {
            let written_by_a: u64 =
                stores_a.iter().filter(|l| fb.lines.contains_key(l)).count() as u64;
            let written_by_b: u64 =
                stores_b.iter().filter(|l| fa.lines.contains_key(l)).count() as u64;
            let shared: HashSet<&LineKey> = stores_a
                .iter()
                .filter(|l| fb.lines.contains_key(l))
                .chain(stores_b.iter().filter(|l| fa.lines.contains_key(l)))
                .collect();
            let mass: f64 = shared
                .iter()
                .map(|l| {
                    (fa.lines.get(l).copied().unwrap_or(0) + fb.lines.get(l).copied().unwrap_or(0))
                        as f64
                })
                .sum();
            (
                Some(written_by_a + written_by_b),
                Some(mass / (fa.mass() + fb.mass()).max(1.0)),
            )
        }
        _ => (None, None),
    };

    PairRecord {
        kind: "pair",
        space,
        window_ms,
        window_start_ns,
        window_end_ns,
        a: name_a.to_string(),
        b: name_b.to_string(),
        samples_a: fa.samples,
        samples_b: fb.samples,
        shared_lines,
        line_jaccard: if union_lines == 0 {
            0.0
        } else {
            shared_lines as f64 / union_lines as f64
        },
        containment_ab: mass_a_shared / fa.mass().max(1.0),
        containment_ba: mass_b_shared / fb.mass().max(1.0),
        cosine,
        shared_pages,
        page_jaccard: if union_pages == 0 {
            0.0
        } else {
            shared_pages as f64 / union_pages as f64
        },
        write_shared_lines,
        write_shared_share,
    }
}

fn entity_name(group_by: &LocalityGroupBy, comm: &str, pid: u32, tid: u32, hint: u64) -> String {
    match group_by {
        LocalityGroupBy::Tid => format!("tid:{tid}:{comm}"),
        LocalityGroupBy::Pid => format!("pid:{pid}:{comm}"),
        LocalityGroupBy::Comm => comm.to_string(),
        LocalityGroupBy::CommHint => format!("{comm}@hint={hint}"),
    }
}

fn parse_hex(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value == "0" || value == "N/A" {
        return None;
    }
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
}

fn load_mem_records(path: &PathBuf, comm_regex: Option<&Regex>) -> Result<Vec<PerfMemRecord>> {
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    );
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line.context("failed to read mem record")?;
        if line.trim().is_empty() {
            continue;
        }
        let record: PerfMemRecord =
            serde_json::from_str(&line).context("failed to parse mem record")?;
        if comm_regex.is_some_and(|re| !re.is_match(&record.comm)) {
            continue;
        }
        records.push(record);
    }
    Ok(records)
}

fn load_code_records(
    path: &PathBuf,
    comm_regex: Option<&Regex>,
) -> Result<(HashMap<u32, String>, Vec<CodeSampleRecord>)> {
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    );
    let mut dsos = HashMap::new();
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line.context("failed to read code record")?;
        if line.trim().is_empty() {
            continue;
        }
        if line.contains("\"kind\":\"dso\"") {
            let dso: CodeDsoRecord =
                serde_json::from_str(&line).context("failed to parse dso record")?;
            dsos.insert(dso.id, dso.path);
            continue;
        }
        let record: CodeSampleRecord =
            serde_json::from_str(&line).context("failed to parse code record")?;
        if comm_regex.is_some_and(|re| !re.is_match(&record.comm)) {
            continue;
        }
        records.push(record);
    }
    Ok((dsos, records))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footprint_estimates_and_pair_overlap_follow_sample_mass() {
        // a touches lines 0..8 once each and line 8 four times; b touches
        // lines 4..12 once each. Chao1 adds f1^2 / 2 f2 unseen lines.
        let mut a = CodeEntity::default();
        let mut b = CodeEntity::default();
        for line in 0..8u128 {
            a.footprint.observe(line);
        }
        for _ in 0..4 {
            a.footprint.observe(8);
        }
        a.footprint.observe(9);
        a.footprint.observe(9);
        for line in 4..12u128 {
            b.footprint.observe(line);
        }
        a.footprint.samples = 14;
        b.footprint.samples = 8;

        let stats = a.footprint.stats(64, 64);
        assert_eq!(stats.lines_observed, 10);
        assert!((stats.lines_chao1 - (10.0 + 64.0 / 2.0)).abs() < 1e-9);
        assert!((stats.line_coverage - (1.0 - 8.0 / 14.0)).abs() < 1e-9);

        let pair = pair_metrics("code", (0, 0, u64::MAX), ("a", &a), ("b", &b), 64);
        assert_eq!(pair.shared_lines, 6);
        // a's mass on shared lines 4..=9: 1+1+1+1+4+2 = 10 of 14.
        assert!((pair.containment_ab - 10.0 / 14.0).abs() < 1e-9);
        assert!((pair.containment_ba - 6.0 / 8.0).abs() < 1e-9);
        assert!((pair.line_jaccard - 6.0 / 12.0).abs() < 1e-9);
        assert!(pair.cosine > 0.0 && pair.cosine < 1.0);
        assert_eq!(pair.write_shared_lines, None);
    }
}
