// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::locality::{ExtractLocalityOpts, cmd_extract_locality};
use crate::process::PerfMemRecord;
use crate::sched_util::cmd_extract_sched_util;
use anyhow::{Context as _, Result, bail};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

const DEFAULT_WORKLOAD_CGROUP_REGEX: &str = "workload.slice";
const DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX: &str = r"workload-tw-[^/]+\.allotment\.slice";
const CONFIG_CLUSTER_SAMPLE_THRESHOLD_PCT: f64 = 5.0;
const CONFIG_CLUSTER_PAGE_JACCARD_THRESHOLD: f64 = 0.20;
const CONFIG_CLUSTER_PAGE_CONTAINMENT_THRESHOLD: f64 = 0.50;

#[derive(Debug, Parser)]
pub struct ExtractMemOpts {
    /// Path to mem/perf.mem.jsonl file
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Memory extraction mode
    #[clap(short = 'm', long, value_enum, default_value = "config")]
    pub mode: ExtractMemMode,

    /// Regex pattern for workload cgroup
    #[clap(long, default_value = DEFAULT_WORKLOAD_CGROUP_REGEX)]
    pub workload_cgroup_regex: String,

    /// Regex pattern for workload allotment cgroups
    #[clap(long, default_value = DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX)]
    pub workload_allotment_cgroup_regex: String,

    /// Split significant comm subcells further by hint values
    #[clap(long)]
    pub use_hints: bool,

    /// Verbosity level (-v for summary, -vv for detailed output)
    #[clap(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Window sizes in milliseconds for dispersion mode
    #[clap(long, value_delimiter = ',', default_value = "100,1000,5000")]
    pub window_ms: Vec<u64>,

    /// Entity grouping for dispersion mode
    #[clap(long, value_enum, default_value = "tid")]
    pub group_by: DispersionGroupBy,

    /// Address identity for memory overlap metrics
    #[clap(long, value_enum, default_value = "phys")]
    pub address_space: DispersionAddressSpace,

    /// Regex filter for sampled command names in dispersion mode
    #[clap(long)]
    pub comm_regex: Option<String>,

    /// Minimum samples a measured entity must have for overlap metrics
    #[clap(long, default_value = "2")]
    pub min_samples_per_entity: usize,

    /// Cacheline size in bytes for dispersion mode
    #[clap(long, default_value = "64")]
    pub cacheline_bytes: u64,

    /// Page size in bytes for memory overlap metrics
    #[clap(long, default_value = "4096")]
    pub page_bytes: u64,

    /// Huge page size in bytes for dispersion mode
    #[clap(long, default_value = "2097152")]
    pub hugepage_bytes: u64,

    /// Distance scale in bytes for same-page exponential overlap decay
    #[clap(long, default_value = "256")]
    pub page_decay_bytes: f64,

    /// Distance scale in bytes for same-hugepage exponential overlap decay
    #[clap(long, default_value = "65536")]
    pub hugepage_decay_bytes: f64,

    /// Maximum contribution for same-hugepage overlap when page overlap is absent
    #[clap(long, default_value = "0.05")]
    pub hugepage_weight: f64,

    /// Emit per-pair dispersion records in addition to window summaries
    #[clap(long)]
    pub emit_pairs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExtractMemMode {
    /// Generate scx_layered cell config from memory samples
    Config,
    /// Compute sampled working-set overlap and dispersion metrics
    Dispersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DispersionGroupBy {
    /// Group samples by thread id
    Tid,
    /// Group samples by process id
    Pid,
    /// Group samples by command name
    Comm,
    /// Group samples by command name and hint value
    CommHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DispersionAddressSpace {
    /// Use sampled physical addresses for LLC working-set identity
    Phys,
    /// Use sampled virtual addresses for single-process synthetic validation
    Virt,
}

#[derive(Debug, Parser)]
pub struct ExtractOpts {
    #[clap(subcommand)]
    pub command: ExtractCommand,
}

#[derive(Debug, Subcommand)]
pub enum ExtractCommand {
    /// Extract memory-derived summaries from mem/perf.mem.jsonl
    Mem(ExtractMemOpts),
    /// Extract derived metrics from sched/perf.sched.jsonl
    Sched(ExtractSchedOpts),
    /// Extract data and code footprints and sharing per thread class
    Locality(ExtractLocalityOpts),
}

#[derive(Debug, Parser)]
pub struct ExtractSchedOpts {
    #[clap(subcommand)]
    pub command: ExtractSchedCommand,
}

#[derive(Debug, Subcommand)]
pub enum ExtractSchedCommand {
    /// Compute time-weighted CPU busy utilization from sched/perf.sched.jsonl
    Util(ExtractSchedUtilOpts),
}

#[derive(Debug, Parser)]
pub struct ExtractSchedUtilOpts {
    /// Path to sched/perf.sched.jsonl file
    #[clap(short = 'f', long)]
    pub file: PathBuf,

    /// Aggregation window size in milliseconds
    #[clap(long, default_value = "1")]
    pub window_ms: u64,

    /// Comma-separated mutually exclusive categories, e.g. "worker-a@hint=0,worker-a@hint=640,svc-*,perf"
    #[clap(long, default_value = "")]
    pub categories: String,

    /// Print extra summary information to stderr
    #[clap(short, long)]
    pub verbose: bool,
}

fn classify_cgroup<'a>(cgroup: &'a str, workload_cgroup: &'a str, allotment_re: &Regex) -> &'a str {
    if !cgroup.contains(workload_cgroup) {
        return "rest";
    }

    if let Some(m) = allotment_re.find(cgroup) {
        return m.as_str();
    }

    workload_cgroup
}

/// Samples belonging to a group, in time order
struct GroupData {
    samples: Vec<PerfMemRecord>,
}

impl GroupData {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn push(&mut self, sample: PerfMemRecord) {
        self.samples.push(sample);
    }

    fn samples(&self) -> &[PerfMemRecord] {
        &self.samples
    }

    fn print(&self, group_name: &str, global_total: u64, verbosity: u8, use_hints: bool) {
        let group_pct = (self.samples.len() as f64 / global_total as f64) * 100.0;
        eprintln!(
            "\n{}: {} samples ({:.2}%)",
            group_name,
            self.samples.len(),
            group_pct
        );

        let sample_refs: Vec<_> = self.samples.iter().collect();
        let counts = summarize_comm_groups(&sample_refs);
        let mut printed_aggregated_marker_note = false;

        let mut skipped = 0;
        for entry in counts {
            let pct = (entry.count as f64 / self.samples.len() as f64) * 100.0;
            if verbosity >= 2 || pct > 1.0 {
                let display_name = if entry.aggregated_numeric_suffixes {
                    printed_aggregated_marker_note = true;
                    format!("{}*", entry.name)
                } else {
                    entry.name.clone()
                };
                eprintln!("  {}: {} ({:.2}%)", display_name, entry.count, pct);
                if use_hints && entry.hint_counts.len() > 1 {
                    let mut skipped_hints = 0;
                    for (hint, count) in entry.hint_counts {
                        let hint_pct = (count as f64 / entry.count as f64) * 100.0;
                        if verbosity >= 2 || hint_pct > 1.0 {
                            eprintln!("    hint={}: {} ({:.2}%)", hint, count, hint_pct);
                        } else {
                            skipped_hints += 1;
                        }
                    }
                    if skipped_hints > 0 {
                        eprintln!("    ... {} more hints below 1%", skipped_hints);
                    }
                }
                if verbosity >= 2 && entry.concrete_counts.len() > 1 {
                    for (comm, count) in entry.concrete_counts {
                        let comm_pct = (count as f64 / entry.count as f64) * 100.0;
                        eprintln!("    {}: {} ({:.2}%)", comm, count, comm_pct);
                    }
                }
            } else {
                skipped += 1;
            }
        }
        if skipped > 0 {
            eprintln!("  ... {} more below 1%", skipped);
        }
        if printed_aggregated_marker_note {
            eprintln!("  * trailing numeric suffixes merged");
        }
    }
}

/// Result of clustering analysis for a group
struct ClusterResult {
    /// Stable selector clusters that can be emitted in the config.
    clusters: Vec<ConfigCluster>,
    diagnostics: ConfigClusterDiagnostics,
}

#[derive(Debug, Clone)]
struct ConfigCluster {
    emit_keys: Vec<EmitKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EmitKey {
    comm: String,
    hint: Option<u64>,
}

impl EmitKey {
    fn comm(comm: String) -> Self {
        Self { comm, hint: None }
    }

    fn comm_hint(comm: String, hint: u64) -> Self {
        Self {
            comm,
            hint: Some(hint),
        }
    }

    fn display_name(&self) -> String {
        match self.hint {
            Some(hint) => format!("{}@hint={hint}", self.comm),
            None => self.comm.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommSummary {
    name: String,
    count: u64,
    aggregated_numeric_suffixes: bool,
    hint_counts: Vec<(u64, u64)>,
    concrete_counts: Vec<(String, u64)>,
}

#[derive(Debug, Default)]
struct GroupedCommSamples<'a> {
    samples: Vec<&'a PerfMemRecord>,
    hint_counts: HashMap<u64, u64>,
    concrete_counts: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct ConfigMeasurementNode {
    emit_key: EmitKey,
    tid: u32,
    sample_count: usize,
    pages: BTreeSet<u64>,
}

impl ConfigMeasurementNode {
    fn new(emit_key: EmitKey, tid: u32) -> Self {
        Self {
            emit_key,
            tid,
            sample_count: 0,
            pages: BTreeSet::new(),
        }
    }

    fn observe(&mut self, addr: u64, opts: &ExtractMemOpts) {
        self.sample_count += 1;
        self.pages.insert(addr / opts.page_bytes);
    }
}

#[derive(Debug, Clone, Default)]
struct ConfigClusterDiagnostics {
    total_samples: usize,
    threshold_pct: f64,
    threshold_count: usize,
    emit_keys: Vec<ConfigEmitKeySummary>,
    measurement_nodes: Vec<ConfigMeasurementSummary>,
    overlap_edges: Vec<ConfigOverlapEdge>,
    stable_selector_components: Vec<StableSelectorComponentSummary>,
}

#[derive(Debug, Clone)]
struct ConfigEmitKeySummary {
    emit_key: EmitKey,
    sample_count: usize,
}

#[derive(Debug, Clone)]
struct ConfigMeasurementSummary {
    emit_key: EmitKey,
    tid: u32,
    sample_count: usize,
    page_count: usize,
}

#[derive(Debug, Clone)]
struct ConfigOverlapEdge {
    emit_key_a: EmitKey,
    tid_a: u32,
    emit_key_b: EmitKey,
    tid_b: u32,
    intersection_pages: usize,
    union_pages: usize,
    jaccard: f64,
    containment: f64,
}

#[derive(Debug, Clone)]
struct StableSelectorComponentSummary {
    emit_key: EmitKey,
    component_count: usize,
}

#[derive(Debug, Clone)]
struct ConfigClusterBuildResult {
    clusters: Vec<ConfigCluster>,
    overlap_edges: Vec<ConfigOverlapEdge>,
    stable_selector_components: Vec<StableSelectorComponentSummary>,
}

#[derive(Debug, Clone)]
struct DisjointSet {
    parent: Vec<usize>,
}

impl DisjointSet {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
        }
    }

    fn find(&mut self, idx: usize) -> usize {
        let parent = self.parent[idx];
        if parent != idx {
            let root = self.find(parent);
            self.parent[idx] = root;
        }
        self.parent[idx]
    }

    fn union(&mut self, a: usize, b: usize) {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a != root_b {
            self.parent[root_b] = root_a;
        }
    }
}

/// Group type for clustering decisions
#[derive(Debug, Clone, Copy, PartialEq)]
enum GroupType {
    Allotment,
    Workload,
    Rest,
}

/// Compute clustering for samples. Returns empty result for group types
/// where clustering is not yet implemented.
fn compute_clusters(
    group_type: GroupType,
    samples: &[&PerfMemRecord],
    opts: &ExtractMemOpts,
) -> ClusterResult {
    let threshold_pct = CONFIG_CLUSTER_SAMPLE_THRESHOLD_PCT;
    let threshold_count = ((samples.len() as f64) * threshold_pct / 100.0).ceil() as usize;
    let mut diagnostics = ConfigClusterDiagnostics {
        total_samples: samples.len(),
        threshold_pct,
        threshold_count,
        ..Default::default()
    };

    // TODO(kkd): Enable clustering for Workload and Rest
    if group_type != GroupType::Allotment {
        return ClusterResult {
            clusters: Vec::new(),
            diagnostics,
        };
    }

    let emit_groups = significant_emit_groups(samples, threshold_pct, opts.use_hints);
    diagnostics.emit_keys = emit_groups
        .iter()
        .map(|(emit_key, samples)| ConfigEmitKeySummary {
            emit_key: emit_key.clone(),
            sample_count: samples.len(),
        })
        .collect();

    if emit_groups.is_empty() {
        return ClusterResult {
            clusters: Vec::new(),
            diagnostics,
        };
    }

    let emit_keys: Vec<_> = emit_groups.keys().cloned().collect();
    let measurement_nodes = build_config_measurement_nodes(samples, &emit_groups, opts);
    diagnostics.measurement_nodes = measurement_nodes
        .iter()
        .map(|node| ConfigMeasurementSummary {
            emit_key: node.emit_key.clone(),
            tid: node.tid,
            sample_count: node.sample_count,
            page_count: node.pages.len(),
        })
        .collect();

    let cluster_result = cluster_emit_keys_by_overlap(&emit_keys, &measurement_nodes);
    diagnostics.overlap_edges = cluster_result.overlap_edges;
    diagnostics.stable_selector_components = cluster_result.stable_selector_components;

    ClusterResult {
        clusters: cluster_result.clusters,
        diagnostics,
    }
}

fn group_samples_by_normalized_comm<'a>(
    samples: &[&'a PerfMemRecord],
) -> HashMap<String, GroupedCommSamples<'a>> {
    let mut grouped = HashMap::new();
    for sample in samples {
        let cluster_name = normalize_comm_for_cluster(&sample.comm);
        let entry = grouped
            .entry(cluster_name)
            .or_insert_with(GroupedCommSamples::default);
        entry.samples.push(*sample);
        *entry.hint_counts.entry(sample.hint).or_insert(0) += 1;
        *entry
            .concrete_counts
            .entry(sample.comm.clone())
            .or_insert(0) += 1;
    }
    grouped
}

fn normalize_comm_for_cluster(comm: &str) -> String {
    let normalized = comm.trim_end_matches(|ch: char| ch.is_ascii_digit());
    if normalized.is_empty() {
        comm.to_string()
    } else {
        normalized.to_string()
    }
}

fn significant_emit_groups<'a>(
    samples: &[&'a PerfMemRecord],
    threshold_pct: f64,
    use_hints: bool,
) -> BTreeMap<EmitKey, Vec<&'a PerfMemRecord>> {
    let total = samples.len();
    if total == 0 {
        return BTreeMap::new();
    }

    let threshold_count = ((total as f64) * threshold_pct / 100.0).ceil() as usize;
    let grouped_samples = group_samples_by_normalized_comm(samples);
    let mut emit_groups = BTreeMap::new();

    for (comm, group) in grouped_samples {
        if group.samples.len() < threshold_count {
            continue;
        }

        if use_hints && group.hint_counts.len() > 1 {
            let mut hint_samples: BTreeMap<u64, Vec<&PerfMemRecord>> = BTreeMap::new();
            for sample in group.samples {
                hint_samples.entry(sample.hint).or_default().push(sample);
            }

            for (hint, samples) in hint_samples {
                if samples.len() >= threshold_count {
                    emit_groups.insert(EmitKey::comm_hint(comm.clone(), hint), samples);
                }
            }
        } else {
            emit_groups.insert(EmitKey::comm(comm), group.samples);
        }
    }

    emit_groups
}

fn build_config_measurement_nodes(
    samples: &[&PerfMemRecord],
    emit_groups: &BTreeMap<EmitKey, Vec<&PerfMemRecord>>,
    opts: &ExtractMemOpts,
) -> Vec<ConfigMeasurementNode> {
    let emit_keys: BTreeSet<_> = emit_groups.keys().cloned().collect();
    let mut nodes: BTreeMap<(EmitKey, u32), ConfigMeasurementNode> = BTreeMap::new();

    for sample in samples {
        let Some(emit_key) = config_emit_key_for_sample(sample, &emit_keys, opts.use_hints) else {
            continue;
        };
        let Some(addr) = dispersion_addr(sample, opts.address_space) else {
            continue;
        };
        if addr == 0 {
            continue;
        }

        nodes
            .entry((emit_key.clone(), sample.tid))
            .or_insert_with(|| ConfigMeasurementNode::new(emit_key, sample.tid))
            .observe(addr, opts);
    }

    nodes
        .into_values()
        .filter(|node| node.sample_count >= opts.min_samples_per_entity && !node.pages.is_empty())
        .collect()
}

fn config_emit_key_for_sample(
    sample: &PerfMemRecord,
    emit_keys: &BTreeSet<EmitKey>,
    use_hints: bool,
) -> Option<EmitKey> {
    let comm = normalize_comm_for_cluster(&sample.comm);
    if use_hints {
        let hinted_key = EmitKey::comm_hint(comm.clone(), sample.hint);
        if emit_keys.contains(&hinted_key) {
            return Some(hinted_key);
        }
    }

    let comm_key = EmitKey::comm(comm);
    emit_keys.contains(&comm_key).then_some(comm_key)
}

fn cluster_emit_keys_by_overlap(
    emit_keys: &[EmitKey],
    measurement_nodes: &[ConfigMeasurementNode],
) -> ConfigClusterBuildResult {
    let mut key_index = BTreeMap::new();
    for (idx, key) in emit_keys.iter().enumerate() {
        key_index.insert(key.clone(), idx);
    }

    let mut measured_dsu = DisjointSet::new(measurement_nodes.len());
    let mut overlap_edges = Vec::new();
    for i in 0..measurement_nodes.len() {
        for j in i + 1..measurement_nodes.len() {
            if let Some(edge) = config_overlap_edge(&measurement_nodes[i], &measurement_nodes[j]) {
                measured_dsu.union(i, j);
                overlap_edges.push(edge);
            }
        }
    }

    let mut key_dsu = DisjointSet::new(emit_keys.len());
    let mut measured_components: BTreeMap<usize, BTreeSet<EmitKey>> = BTreeMap::new();
    let mut emit_key_components: BTreeMap<EmitKey, BTreeSet<usize>> = BTreeMap::new();
    for (idx, node) in measurement_nodes.iter().enumerate() {
        let root = measured_dsu.find(idx);
        measured_components
            .entry(root)
            .or_default()
            .insert(node.emit_key.clone());
        emit_key_components
            .entry(node.emit_key.clone())
            .or_default()
            .insert(root);
    }

    let stable_selector_components = emit_key_components
        .into_iter()
        .filter_map(|(emit_key, components)| {
            (components.len() > 1).then_some(StableSelectorComponentSummary {
                emit_key,
                component_count: components.len(),
            })
        })
        .collect();

    for keys in measured_components.values() {
        let mut iter = keys.iter();
        let Some(first) = iter.next() else {
            continue;
        };
        let first_idx = key_index[first];
        for key in iter {
            key_dsu.union(first_idx, key_index[key]);
        }
    }

    let mut clustered_keys: BTreeMap<usize, BTreeSet<EmitKey>> = BTreeMap::new();
    for (idx, key) in emit_keys.iter().enumerate() {
        let root = key_dsu.find(idx);
        clustered_keys.entry(root).or_default().insert(key.clone());
    }

    let clusters = clustered_keys
        .into_values()
        .map(|keys| ConfigCluster {
            emit_keys: keys.into_iter().collect(),
        })
        .collect();

    ConfigClusterBuildResult {
        clusters,
        overlap_edges,
        stable_selector_components,
    }
}

fn config_overlap_edge(
    a: &ConfigMeasurementNode,
    b: &ConfigMeasurementNode,
) -> Option<ConfigOverlapEdge> {
    if a.pages.is_empty() || b.pages.is_empty() {
        return None;
    }

    let intersection = a.pages.intersection(&b.pages).count();
    if intersection == 0 {
        return None;
    }

    let union = a.pages.len() + b.pages.len() - intersection;
    let jaccard = intersection as f64 / union as f64;
    let containment = intersection as f64 / a.pages.len().min(b.pages.len()) as f64;

    (jaccard >= CONFIG_CLUSTER_PAGE_JACCARD_THRESHOLD
        || containment >= CONFIG_CLUSTER_PAGE_CONTAINMENT_THRESHOLD)
        .then_some(ConfigOverlapEdge {
            emit_key_a: a.emit_key.clone(),
            tid_a: a.tid,
            emit_key_b: b.emit_key.clone(),
            tid_b: b.tid,
            intersection_pages: intersection,
            union_pages: union,
            jaccard,
            containment,
        })
}

fn summarize_comm_groups(samples: &[&PerfMemRecord]) -> Vec<CommSummary> {
    let mut summary: Vec<_> = group_samples_by_normalized_comm(samples)
        .into_iter()
        .map(|(name, group)| {
            let mut hint_counts: Vec<_> = group.hint_counts.into_iter().collect();
            hint_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let mut concrete_counts: Vec<_> = group.concrete_counts.into_iter().collect();
            concrete_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            CommSummary {
                name,
                count: group.samples.len() as u64,
                aggregated_numeric_suffixes: concrete_counts.len() > 1,
                hint_counts,
                concrete_counts,
            }
        })
        .collect();

    summary.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    summary
}

/// Build subcells from clustering result. Returns empty if no significant comms.
fn build_subcells_from_clusters(result: &ClusterResult) -> Vec<CellSpec> {
    if result.clusters.is_empty() {
        return Vec::new();
    }

    let mut subcells = Vec::new();

    for cluster in &result.clusters {
        subcells.push(CellSpec {
            name: config_cluster_name(cluster),
            matches: CellMatches::complex(build_emit_key_match_clauses(&cluster.emit_keys)),
            subcells: Vec::new(),
        });
    }

    subcells.push(CellSpec {
        name: "rest".to_string(),
        matches: CellMatches::complex(vec![vec![]]),
        subcells: Vec::new(),
    });

    subcells
}

fn config_cluster_name(cluster: &ConfigCluster) -> String {
    cluster
        .emit_keys
        .iter()
        .map(EmitKey::display_name)
        .collect::<Vec<_>>()
        .join("+")
}

fn build_emit_key_match_clauses(emit_keys: &[EmitKey]) -> Vec<Vec<CellMatch>> {
    emit_keys
        .iter()
        .map(|emit_key| {
            let mut clause = vec![CellMatch::CommPrefix(emit_key.comm.clone())];
            if let Some(hint) = emit_key.hint {
                clause.push(CellMatch::Hint(hint));
            }
            clause
        })
        .collect()
}

fn print_config_cluster_diagnostics(group_name: &str, result: &ClusterResult, verbosity: u8) {
    let diagnostics = &result.diagnostics;

    eprintln!(
        "\n{} overlap clusters: {} emitted clusters from {} significant selectors",
        group_name,
        result.clusters.len(),
        diagnostics.emit_keys.len()
    );
    eprintln!(
        "  significance threshold: {:.1}% (>= {} of {} samples)",
        diagnostics.threshold_pct, diagnostics.threshold_count, diagnostics.total_samples
    );

    if diagnostics.emit_keys.is_empty() {
        eprintln!("  no selectors exceeded the significance threshold");
        return;
    }

    eprintln!("  significant selectors:");
    for summary in &diagnostics.emit_keys {
        let pct = (summary.sample_count as f64 / diagnostics.total_samples.max(1) as f64) * 100.0;
        eprintln!(
            "    {}: {} samples ({:.2}%)",
            summary.emit_key.display_name(),
            summary.sample_count,
            pct
        );
    }

    eprintln!("  emitted clusters:");
    for cluster in &result.clusters {
        eprintln!(
            "    {}: {}",
            config_cluster_name(cluster),
            emit_key_names(&cluster.emit_keys).join(", ")
        );
    }

    if !diagnostics.stable_selector_components.is_empty() {
        eprintln!("  merged non-emittable measured clusters:");
        for summary in &diagnostics.stable_selector_components {
            eprintln!(
                "    {} appeared in {} measured components; merged for stable config matching",
                summary.emit_key.display_name(),
                summary.component_count
            );
        }
    }

    if verbosity < 2 {
        return;
    }

    eprintln!("  measured entities:");
    for node in &diagnostics.measurement_nodes {
        eprintln!(
            "    {} tid={}: {} samples, {} pages",
            node.emit_key.display_name(),
            node.tid,
            node.sample_count,
            node.page_count
        );
    }

    eprintln!("  overlap edges:");
    if diagnostics.overlap_edges.is_empty() {
        eprintln!("    none");
    } else {
        for edge in &diagnostics.overlap_edges {
            eprintln!(
                "    {} tid={} <-> {} tid={}: intersection={} pages union={} pages jaccard={:.3} containment={:.3}",
                edge.emit_key_a.display_name(),
                edge.tid_a,
                edge.emit_key_b.display_name(),
                edge.tid_b,
                edge.intersection_pages,
                edge.union_pages,
                edge.jaccard,
                edge.containment
            );
        }
    }
}

fn emit_key_names(emit_keys: &[EmitKey]) -> Vec<String> {
    emit_keys.iter().map(EmitKey::display_name).collect()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum CellMatch {
    CommPrefix(String),
    Hint(u64),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum CellMatches {
    Simple(SimpleCellMatches),
    Complex(Vec<Vec<CellMatch>>),
}

impl CellMatches {
    fn simple(matches: SimpleCellMatches) -> Self {
        Self::Simple(matches)
    }

    fn complex(matches: Vec<Vec<CellMatch>>) -> Self {
        Self::Complex(matches)
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct SimpleCellMatches {
    #[serde(rename = "CgroupRegex", skip_serializing_if = "Option::is_none")]
    cgroup_regex: Option<String>,
    #[serde(rename = "CgroupContains", skip_serializing_if = "Option::is_none")]
    cgroup_contains: Option<String>,
}

impl SimpleCellMatches {
    fn cgroup_regex(value: String) -> Self {
        Self {
            cgroup_regex: Some(value),
            cgroup_contains: None,
        }
    }

    fn cgroup_contains(value: String) -> Self {
        Self {
            cgroup_regex: None,
            cgroup_contains: Some(value),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CellSpec {
    name: String,
    matches: CellMatches,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subcells: Vec<CellSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
struct CellConfig {
    specs: Vec<CellSpec>,
}

pub fn cmd_extract_mem(opts: ExtractMemOpts) -> Result<()> {
    match opts.mode {
        ExtractMemMode::Config => cmd_extract_mem_config(opts),
        ExtractMemMode::Dispersion => cmd_extract_mem_dispersion(opts),
    }
}

fn cmd_extract_mem_config(opts: ExtractMemOpts) -> Result<()> {
    let file = File::open(&opts.file).context("failed to open mem/perf.mem.jsonl")?;
    let reader = BufReader::new(file);

    let allotment_re =
        Regex::new(&opts.workload_allotment_cgroup_regex).context("invalid allotment regex")?;
    let workload_cgroup = &opts.workload_cgroup_regex;

    let mut groups: HashMap<String, GroupData> = HashMap::new();
    let mut global_total: u64 = 0;

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        let record: PerfMemRecord =
            serde_json::from_str(&line).context("failed to parse record")?;

        let group = classify_cgroup(&record.cgroup, workload_cgroup, &allotment_re);
        groups
            .entry(group.to_string())
            .or_insert_with(GroupData::new)
            .push(record);
        global_total += 1;
    }

    let mut group_names: Vec<_> = groups.keys().cloned().collect();
    group_names.sort_by(|a, b| {
        let order = |s: &str| -> u8 {
            if s == "rest" {
                2
            } else if s == workload_cgroup {
                1
            } else {
                0
            }
        };
        order(a).cmp(&order(b)).then_with(|| a.cmp(b))
    });

    if opts.verbose > 0 {
        eprintln!("Total samples: {}", global_total);
    }

    let config = generate_config(
        &groups,
        &group_names,
        workload_cgroup,
        &opts.workload_allotment_cgroup_regex,
        &opts,
    );

    if opts.verbose > 0 {
        for name in &group_names {
            if let Some(data) = groups.get(name) {
                data.print(name, global_total, opts.verbose, opts.use_hints);
            }
        }
    }

    let json = serde_json::to_string_pretty(&config).context("failed to serialize config")?;
    println!("{}", json);

    Ok(())
}

#[derive(Debug, Clone)]
struct DispersionSample {
    entity: String,
    time_ns: u64,
    addr: u64,
}

#[derive(Debug, Default)]
struct DispersionEntitySamples {
    addrs: Vec<u64>,
    lines: BTreeSet<u64>,
    pages: BTreeSet<u64>,
    hugepages: BTreeSet<u64>,
}

impl DispersionEntitySamples {
    fn observe(&mut self, addr: u64, opts: &ExtractMemOpts) {
        self.addrs.push(addr);
        self.lines.insert(addr / opts.cacheline_bytes);
        self.pages.insert(addr / opts.page_bytes);
        self.hugepages.insert(addr / opts.hugepage_bytes);
    }

    fn sample_count(&self) -> usize {
        self.addrs.len()
    }

    fn observed_line_wss_bytes(&self, opts: &ExtractMemOpts) -> u64 {
        self.lines.len() as u64 * opts.cacheline_bytes
    }

    fn observed_page_wss_bytes(&self, opts: &ExtractMemOpts) -> u64 {
        self.pages.len() as u64 * opts.page_bytes
    }
}

#[derive(Debug, Clone, Serialize)]
struct DispersionSummaryRecord {
    kind: &'static str,
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    entity_count: usize,
    pair_count: u64,
    sample_count: usize,
    access_pair_count: u64,
    mean_entity_line_wss_bytes: f64,
    mean_entity_page_wss_bytes: f64,
    union_line_wss_bytes: u64,
    union_page_wss_bytes: u64,
    mean_line_overlap: f64,
    mean_page_proximity: f64,
    mean_hugepage_proximity: f64,
    mean_weighted_overlap: f64,
    mean_dispersion: f64,
    access_weighted_overlap: f64,
    access_weighted_dispersion: f64,
}

#[derive(Debug, Clone, Serialize)]
struct DispersionPairRecord {
    kind: &'static str,
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    entity_a: String,
    entity_b: String,
    samples_a: usize,
    samples_b: usize,
    observed_line_wss_bytes_a: u64,
    observed_line_wss_bytes_b: u64,
    observed_page_wss_bytes_a: u64,
    observed_page_wss_bytes_b: u64,
    access_pair_count: u64,
    line_overlap: f64,
    page_proximity: f64,
    hugepage_proximity: f64,
    weighted_overlap: f64,
    dispersion: f64,
}

#[derive(Debug, Default)]
struct DispersionSummaryAccum {
    pair_count: u64,
    access_pair_count: u64,
    line_sum: f64,
    page_sum: f64,
    hugepage_sum: f64,
    weighted_sum: f64,
    access_weighted_sum: f64,
}

impl DispersionSummaryAccum {
    fn observe(&mut self, pair: &DispersionPairRecord) {
        self.pair_count += 1;
        self.access_pair_count += pair.access_pair_count;
        self.line_sum += pair.line_overlap;
        self.page_sum += pair.page_proximity;
        self.hugepage_sum += pair.hugepage_proximity;
        self.weighted_sum += pair.weighted_overlap;
        self.access_weighted_sum += pair.weighted_overlap * pair.access_pair_count as f64;
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        self,
        window_ms: u64,
        window_start_ns: u64,
        window_end_ns: u64,
        entity_count: usize,
        sample_count: usize,
        mean_entity_line_wss_bytes: f64,
        mean_entity_page_wss_bytes: f64,
        union_line_wss_bytes: u64,
        union_page_wss_bytes: u64,
    ) -> DispersionSummaryRecord {
        let pair_count = self.pair_count.max(1) as f64;
        let access_pair_count = self.access_pair_count.max(1) as f64;
        let mean_weighted_overlap = self.weighted_sum / pair_count;
        let access_weighted_overlap = self.access_weighted_sum / access_pair_count;

        DispersionSummaryRecord {
            kind: "summary",
            window_ms,
            window_start_ns,
            window_end_ns,
            entity_count,
            pair_count: self.pair_count,
            sample_count,
            access_pair_count: self.access_pair_count,
            mean_entity_line_wss_bytes,
            mean_entity_page_wss_bytes,
            union_line_wss_bytes,
            union_page_wss_bytes,
            mean_line_overlap: self.line_sum / pair_count,
            mean_page_proximity: self.page_sum / pair_count,
            mean_hugepage_proximity: self.hugepage_sum / pair_count,
            mean_weighted_overlap,
            mean_dispersion: 1.0 - mean_weighted_overlap,
            access_weighted_overlap,
            access_weighted_dispersion: 1.0 - access_weighted_overlap,
        }
    }
}

fn cmd_extract_mem_dispersion(opts: ExtractMemOpts) -> Result<()> {
    validate_dispersion_opts(&opts)?;
    let samples = load_dispersion_samples(&opts)?;
    if samples.is_empty() {
        bail!("no valid memory samples with physical addresses and timestamps");
    }

    let trace_start_ns = samples
        .iter()
        .map(|sample| sample.time_ns)
        .min()
        .context("no memory samples")?;

    for window_ms in &opts.window_ms {
        emit_dispersion_for_window(&samples, trace_start_ns, *window_ms, &opts)?;
    }

    Ok(())
}

fn validate_dispersion_opts(opts: &ExtractMemOpts) -> Result<()> {
    if opts.window_ms.is_empty() {
        bail!("at least one --window-ms value is required");
    }
    if opts.window_ms.contains(&0) {
        bail!("--window-ms values must be greater than zero");
    }
    if opts.cacheline_bytes == 0 || opts.page_bytes == 0 || opts.hugepage_bytes == 0 {
        bail!("address granularity sizes must be greater than zero");
    }
    if !opts.page_bytes.is_multiple_of(opts.cacheline_bytes)
        || !opts.hugepage_bytes.is_multiple_of(opts.cacheline_bytes)
    {
        bail!("page and hugepage sizes must be multiples of --cacheline-bytes");
    }
    if opts.page_decay_bytes <= 0.0 || opts.hugepage_decay_bytes <= 0.0 {
        bail!("distance decay values must be greater than zero");
    }
    if !(0.0..=1.0).contains(&opts.hugepage_weight) {
        bail!("--hugepage-weight must be between 0 and 1");
    }
    Ok(())
}

fn load_dispersion_samples(opts: &ExtractMemOpts) -> Result<Vec<DispersionSample>> {
    let file = File::open(&opts.file).context("failed to open mem/perf.mem.jsonl")?;
    let reader = BufReader::new(file);
    let comm_regex = opts
        .comm_regex
        .as_deref()
        .map(Regex::new)
        .transpose()
        .context("invalid --comm-regex")?;
    let mut samples = Vec::new();

    for line in reader.lines() {
        let line = line.context("failed to read line")?;
        if line.trim().is_empty() {
            continue;
        }
        let record: PerfMemRecord =
            serde_json::from_str(&line).context("failed to parse record")?;
        if let Some(regex) = &comm_regex
            && !regex.is_match(&record.comm)
        {
            continue;
        }
        let Some(time_ns) = record.sample_time_ns() else {
            continue;
        };
        let Some(addr) = dispersion_addr(&record, opts.address_space) else {
            continue;
        };
        if addr == 0 {
            continue;
        }
        samples.push(DispersionSample {
            entity: dispersion_entity(&record, opts.group_by),
            time_ns,
            addr,
        });
    }

    Ok(samples)
}

fn dispersion_addr(record: &PerfMemRecord, address_space: DispersionAddressSpace) -> Option<u64> {
    match address_space {
        DispersionAddressSpace::Phys => parse_hex_addr(&record.phys_addr),
        DispersionAddressSpace::Virt => parse_hex_addr(&record.addr),
    }
}

fn parse_hex_addr(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value == "0" || value == "N/A" {
        return None;
    }
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(value, 16).ok()
}

fn dispersion_entity(record: &PerfMemRecord, group_by: DispersionGroupBy) -> String {
    match group_by {
        DispersionGroupBy::Tid => format!("tid:{}:{}", record.tid, record.comm),
        DispersionGroupBy::Pid => format!("pid:{}:{}", record.pid, record.comm),
        DispersionGroupBy::Comm => record.comm.clone(),
        DispersionGroupBy::CommHint => format!("{}@hint={}", record.comm, record.hint),
    }
}

fn emit_dispersion_for_window(
    samples: &[DispersionSample],
    trace_start_ns: u64,
    window_ms: u64,
    opts: &ExtractMemOpts,
) -> Result<()> {
    let window_ns = window_ms
        .checked_mul(1_000_000)
        .context("window size overflow")?;
    let mut windows: BTreeMap<u64, BTreeMap<String, DispersionEntitySamples>> = BTreeMap::new();

    for sample in samples {
        let offset = sample.time_ns.saturating_sub(trace_start_ns);
        let window_start_ns = trace_start_ns + (offset / window_ns) * window_ns;
        windows
            .entry(window_start_ns)
            .or_default()
            .entry(sample.entity.clone())
            .or_default()
            .observe(sample.addr, opts);
    }

    for (window_start_ns, entities) in windows {
        let window_end_ns = window_start_ns + window_ns;
        let qualifying: Vec<_> = entities
            .iter()
            .filter(|(_, samples)| samples.sample_count() >= opts.min_samples_per_entity)
            .collect();
        let sample_count: usize = qualifying
            .iter()
            .map(|(_, samples)| samples.sample_count())
            .sum();
        let entity_count = qualifying.len();
        let entity_count_denom = entity_count.max(1) as f64;
        let mean_entity_line_wss_bytes = qualifying
            .iter()
            .map(|(_, samples)| samples.observed_line_wss_bytes(opts) as f64)
            .sum::<f64>()
            / entity_count_denom;
        let mean_entity_page_wss_bytes = qualifying
            .iter()
            .map(|(_, samples)| samples.observed_page_wss_bytes(opts) as f64)
            .sum::<f64>()
            / entity_count_denom;
        let union_lines: BTreeSet<_> = qualifying
            .iter()
            .flat_map(|(_, samples)| samples.lines.iter().copied())
            .collect();
        let union_pages: BTreeSet<_> = qualifying
            .iter()
            .flat_map(|(_, samples)| samples.pages.iter().copied())
            .collect();
        let union_line_wss_bytes = union_lines.len() as u64 * opts.cacheline_bytes;
        let union_page_wss_bytes = union_pages.len() as u64 * opts.page_bytes;
        let mut accum = DispersionSummaryAccum::default();
        let mut pair_records = Vec::new();

        for i in 0..qualifying.len() {
            for j in i + 1..qualifying.len() {
                let (entity_a, samples_a) = qualifying[i];
                let (entity_b, samples_b) = qualifying[j];
                let pair = compute_dispersion_pair(
                    window_ms,
                    window_start_ns,
                    window_end_ns,
                    entity_a,
                    samples_a,
                    entity_b,
                    samples_b,
                    opts,
                );
                accum.observe(&pair);
                pair_records.push(pair);
            }
        }

        let summary = accum.finish(
            window_ms,
            window_start_ns,
            window_end_ns,
            entity_count,
            sample_count,
            mean_entity_line_wss_bytes,
            mean_entity_page_wss_bytes,
            union_line_wss_bytes,
            union_page_wss_bytes,
        );
        println!("{}", serde_json::to_string(&summary)?);

        if opts.emit_pairs {
            for pair in pair_records {
                println!("{}", serde_json::to_string(&pair)?);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_dispersion_pair(
    window_ms: u64,
    window_start_ns: u64,
    window_end_ns: u64,
    entity_a: &str,
    samples_a: &DispersionEntitySamples,
    entity_b: &str,
    samples_b: &DispersionEntitySamples,
    opts: &ExtractMemOpts,
) -> DispersionPairRecord {
    let access_pair_count = (samples_a.sample_count() as u64) * (samples_b.sample_count() as u64);
    let line_overlap = line_jaccard(&samples_a.lines, &samples_b.lines);
    let page_proximity = symmetric_line_proximity(
        &samples_a.lines,
        &samples_b.lines,
        opts.page_bytes,
        opts.page_decay_bytes,
        1.0,
        opts,
    );
    let hugepage_proximity = symmetric_line_proximity(
        &samples_a.lines,
        &samples_b.lines,
        opts.hugepage_bytes,
        opts.hugepage_decay_bytes,
        opts.hugepage_weight,
        opts,
    );
    let weighted_overlap = line_overlap.max(page_proximity).max(hugepage_proximity);

    DispersionPairRecord {
        kind: "pair",
        window_ms,
        window_start_ns,
        window_end_ns,
        entity_a: entity_a.to_string(),
        entity_b: entity_b.to_string(),
        samples_a: samples_a.sample_count(),
        samples_b: samples_b.sample_count(),
        observed_line_wss_bytes_a: samples_a.observed_line_wss_bytes(opts),
        observed_line_wss_bytes_b: samples_b.observed_line_wss_bytes(opts),
        observed_page_wss_bytes_a: samples_a.observed_page_wss_bytes(opts),
        observed_page_wss_bytes_b: samples_b.observed_page_wss_bytes(opts),
        access_pair_count,
        line_overlap,
        page_proximity,
        hugepage_proximity,
        weighted_overlap,
        dispersion: 1.0 - weighted_overlap,
    }
}

fn line_jaccard(lines_a: &BTreeSet<u64>, lines_b: &BTreeSet<u64>) -> f64 {
    if lines_a.is_empty() || lines_b.is_empty() {
        return 0.0;
    }

    let intersection = lines_a.intersection(lines_b).count();
    let union = lines_a.len() + lines_b.len() - intersection;
    intersection as f64 / union as f64
}

fn symmetric_line_proximity(
    lines_a: &BTreeSet<u64>,
    lines_b: &BTreeSet<u64>,
    granularity_bytes: u64,
    decay_bytes: f64,
    weight: f64,
    opts: &ExtractMemOpts,
) -> f64 {
    if lines_a.is_empty() || lines_b.is_empty() {
        return 0.0;
    }

    let a_to_b = directional_line_proximity(
        lines_a,
        lines_b,
        granularity_bytes,
        decay_bytes,
        weight,
        opts,
    );
    let b_to_a = directional_line_proximity(
        lines_b,
        lines_a,
        granularity_bytes,
        decay_bytes,
        weight,
        opts,
    );
    (a_to_b + b_to_a) / 2.0
}

fn directional_line_proximity(
    from_lines: &BTreeSet<u64>,
    to_lines: &BTreeSet<u64>,
    granularity_bytes: u64,
    decay_bytes: f64,
    weight: f64,
    opts: &ExtractMemOpts,
) -> f64 {
    let mut score_sum = 0.0;

    for line in from_lines {
        let Some(nearest) = nearest_line_in_same_granule(*line, to_lines, granularity_bytes, opts)
        else {
            continue;
        };
        let distance_bytes = line.abs_diff(nearest) * opts.cacheline_bytes;
        score_sum += weight * (-(distance_bytes as f64) / decay_bytes).exp();
    }

    score_sum / from_lines.len() as f64
}

fn nearest_line_in_same_granule(
    line: u64,
    candidates: &BTreeSet<u64>,
    granularity_bytes: u64,
    opts: &ExtractMemOpts,
) -> Option<u64> {
    let line_addr = line.checked_mul(opts.cacheline_bytes)?;
    let granule_start_addr = (line_addr / granularity_bytes) * granularity_bytes;
    let granule_end_addr = granule_start_addr.checked_add(granularity_bytes)?;
    let start_line = granule_start_addr / opts.cacheline_bytes;
    let end_line = granule_end_addr / opts.cacheline_bytes;

    let next = candidates.range(line..end_line).next().copied();
    let prev = candidates.range(start_line..=line).next_back().copied();

    match (prev, next) {
        (Some(prev), Some(next)) => {
            if line.abs_diff(prev) <= line.abs_diff(next) {
                Some(prev)
            } else {
                Some(next)
            }
        }
        (Some(prev), None) => Some(prev),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

pub fn cmd_extract(opts: ExtractOpts) -> Result<()> {
    match opts.command {
        ExtractCommand::Mem(opts) => cmd_extract_mem(opts),
        ExtractCommand::Sched(opts) => cmd_extract_sched(opts),
        ExtractCommand::Locality(opts) => cmd_extract_locality(opts),
    }
}

pub fn cmd_extract_sched(opts: ExtractSchedOpts) -> Result<()> {
    match opts.command {
        ExtractSchedCommand::Util(opts) => cmd_extract_sched_util(opts),
    }
}

fn generate_config(
    groups: &HashMap<String, GroupData>,
    group_names: &[String],
    workload_cgroup: &str,
    allotment_regex: &str,
    opts: &ExtractMemOpts,
) -> CellConfig {
    let mut specs = Vec::new();

    let group_types = [
        (GroupType::Allotment, "allotment"),
        (GroupType::Workload, workload_cgroup),
        (GroupType::Rest, "rest"),
    ];

    for (group_type, name) in group_types {
        let samples: Vec<&PerfMemRecord> = match group_type {
            GroupType::Allotment => group_names
                .iter()
                .filter(|n| *n != "rest" && *n != workload_cgroup)
                .filter_map(|n| groups.get(n))
                .flat_map(|g| g.samples())
                .collect(),
            GroupType::Workload => groups
                .get(workload_cgroup)
                .map(|g| g.samples().iter().collect())
                .unwrap_or_default(),
            GroupType::Rest => groups
                .get("rest")
                .map(|g| g.samples().iter().collect())
                .unwrap_or_default(),
        };

        if samples.is_empty() {
            continue;
        }

        let clusters = compute_clusters(group_type, &samples, opts);
        if opts.verbose > 0 && group_type == GroupType::Allotment {
            print_config_cluster_diagnostics(name, &clusters, opts.verbose);
        }
        let subcells = build_subcells_from_clusters(&clusters);

        let matches = match group_type {
            GroupType::Allotment => {
                CellMatches::simple(SimpleCellMatches::cgroup_regex(allotment_regex.to_string()))
            }
            GroupType::Workload => CellMatches::simple(SimpleCellMatches::cgroup_contains(
                workload_cgroup.to_string(),
            )),
            GroupType::Rest => CellMatches::simple(SimpleCellMatches::default()),
        };

        specs.push(CellSpec {
            name: name.to_string(),
            matches,
            subcells,
        });
    }

    CellConfig { specs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample(comm: &str, cgroup: &str, hint: u64) -> PerfMemRecord {
        serde_json::from_value(json!({
            "comm": comm,
            "tid": 1,
            "pid": 1,
            "time": "0",
            "addr": "0",
            "cgroup": cgroup,
            "ip": "0",
            "sym": "sym",
            "dso": "dso",
            "phys_addr": "0",
            "data_page_size": 4096,
            "hint": hint,
        }))
        .expect("failed to build PerfMemRecord test sample")
    }

    fn sample_with_tid_addr(
        comm: &str,
        cgroup: &str,
        hint: u64,
        tid: u32,
        addr: u64,
    ) -> PerfMemRecord {
        serde_json::from_value(json!({
            "comm": comm,
            "tid": tid,
            "pid": 1,
            "time": "0",
            "addr": format!("{addr:x}"),
            "cgroup": cgroup,
            "ip": "0",
            "sym": "sym",
            "dso": "dso",
            "phys_addr": format!("{addr:x}"),
            "data_page_size": 4096,
            "hint": hint,
        }))
        .expect("failed to build PerfMemRecord test sample")
    }

    fn dispersion_opts() -> ExtractMemOpts {
        ExtractMemOpts {
            file: PathBuf::from("unused"),
            mode: ExtractMemMode::Dispersion,
            workload_cgroup_regex: DEFAULT_WORKLOAD_CGROUP_REGEX.to_string(),
            workload_allotment_cgroup_regex: DEFAULT_WORKLOAD_ALLOTMENT_CGROUP_REGEX.to_string(),
            use_hints: false,
            verbose: 0,
            window_ms: vec![1],
            group_by: DispersionGroupBy::Tid,
            address_space: DispersionAddressSpace::Phys,
            comm_regex: None,
            min_samples_per_entity: 1,
            cacheline_bytes: 64,
            page_bytes: 4096,
            hugepage_bytes: 2 * 1024 * 1024,
            page_decay_bytes: 256.0,
            hugepage_decay_bytes: 65536.0,
            hugepage_weight: 0.05,
            emit_pairs: false,
        }
    }

    fn config_opts(use_hints: bool) -> ExtractMemOpts {
        let mut opts = dispersion_opts();
        opts.mode = ExtractMemMode::Config;
        opts.use_hints = use_hints;
        opts
    }

    fn dispersion_entity_samples(addrs: &[u64], opts: &ExtractMemOpts) -> DispersionEntitySamples {
        let mut samples = DispersionEntitySamples::default();
        for addr in addrs {
            samples.observe(*addr, opts);
        }
        samples
    }

    fn push_samples(
        groups: &mut HashMap<String, GroupData>,
        group: &str,
        comm: &str,
        hint: u64,
        count: usize,
    ) {
        let data = groups
            .entry(group.to_string())
            .or_insert_with(GroupData::new);
        for _ in 0..count {
            data.push(sample(comm, group, hint));
        }
    }

    fn push_addr_samples(
        groups: &mut HashMap<String, GroupData>,
        group: &str,
        comm: &str,
        hint: u64,
        tid: u32,
        page_addr: u64,
        count: usize,
    ) {
        let data = groups
            .entry(group.to_string())
            .or_insert_with(GroupData::new);
        for idx in 0..count {
            let addr = page_addr + ((idx as u64 % 16) * 64);
            data.push(sample_with_tid_addr(comm, group, hint, tid, addr));
        }
    }

    fn generate_test_config(
        groups: &HashMap<String, GroupData>,
        group_names: &[String],
        workload_cgroup: &str,
        allotment_regex: &str,
        use_hints: bool,
    ) -> CellConfig {
        let opts = config_opts(use_hints);
        generate_config(groups, group_names, workload_cgroup, allotment_regex, &opts)
    }

    #[test]
    fn mem_extract_does_not_split_comms_by_hint_without_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 60);
        push_samples(&mut groups, allotment, "alpha", 7, 20);
        push_samples(&mut groups, allotment, "alpha", 9, 10);
        push_samples(&mut groups, allotment, "beta", 0, 10);

        let group_names = vec![allotment.to_string()];
        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let alpha = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha")
            .expect("missing alpha comm subcell");

        assert!(alpha.subcells.is_empty());
    }

    #[test]
    fn mem_extract_splits_significant_comms_by_hint_with_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 60);
        push_samples(&mut groups, allotment, "alpha", 7, 20);
        push_samples(&mut groups, allotment, "alpha", 9, 10);
        push_samples(&mut groups, allotment, "beta", 0, 10);

        let group_names = vec![allotment.to_string()];
        let config = generate_test_config(&groups, &group_names, workload, "allotment-regex", true);

        let allotment_spec = &config.specs[0];
        let alpha_hint_0 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=0")
            .expect("missing alpha@hint=0 subcell");
        let alpha_hint_7 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=7")
            .expect("missing alpha@hint=7 subcell");
        let alpha_hint_9 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha@hint=9")
            .expect("missing alpha@hint=9 subcell");

        assert_eq!(
            alpha_hint_0.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(0),
            ]])
        );
        assert_eq!(
            alpha_hint_7.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(7),
            ]])
        );
        assert_eq!(
            alpha_hint_9.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("alpha".to_string()),
                CellMatch::Hint(9),
            ]])
        );

        let beta = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "beta")
            .expect("missing beta comm subcell");
        assert!(beta.subcells.is_empty());
    }

    #[test]
    fn mem_extract_uses_single_match_statement_for_top_level_cells() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "alpha", 0, 10);
        push_samples(&mut groups, workload, "beta", 0, 10);
        push_samples(&mut groups, "rest", "gamma", 0, 10);

        let mut group_names = vec![
            allotment.to_string(),
            workload.to_string(),
            "rest".to_string(),
        ];
        group_names.sort();

        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == "allotment")
            .expect("missing allotment spec");
        assert_eq!(
            allotment_spec.matches,
            CellMatches::simple(SimpleCellMatches::cgroup_regex(
                "allotment-regex".to_string()
            ))
        );

        let workload_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == workload)
            .expect("missing workload spec");
        assert_eq!(
            workload_spec.matches,
            CellMatches::simple(SimpleCellMatches::cgroup_contains(workload.to_string()))
        );

        let rest_spec = config
            .specs
            .iter()
            .find(|spec| spec.name == "rest")
            .expect("missing rest spec");
        assert_eq!(
            rest_spec.matches,
            CellMatches::simple(SimpleCellMatches::default())
        );
    }

    #[test]
    fn mem_extract_clusters_numeric_suffix_comms_for_dominance() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "proxyNR1", 0, 4);
        push_samples(&mut groups, allotment, "proxyNR2", 0, 4);
        push_samples(&mut groups, allotment, "beta", 0, 92);

        let group_names = vec![allotment.to_string()];
        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let merged = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "proxyNR")
            .expect("missing merged numeric-suffix comm subcell");

        assert_eq!(
            merged.matches,
            CellMatches::complex(vec![vec![CellMatch::CommPrefix("proxyNR".to_string())]])
        );
        assert!(
            allotment_spec
                .subcells
                .iter()
                .all(|spec| spec.name != "proxyNR1" && spec.name != "proxyNR2")
        );
    }

    #[test]
    fn mem_extract_clusters_comms_with_overlapping_working_sets() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_addr_samples(&mut groups, allotment, "alpha", 0, 10, 0x1000, 50);
        push_addr_samples(&mut groups, allotment, "beta", 0, 20, 0x1000, 50);

        let group_names = vec![allotment.to_string()];
        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let cluster = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "alpha+beta")
            .expect("missing overlap cluster");

        assert_eq!(
            cluster.matches,
            CellMatches::complex(vec![
                vec![CellMatch::CommPrefix("alpha".to_string())],
                vec![CellMatch::CommPrefix("beta".to_string())],
            ])
        );
        assert!(
            allotment_spec
                .subcells
                .iter()
                .all(|spec| spec.name != "alpha" && spec.name != "beta")
        );
    }

    #[test]
    fn mem_extract_ignores_overlapping_comms_below_sample_threshold() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_addr_samples(&mut groups, allotment, "alpha", 0, 10, 0x1000, 96);
        push_addr_samples(&mut groups, allotment, "beta", 0, 20, 0x1000, 4);

        let group_names = vec![allotment.to_string()];
        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        assert!(
            allotment_spec
                .subcells
                .iter()
                .any(|spec| spec.name == "alpha")
        );
        assert!(
            allotment_spec
                .subcells
                .iter()
                .all(|spec| spec.name != "beta" && spec.name != "alpha+beta")
        );
    }

    #[test]
    fn mem_extract_merges_numeric_suffix_comms_even_when_working_sets_differ() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_addr_samples(&mut groups, allotment, "worker0", 0, 10, 0x1000, 50);
        push_addr_samples(&mut groups, allotment, "worker1", 0, 20, 0x20_0000, 50);

        let group_names = vec![allotment.to_string()];
        let config =
            generate_test_config(&groups, &group_names, workload, "allotment-regex", false);

        let allotment_spec = &config.specs[0];
        let worker = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "worker")
            .expect("missing normalized worker subcell");

        assert_eq!(
            worker.matches,
            CellMatches::complex(vec![vec![CellMatch::CommPrefix("worker".to_string())]])
        );
        assert!(
            allotment_spec
                .subcells
                .iter()
                .all(|spec| spec.name != "worker0" && spec.name != "worker1")
        );
    }

    #[test]
    fn mem_extract_splits_merged_numeric_suffix_comm_by_hint_with_flag() {
        let allotment = "workload-tw-foo.allotment.slice";
        let workload = "workload.slice";

        let mut groups = HashMap::new();
        push_samples(&mut groups, allotment, "proxyNR1", 0, 8);
        push_samples(&mut groups, allotment, "proxyNR1", 7, 2);
        push_samples(&mut groups, allotment, "proxyNR2", 7, 8);
        push_samples(&mut groups, allotment, "proxyNR2", 9, 10);
        push_samples(&mut groups, allotment, "beta", 0, 72);

        let group_names = vec![allotment.to_string()];
        let config = generate_test_config(&groups, &group_names, workload, "allotment-regex", true);

        let allotment_spec = &config.specs[0];
        let merged_hint_0 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "proxyNR@hint=0")
            .expect("missing merged numeric-suffix hint=0 subcell");
        let merged_hint_7 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "proxyNR@hint=7")
            .expect("missing merged numeric-suffix hint=7 subcell");
        let merged_hint_9 = allotment_spec
            .subcells
            .iter()
            .find(|spec| spec.name == "proxyNR@hint=9")
            .expect("missing merged numeric-suffix hint=9 subcell");
        assert_eq!(
            merged_hint_0.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("proxyNR".to_string()),
                CellMatch::Hint(0),
            ]])
        );
        assert_eq!(
            merged_hint_7.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("proxyNR".to_string()),
                CellMatch::Hint(7),
            ]])
        );
        assert_eq!(
            merged_hint_9.matches,
            CellMatches::complex(vec![vec![
                CellMatch::CommPrefix("proxyNR".to_string()),
                CellMatch::Hint(9),
            ]])
        );
    }

    #[test]
    fn mem_extract_summary_groups_numeric_suffix_comms_and_reports_hints() {
        let samples = [
            sample("proxyNR1", "cg", 0),
            sample("proxyNR2", "cg", 7),
            sample("proxyNR3", "cg", 7),
        ];
        let sample_refs: Vec<_> = samples.iter().collect();
        let summary = summarize_comm_groups(&sample_refs);

        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].name, "proxyNR");
        assert_eq!(summary[0].count, 3);
        assert!(summary[0].aggregated_numeric_suffixes);
        assert_eq!(summary[0].hint_counts, vec![(7, 2), (0, 1)]);
        assert_eq!(
            summary[0].concrete_counts,
            vec![
                ("proxyNR1".to_string(), 1),
                ("proxyNR2".to_string(), 1),
                ("proxyNR3".to_string(), 1),
            ]
        );
    }

    #[test]
    fn mem_dispersion_scores_exact_line_overlap_and_same_page_proximity() {
        let opts = dispersion_opts();
        let samples_a = dispersion_entity_samples(&[0x1000, 0x1040], &opts);
        let samples_b = dispersion_entity_samples(&[0x1000, 0x1080], &opts);

        let pair =
            compute_dispersion_pair(1, 0, 1_000_000, "a", &samples_a, "b", &samples_b, &opts);

        assert_eq!(pair.access_pair_count, 4);
        assert!((pair.line_overlap - (1.0 / 3.0)).abs() < f64::EPSILON);
        assert!(
            pair.page_proximity > pair.line_overlap,
            "same-page proximity should add signal beyond exact line overlap"
        );
        assert_eq!(pair.weighted_overlap, pair.page_proximity);
        assert!(pair.dispersion < 1.0);
    }

    #[test]
    fn mem_dispersion_reports_full_dispersion_for_distant_footprints() {
        let opts = dispersion_opts();
        let samples_a = dispersion_entity_samples(&[0x1000, 0x1040], &opts);
        let samples_b = dispersion_entity_samples(&[0x20_0000, 0x20_0040], &opts);

        let pair =
            compute_dispersion_pair(1, 0, 1_000_000, "a", &samples_a, "b", &samples_b, &opts);

        assert_eq!(pair.line_overlap, 0.0);
        assert_eq!(pair.page_proximity, 0.0);
        assert_eq!(pair.hugepage_proximity, 0.0);
        assert_eq!(pair.weighted_overlap, 0.0);
        assert_eq!(pair.dispersion, 1.0);
    }

    #[test]
    fn mem_dispersion_reports_full_overlap_for_identical_sampled_working_sets() {
        let opts = dispersion_opts();
        let samples_a = dispersion_entity_samples(&[0x1000, 0x1040], &opts);
        let samples_b = dispersion_entity_samples(&[0x1000, 0x1040], &opts);

        let pair =
            compute_dispersion_pair(1, 0, 1_000_000, "a", &samples_a, "b", &samples_b, &opts);

        assert_eq!(pair.line_overlap, 1.0);
        assert_eq!(pair.page_proximity, 1.0);
        assert_eq!(pair.weighted_overlap, 1.0);
        assert_eq!(pair.dispersion, 0.0);
    }
}
