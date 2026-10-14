// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Decoder for the `perf_mem_data_src` word perf attaches to memory samples.
//!
//! The layout follows `union perf_mem_data_src` in the kernel UAPI: the
//! operation in bits 0..5, the legacy level bitmask in bits 5..19, the snoop
//! bits in 19..24, the lock bits in 24..26, the TLB bits in 26..33, the level
//! number in 33..37, the remote flag in bit 37, and the hop count in 43..46.

const OP_SHIFT: u32 = 0;
const OP_LOAD: u64 = 0x02;
const OP_STORE: u64 = 0x04;
const OP_PFETCH: u64 = 0x08;
const OP_EXEC: u64 = 0x10;

const LVL_SHIFT: u32 = 5;
const LVL_HIT: u64 = 0x02;
const LVL_MISS: u64 = 0x04;
const LVL_L1: u64 = 0x08;
const LVL_LFB: u64 = 0x10;
const LVL_L2: u64 = 0x20;
const LVL_L3: u64 = 0x40;
const LVL_LOC_RAM: u64 = 0x80;
const LVL_REM_RAM1: u64 = 0x100;
const LVL_REM_RAM2: u64 = 0x200;
const LVL_REM_CCE1: u64 = 0x400;
const LVL_REM_CCE2: u64 = 0x800;
const LVL_IO: u64 = 0x1000;
const LVL_UNC: u64 = 0x2000;

const TLB_SHIFT: u32 = 26;
const TLB_HIT: u64 = 0x02;
const TLB_MISS: u64 = 0x04;
const TLB_L1: u64 = 0x08;
const TLB_L2: u64 = 0x10;
const TLB_WK: u64 = 0x20;
const TLB_OS: u64 = 0x40;

const LVLNUM_SHIFT: u32 = 33;
const LVLNUM_MASK: u64 = 0xf;
const LVLNUM_NA: u64 = 0xf;

const REMOTE_SHIFT: u32 = 37;
const HOPS_SHIFT: u32 = 43;
const HOPS_MASK: u64 = 0x7;

/// The parts of a data source word the locality analysis uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemDataSrc {
    /// `load`, `store`, `pfetch`, `exec` or `na`.
    pub op: &'static str,
    /// Level that served the access: `l1`, `l2`, `l3`, `l4`, `lfb`, `ram`,
    /// `any_cache` (a peer cache), `io`, `unc`, `pmem`, `cxl`, `msc`,
    /// `l2_mhb` or `na`.
    pub lvl: &'static str,
    /// Whether the legacy level bits report a hit or a miss at that level.
    pub hit: Option<bool>,
    /// The access was served from another node or socket.
    pub remote: bool,
    /// Hop count from `perf_mem_data_src.mem_hops`, zero when not reported.
    pub hops: u8,
    /// `l1`, `l2`, `walk`, `miss` or `na` for the data TLB outcome.
    pub tlb: &'static str,
}

impl MemDataSrc {
    pub fn decode(raw: u64) -> Self {
        let op_bits = (raw >> OP_SHIFT) & 0x1f;
        let op = if op_bits & OP_LOAD != 0 {
            "load"
        } else if op_bits & OP_STORE != 0 {
            "store"
        } else if op_bits & OP_PFETCH != 0 {
            "pfetch"
        } else if op_bits & OP_EXEC != 0 {
            "exec"
        } else {
            "na"
        };

        let lvl_bits = (raw >> LVL_SHIFT) & 0x3fff;
        let hit = if lvl_bits & LVL_HIT != 0 {
            Some(true)
        } else if lvl_bits & LVL_MISS != 0 {
            Some(false)
        } else {
            None
        };

        let legacy_remote =
            lvl_bits & (LVL_REM_RAM1 | LVL_REM_RAM2 | LVL_REM_CCE1 | LVL_REM_CCE2) != 0;
        let remote = (raw >> REMOTE_SHIFT) & 0x1 != 0 || legacy_remote;
        let hops = ((raw >> HOPS_SHIFT) & HOPS_MASK) as u8;

        let lvlnum = (raw >> LVLNUM_SHIFT) & LVLNUM_MASK;
        let lvl = match lvlnum {
            0x1 => "l1",
            0x2 => "l2",
            0x3 => "l3",
            0x4 => "l4",
            0x5 => "l2_mhb",
            0x6 => "msc",
            0x8 => "unc",
            0x9 => "cxl",
            0xa => "io",
            0xb => "any_cache",
            0xc => "lfb",
            0xd => "ram",
            0xe => "pmem",
            LVLNUM_NA => legacy_level(lvl_bits),
            _ => legacy_level(lvl_bits),
        };

        let tlb_bits = (raw >> TLB_SHIFT) & 0x7f;
        let tlb = if tlb_bits & (TLB_WK | TLB_OS) != 0 {
            "walk"
        } else if tlb_bits & TLB_HIT != 0 && tlb_bits & TLB_L1 != 0 {
            "l1"
        } else if tlb_bits & TLB_HIT != 0 && tlb_bits & TLB_L2 != 0 {
            "l2"
        } else if tlb_bits & TLB_MISS != 0 {
            "miss"
        } else {
            "na"
        };

        Self {
            op,
            lvl,
            hit,
            remote,
            hops,
            tlb,
        }
    }
}

fn legacy_level(lvl_bits: u64) -> &'static str {
    if lvl_bits & LVL_L1 != 0 {
        "l1"
    } else if lvl_bits & LVL_LFB != 0 {
        "lfb"
    } else if lvl_bits & LVL_L2 != 0 {
        "l2"
    } else if lvl_bits & LVL_L3 != 0 {
        "l3"
    } else if lvl_bits & (LVL_LOC_RAM | LVL_REM_RAM1 | LVL_REM_RAM2) != 0 {
        "ram"
    } else if lvl_bits & (LVL_REM_CCE1 | LVL_REM_CCE2) != 0 {
        "any_cache"
    } else if lvl_bits & LVL_IO != 0 {
        "io"
    } else if lvl_bits & LVL_UNC != 0 {
        "unc"
    } else {
        "na"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_data_source_words() {
        let src = MemDataSrc::decode(0x229080142);
        assert_eq!(
            (src.op, src.lvl, src.hit, src.remote, src.tlb),
            ("load", "l1", Some(true), false, "l1")
        );
        assert_eq!(MemDataSrc::decode(0x229080144).op, "store");

        let src = MemDataSrc::decode(0x1e05080021);
        assert_eq!(
            (src.op, src.lvl, src.hit, src.tlb),
            ("na", "na", None, "na")
        );

        let raw = (0xd << LVLNUM_SHIFT) | (1 << REMOTE_SHIFT) | (2 << HOPS_SHIFT) | OP_LOAD;
        let src = MemDataSrc::decode(raw);
        assert_eq!((src.lvl, src.remote, src.hops), ("ram", true, 2));
        assert_eq!(
            MemDataSrc::decode((0xb << LVLNUM_SHIFT) | OP_LOAD).lvl,
            "any_cache"
        );

        let raw = (LVLNUM_NA << LVLNUM_SHIFT) | ((LVL_L3 | LVL_MISS) << LVL_SHIFT) | OP_LOAD;
        let src = MemDataSrc::decode(raw);
        assert_eq!((src.lvl, src.hit), ("l3", Some(false)));
    }
}
