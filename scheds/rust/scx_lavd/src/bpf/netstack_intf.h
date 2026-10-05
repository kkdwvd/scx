/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The network soft partition: the record a network stack and scx_lavd share.
 *
 * A stack asks for CPUs by writing a request into this record and lavd
 * answers with a grant in the same record, so the layout is shared with the
 * stack's own programs (the BPF NAPI pollers) and user space. Everything
 * here is plain C with fixed-size fields; keep it that way.
 */
#ifndef __NETSTACK_INTF_H
#define __NETSTACK_INTF_H

#define NETSTACK_CPU_ID_MAX	8192
#define NETSTACK_MASK_WORDS	(NETSTACK_CPU_ID_MAX / 64)

/* Request flags. */
enum {
	NETSTACK_REQ_CANDIDATES	= 0x1,	/* grant only within the candidates mask */
	NETSTACK_REQ_DROP	= 0x2,	/* release the CPUs of the drop mask first */
	NETSTACK_REQ_EXCLUSIVE	= 0x4,	/* reserved: no borrowing of idle time */
	NETSTACK_REQ_NO_QUANTA	= 0x8,	/* reserved: no time share with pinned tasks */
};

/*
 * The request is a seqlock: the writer makes req_seq odd, writes the fields,
 * and makes it even again; a reader that sees an odd value or a changed one
 * after reading tries again. The grant side does the same with grant_seq.
 * applied_seq is the req_seq the grant answers.
 */
struct netstack_shm {
	/* The request: written by the stack. */
	u64	req_seq;
	u32	target;		/* CPUs the stack wants in all */
	u32	flags;		/* NETSTACK_REQ_* */
	u64	candidates[NETSTACK_MASK_WORDS];
	u64	drop[NETSTACK_MASK_WORDS];
	/* The grant: written by lavd. */
	u64	grant_seq;
	u64	applied_seq;
	u32	nr_granted;
	u32	cap;		/* the most lavd would grant now */
	u64	granted[NETSTACK_MASK_WORDS];
	/* Counters. */
	u64	nr_requests;
	u64	nr_grows;	/* CPUs added, summed over grants */
	u64	nr_shrinks;	/* CPUs released, summed over grants */
	u64	nr_denied;	/* CPUs requested beyond the cap, summed */
	u32	nr_registered;	/* registered network threads */
	u32	__pad;
};

#endif /* __NETSTACK_INTF_H */
