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

/*
 * Pools: the global pool, whose candidates are every CPU, and one pool per
 * compute domain d (an LLC, or one core type of an LLC) numbered 1 + d,
 * whose candidates are the domain's CPUs. Each has its own record; the
 * records are the entries of the shm map, indexed by pool.
 */
#define NETSTACK_POOL_GLOBAL		0
#define NETSTACK_MAX_POOLS		129	/* 1 + LAVD_CPDOM_MAX_NR */
#define NETSTACK_POOL_GLOBAL_CPDOM	0xffffffffU

/* Request flags. */
enum {
	NETSTACK_REQ_CANDIDATES	= 0x1,	/* grant only within the candidates mask */
	NETSTACK_REQ_DROP	= 0x2,	/* release the CPUs of the drop mask first */
	NETSTACK_REQ_EXCLUSIVE	= 0x4,	/* no borrowing of the pool's idle time by other tasks */
	NETSTACK_REQ_NO_QUANTA	= 0x8,	/* no time share of the pool's CPUs with pinned tasks */
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
	u64	nr_quanta_kicks; /* phase boundaries that preempted the running task */
	u32	withheld;	/* CPUs lavd holds back from this pool's target for a saturated application */
	u32	__pad1;
	u64	nr_yields;	/* CPUs withheld, summed */
	u64	nr_restores;	/* CPUs given back, summed */
	u32	nr_registered;	/* registered network threads */
	u32	pool;		/* this record's pool */
	u32	cpdom;		/* its compute domain; NETSTACK_POOL_GLOBAL_CPDOM for the global pool */
	u32	__pad;
};

/*
 * Arguments of the syscall programs, run with BPF_PROG_TEST_RUN on the
 * programs lavd pins under its netstack directory: register_thread,
 * unregister_thread, get_capacity, request_capacity.
 */

/*
 * lavd_netstack_register_thread(), lavd_netstack_unregister_thread(): a
 * thread belongs to one pool and runs on its CPUs; unregister it before
 * registering it with another.
 */
struct netstack_thread_arg {
	s32	tid;		/* the thread, or 0 for the calling thread */
	u32	flags;		/* reserved: 0 */
	u32	pool;
	u32	__pad;
};

/* lavd_netstack_get_capacity(): the grant in force, returns nr_granted */
struct netstack_cap_arg {
	u32	pool;
	u32	nr_granted;
	u32	target;		/* the request the grant answers */
	u32	cap;
	u64	req_seq;
	u64	grant_seq;
	u64	granted[NETSTACK_MASK_WORDS];
};

/*
 * lavd_netstack_request_capacity(): set the target, and the candidates and
 * drop masks when their flags are set; returns the nr_granted in force when
 * the call returned, which is the previous grant. The request takes effect
 * on lavd's next tick; a grant whose applied_seq is at least req_seq
 * answers it. Two requesters racing get -EBUSY for the second.
 */
struct netstack_req_arg {
	u32	pool;
	s32	target_cpus;	/* CPUs wanted in all, capped by lavd; -1 keeps the current target */
	u32	flags;		/* NETSTACK_REQ_* */
	u32	nr_granted;	/* out */
	u64	req_seq;	/* out */
	u64	candidates[NETSTACK_MASK_WORDS];
	u64	drop[NETSTACK_MASK_WORDS];
	u64	granted[NETSTACK_MASK_WORDS];	/* out */
};

#endif /* __NETSTACK_INTF_H */
