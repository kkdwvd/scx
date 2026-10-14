// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

/*
 * Thread classes with known code and data footprints and known sharing,
 * for checking what scx_characterize measures against what was configured.
 *
 *   cc -O2 -pthread -o locality_bench locality_bench.c
 *   ./locality_bench --seconds 20 \
 *       --class a:4:0-128:512:512:g1:20 \
 *       --class b:4:64-192:512:512:g1:20 \
 *       --class c:4:256-320:256:0:-:0
 *
 * A class is NAME:THREADS:LO-HI:PRIVATE_KB:SHARED_KB:GROUP:WRITE_PCT. Its
 * threads are named NAME and call the generated functions LO..HI-1 round
 * robin. Each call reads its table slot and touches eight random cache
 * lines, picked uniformly over
 * the thread's own private buffer of PRIVATE_KB and the buffer shared by
 * every class in GROUP, sized SHARED_KB by the first class that names the
 * group, and writes WRITE_PCT percent of them. A class with T threads thus
 * has a data footprint of T * PRIVATE + SHARED, and the share of its
 * accesses that land in the shared buffer is SHARED / (T * PRIVATE + SHARED).
 *
 * Every generated function sits in its own 256-byte slot and holds the whole
 * touch loop, so a class that runs N functions executes N * 256 bytes of
 * class-specific code and two classes whose ranges overlap share exactly the
 * overlapping functions; the driver outside the functions is a few lines.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NFUNCS 500
#define FUNC_SLOT 256
#define LINE 64

struct ctx {
	unsigned char *priv;
	unsigned char *shared;
	size_t private_lines;
	size_t total_lines;
	unsigned write_pct;
};

typedef uint64_t (*fn_t)(const struct ctx *, uint64_t);

/*
 * One generated function: eight touches of random lines. The whole loop
 * lives inside the function so the executed code is class specific.
 */
#define F(n)                                                                   \
	static __attribute__((noinline, aligned(FUNC_SLOT))) uint64_t fn_##n(  \
		const struct ctx *c, uint64_t x)                               \
	{                                                                      \
		unsigned char *priv = c->priv, *shared = c->shared;            \
		size_t private_lines = c->private_lines;                       \
		size_t total_lines = c->total_lines;                           \
		unsigned write_pct = c->write_pct;                             \
		for (int i = 0; i < 8; i++) {                                  \
			x ^= x << 13;                                          \
			x ^= x >> 7;                                           \
			x ^= x << 17;                                          \
			size_t line = (size_t)(x % total_lines);               \
			volatile uint64_t *p = line < private_lines ?          \
				(volatile uint64_t *)(priv + line * LINE) :    \
				(volatile uint64_t *)(shared +                 \
					(line - private_lines) * LINE);        \
			if ((unsigned)(x >> 40) % 100 < write_pct)             \
				*p = x;                                        \
			else                                                   \
				x += *p;                                       \
		}                                                              \
		return x;                                                      \
	}
#define FA(p) F(p##0) F(p##1) F(p##2) F(p##3) F(p##4) F(p##5) F(p##6) F(p##7) F(p##8) F(p##9)
#define FB(p) FA(p##0) FA(p##1) FA(p##2) FA(p##3) FA(p##4) FA(p##5) FA(p##6) FA(p##7) FA(p##8) FA(p##9)
FB(0) FB(1) FB(2) FB(3) FB(4)

#define T(n) fn_##n,
#define TA(p) T(p##0) T(p##1) T(p##2) T(p##3) T(p##4) T(p##5) T(p##6) T(p##7) T(p##8) T(p##9)
#define TB(p) TA(p##0) TA(p##1) TA(p##2) TA(p##3) TA(p##4) TA(p##5) TA(p##6) TA(p##7) TA(p##8) TA(p##9)
static const fn_t table[NFUNCS] = { TB(0) TB(1) TB(2) TB(3) TB(4) };

struct group {
	char name[32];
	size_t bytes;
	unsigned char *buf;
};

struct class {
	char name[16];
	int threads;
	int lo, hi;
	size_t private_bytes;
	struct group *group;
	int write_pct;
};

static struct group groups[16];
static int ngroups;
static struct class classes[16];
static int nclasses;
static volatile int stop;
static volatile uint64_t sink;

static struct group *find_group(const char *name, size_t bytes)
{
	for (int i = 0; i < ngroups; i++)
		if (!strcmp(groups[i].name, name))
			return &groups[i];
	struct group *g = &groups[ngroups++];
	snprintf(g->name, sizeof(g->name), "%s", name);
	g->bytes = bytes;
	g->buf = bytes ? aligned_alloc(4096, bytes) : NULL;
	if (g->buf)
		memset(g->buf, 1, bytes);
	return g;
}

static int parse_class(const char *spec)
{
	struct class *c = &classes[nclasses];
	char group[32];
	unsigned private_kb, shared_kb;

	if (sscanf(spec, "%15[^:]:%d:%d-%d:%u:%u:%31[^:]:%d", c->name, &c->threads,
		   &c->lo, &c->hi, &private_kb, &shared_kb, group,
		   &c->write_pct) != 8)
		return -1;
	if (c->lo < 0 || c->hi > NFUNCS || c->lo >= c->hi || c->threads <= 0)
		return -1;
	c->private_bytes = (size_t)private_kb * 1024;
	c->group = strcmp(group, "-") ? find_group(group, (size_t)shared_kb * 1024) : NULL;
	nclasses++;
	return 0;
}

static void *worker(void *arg)
{
	struct class *c = arg;
	struct ctx ctx = {
		.priv = c->private_bytes ? aligned_alloc(4096, c->private_bytes) : NULL,
		.shared = c->group ? c->group->buf : NULL,
		.private_lines = c->private_bytes / LINE,
		.write_pct = (unsigned)c->write_pct,
	};
	uint64_t x = (uint64_t)(uintptr_t)&ctx | 1;
	const int lo = c->lo, hi = c->hi;
	int fn = lo;

	ctx.total_lines = ctx.private_lines + (c->group ? c->group->bytes / LINE : 0);
	if (!ctx.total_lines) {
		fprintf(stderr, "class %s has no data to touch\n", c->name);
		return NULL;
	}
	pthread_setname_np(pthread_self(), c->name);
	if (ctx.priv)
		memset(ctx.priv, 2, c->private_bytes);

	while (!stop) {
		for (int k = 0; k < 64; k++) {
			x = table[fn](&ctx, x);
			if (++fn >= hi)
				fn = lo;
		}
	}
	sink += x;
	free(ctx.priv);
	return NULL;
}

int main(int argc, char **argv)
{
	int seconds = 10;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
			seconds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--class") && i + 1 < argc) {
			if (parse_class(argv[++i])) {
				fprintf(stderr, "bad class spec: %s\n", argv[i]);
				return 2;
			}
		} else {
			fprintf(stderr, "usage: %s --seconds N --class SPEC...\n", argv[0]);
			return 2;
		}
	}
	if (!nclasses) {
		fprintf(stderr, "no classes given\n");
		return 2;
	}

	int total = 0;
	for (int i = 0; i < nclasses; i++)
		total += classes[i].threads;
	pthread_t *threads = calloc(total, sizeof(*threads));
	int t = 0;
	for (int i = 0; i < nclasses; i++)
		for (int j = 0; j < classes[i].threads; j++)
			pthread_create(&threads[t++], NULL, worker, &classes[i]);

	sleep(seconds);
	stop = 1;
	for (int i = 0; i < total; i++)
		pthread_join(threads[i], NULL);
	printf("done\n");
	return 0;
}
