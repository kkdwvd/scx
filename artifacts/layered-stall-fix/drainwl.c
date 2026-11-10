// Workload for the scx_layered LLC drain race.
//
// "drn-hog" threads keep every CPU of the confined "drn" layer busy and
// dispatching. One or more migrator threads alternate between the comm
// "oth-mig" (default layer, runs on some other LLC) and "drn-mig" (confined
// layer). Each switch into the confined layer wakes the thread with its
// previous CPU in an LLC the layer has no CPUs in, so layered_enqueue() queues
// it on that LLC's DSQ and relies on draining to get it serviced.
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static atomic_int stop;
static atomic_ulong nr_wakes, nr_late;
static atomic_ullong max_lat_ns;

static cpu_set_t far_cpus, all_cpus;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void spin_ns(uint64_t ns)
{
	uint64_t until = now_ns() + ns;

	while (now_ns() < until)
		;
}

static void *hog(void *arg)
{
	/* layered re-matches a renamed task when it next wakes up */
	prctl(PR_SET_NAME, "drn-hog");
	usleep(1000);
	while (!stop)
		sched_yield();
	return NULL;
}

static void *mig(void *arg)
{
	const uint64_t sleep_ns = 300000;

	while (!stop) {
		uint64_t t0, lat;
		unsigned long long prev;

		/* run a bit in the default layer, on an LLC "drn" has no CPUs in */
		sched_setaffinity(0, sizeof(far_cpus), &far_cpus);
		prctl(PR_SET_NAME, "oth-mig");
		usleep(sleep_ns / 1000);
		spin_ns(100000);

		/*
		 * The wakeup below enqueues into the confined layer with the
		 * previous CPU on that LLC. Full affinity keeps the task on
		 * the layer DSQs instead of the fallback DSQ.
		 */
		sched_setaffinity(0, sizeof(all_cpus), &all_cpus);
		prctl(PR_SET_NAME, "drn-mig");
		t0 = now_ns();
		usleep(sleep_ns / 1000);
		lat = now_ns() - t0 - sleep_ns;

		nr_wakes++;
		if (lat > 1000000000ULL)
			nr_late++;
		prev = max_lat_ns;
		while (lat > prev &&
		       !atomic_compare_exchange_weak(&max_lat_ns, &prev, lat))
			;
		spin_ns(100000);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int nr_hogs = argc > 1 ? atoi(argv[1]) : 8;
	int nr_migs = argc > 2 ? atoi(argv[2]) : 1;
	int secs = argc > 3 ? atoi(argv[3]) : 60;
	int far_first = argc > 4 ? atoi(argv[4]) : 8;
	int far_last = argc > 5 ? atoi(argv[5]) : 15;
	pthread_t tids[256];
	int i, n = 0;

	sched_getaffinity(0, sizeof(all_cpus), &all_cpus);
	CPU_ZERO(&far_cpus);
	for (i = far_first; i <= far_last; i++)
		CPU_SET(i, &far_cpus);

	for (i = 0; i < nr_hogs; i++)
		pthread_create(&tids[n++], NULL, hog, NULL);
	for (i = 0; i < nr_migs; i++)
		pthread_create(&tids[n++], NULL, mig, NULL);

	for (i = 0; i < secs; i++) {
		sleep(1);
		printf("t=%2d wakes=%lu late(>1s)=%lu max_lat_ms=%.3f\n", i + 1,
		       (unsigned long)nr_wakes, (unsigned long)nr_late,
		       max_lat_ns / 1e6);
		fflush(stdout);
	}
	stop = 1;
	for (i = 0; i < n; i++)
		pthread_join(tids[i], NULL);
	printf("RESULT wakes=%lu late(>1s)=%lu max_lat_ms=%.3f\n",
	       (unsigned long)nr_wakes, (unsigned long)nr_late,
	       max_lat_ns / 1e6);
	return 0;
}
