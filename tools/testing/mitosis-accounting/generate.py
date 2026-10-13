#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual BPF callback/helper bodies with mocked clocks and map faults.
This is a host regression test, not a kernel verifier or scheduler runtime test.
"""
import argparse, hashlib, json, pathlib, re, subprocess, sys
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=pathlib.Path, help='mitosis.bpf.c to extract')
parser.add_argument('output', type=pathlib.Path, help='directory for generated C, executable and results')
args = parser.parse_args()
source = args.source.read_text()
out = args.output; out.mkdir(parents=True, exist_ok=True)
names = ['pinned_dsq_overdue', 'update_task_demand', 'account_task_running',
         'mitosis_dispatch', 'account_task_queued', 'mitosis_runnable',
         'mitosis_quiescent', 'mitosis_running', 'update_task_runtime_ewma',
         'mitosis_tick', 'mitosis_stopping']
def extract(name):
    match = re.search(r'^(?:static [^\n]+\b'+name+r'\(|void BPF_STRUCT_OPS\('+name+r',)', source, re.M)
    if not match: raise ValueError(name)
    start = source.index('{', match.start()); end = start + 1; depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}'); end += 1
    return source[match.start():end]
preamble = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
typedef uint64_t u64; typedef uint32_t u32; typedef int32_t s32;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define unlikely(x) (x)
#define MEMBER_VPTR(base,member) (tctx->cell < 2 ? &(base member) : NULL)
#define scx_bpf_error(...) (++errors)
#define cstat_inc(...) ((void)0)
#define SCX_TASK_QUEUED 1
#define MAX_LLCS 2
#define FAKE_FLAT_SUBCELL_LLC 0
#define PINNED_MAX_WAIT_SLICES 8
#define DEMAND_SHIFT 10
#define DEMAND_TAU_NS (100ULL*1000*1000)
#define DEMAND_MAX_WINDOW_NS (1ULL<<40)
typedef struct { u64 raw; } dsq_id_t;
#define DSQ_INVALID ((dsq_id_t){0})
struct task_struct { int pid, cpu; struct { u64 flags,slice,dsq_vtime; u32 weight; } scx; } task;
struct task_ctx {
 u32 cell,subcell,llc,vtime_charge_subcell,demand;
 bool all_cell_cpus_allowed,borrowed;
 dsq_id_t dsq;
 u64 avg_runtime_ns,started_running_at,running_accounted_at,runnable_at,quiescent_at;
 u64 demand_window_at,window_run_ns,window_sleep_ns;
} taskctx;
struct cpu_ctx { u32 cell,subcell,llc; u64 vtime_now,running_ns[2],pinned_waiting_since; } cpus[2];
struct subcell { u64 llcs_to_drain; } sub;
struct subcell_account { u64 running_ns,queued_ns,demand_sum; } accounts[2][4];
int subcell_accounts,executing,errors,refills; bool map_fail;
u64 local_time[2],task_time[2],global_time,slice_ns=20000000;
bool enable_llc_awareness,enable_slice_shrinking; u32 nr_llc=1;
static inline u64 time_delta(u64 after,u64 before) { return (int64_t)(after-before)>0 ? after-before : 0; }
static inline bool time_before(u64 a,u64 b) { return (int64_t)(a-b)<0; }
static u64 scx_bpf_now(void) { return local_time[executing]; }
static u64 bpf_ktime_get_ns(void) { return global_time; }
static u64 scx_clock_task(u32 cpu) { return task_time[cpu]; }
static int scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static struct cpu_ctx *lookup_cpu_ctx(int cpu) { return &cpus[cpu<0 ? executing : cpu]; }
static struct task_ctx *lookup_task_ctx(struct task_struct *p) { return &taskctx; }
static s32 pack_subcell_id(u32 cell,u32 subcell) {
 if(cell>=2 || subcell>=2) { ++errors; return -EINVAL; } return cell*2+subcell;
}
static void *bpf_map_lookup_elem(void *map,u32 *key) { return map_fail ? NULL : &accounts[executing][*key]; }
static void *bpf_map_lookup_percpu_elem(void *map,u32 *key,u32 cpu) { return map_fail ? NULL : &accounts[cpu][*key]; }
static dsq_id_t get_cpu_dsq_id(int cpu) { return (dsq_id_t){100+cpu}; }
static dsq_id_t get_subcell_llc_dsq_id(u32 c,u32 s,u32 l) { return (dsq_id_t){200+c*2+s}; }
static bool dsq_is_invalid(dsq_id_t dsq) { return !dsq.raw; }
static struct task_struct *dsq_peek(u64 id) { return NULL; }
static struct subcell *lookup_subcell(u32 c,u32 s) { return &sub; }
static int try_draining_work(u32 c,u32 s,u32 l,struct cpu_ctx *ctx) { return 1; }
static int try_stealing_work(u32 c,u32 s,u32 l) { return 1; }
static bool task_needs_refresh(struct task_struct *p,struct task_ctx *ctx) { return false; }
static void scx_bpf_task_set_slice(struct task_struct *p,u64 slice) { ++refills; p->scx.slice=slice; }
static bool scx_bpf_dsq_move_to_local(u64 id,u64 flags) { return false; }
static void subcell_llc_nr_queued_dec(struct subcell *s,u32 l) { }
static int maybe_update_task_llc(struct task_struct *p,struct task_ctx *t,int cpu) { return 0; }
static void advance_subcell_llc_vtime(struct subcell *s,u32 llc,u64 vtime) { }
static int slice_shrink_on_running(struct task_struct *p,u32 cell,struct cpu_ctx *c) { return 0; }
static bool llc_is_valid(u32 llc) { return llc<2; }
static void scx_bpf_task_set_dsq_vtime(struct task_struct *p,u64 vtime) { p->scx.dsq_vtime=vtime; }
'''
driver = r'''
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"%s:%d: %s\n",name,__LINE__,#c); return 1; } } while(0)
static void clock_at(u64 now) { global_time=now; local_time[0]=local_time[1]=now; task_time[0]=task_time[1]=now; }
int main(int argc,char **argv) {
 const char *name=argv[1];
 task.cpu=1; task.pid=42; task.scx.flags=SCX_TASK_QUEUED; task.scx.weight=100;
 taskctx.dsq=get_cpu_dsq_id(1); taskctx.running_accounted_at=1000; taskctx.started_running_at=1000;
 clock_at(1500);
 if(!strcmp(name,"remote-context")) {
  cpus[0].cell=1; mitosis_dispatch(1,&task);
  CHECK(cpus[1].running_ns[0]==500); CHECK(cpus[0].running_ns[0]==0);
 } else if(!strcmp(name,"remote-clock")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  executing=0; clock_at(1500); local_time[0]=500; task_time[0]=500;
  mitosis_dispatch(1,&task);
  CHECK(cpus[0].running_ns[0]+cpus[1].running_ns[0]==500);
  CHECK(cpus[1].running_ns[0]==500);
  CHECK(taskctx.running_accounted_at==1500);
 } else if(!strcmp(name,"remote-subcell")) {
  mitosis_dispatch(1,&task); CHECK(accounts[1][0].running_ns==500); CHECK(accounts[0][0].running_ns==0);
 } else if(!strcmp(name,"queued-clock")) {
  global_time=5000; local_time[0]=1000; mitosis_runnable(&task,0);
  executing=1; global_time=5100; local_time[1]=200; mitosis_running(&task);
  CHECK(accounts[1][0].queued_ns==100); CHECK(taskctx.runnable_at==0);
 } else if(!strcmp(name,"sleep-clock")) {
  global_time=5000; local_time[0]=1000; mitosis_quiescent(&task,0);
  executing=1; global_time=5100; local_time[1]=200; mitosis_runnable(&task,0);
  CHECK(taskctx.window_sleep_ns==100); CHECK(taskctx.quiescent_at==0);
 } else if(!strcmp(name,"error-running-cell")) {
  taskctx.cell=2; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-running-pack")) {
  taskctx.subcell=2; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-running-map")) {
  map_fail=true; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-stopping-map")) {
  executing=1; map_fail=true; taskctx.runnable_at=777; mitosis_stopping(&task,true);
  CHECK(errors); CHECK(taskctx.runnable_at==777);
 } else if(!strcmp(name,"error-quiescent-pack")) {
  taskctx.runnable_at=500; taskctx.quiescent_at=777; taskctx.subcell=2; mitosis_quiescent(&task,0);
  CHECK(errors); CHECK(taskctx.quiescent_at==777); CHECK(taskctx.runnable_at==500);
 } else if(!strcmp(name,"error-quiescent-map")) {
  taskctx.runnable_at=500; taskctx.quiescent_at=777; map_fail=true; mitosis_quiescent(&task,0);
  CHECK(errors); CHECK(taskctx.quiescent_at==777); CHECK(taskctx.runnable_at==500);
 } else if(!strcmp(name,"error-running-queued")) {
  taskctx.runnable_at=500; map_fail=true; executing=1; mitosis_running(&task);
  CHECK(errors); CHECK(taskctx.running_accounted_at==1000); CHECK(taskctx.started_running_at==1000);
 } else if(!strcmp(name,"runtime-excludes-nontask")) {
  executing=1; clock_at(5000000000ULL); task_time[1]=1000;
  mitosis_running(&task);
  clock_at(5000000500ULL); task_time[1]=1350; mitosis_tick(&task);
  CHECK(cpus[1].running_ns[0]==350); CHECK(accounts[1][0].running_ns==350);
  CHECK(taskctx.running_accounted_at==1350);
 } else if(!strcmp(name,"runtime-migration")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  clock_at(1200); mitosis_stopping(&task,true);
  task.cpu=0; executing=0; clock_at(1300); task_time[0]=100;
  mitosis_running(&task); CHECK(taskctx.running_accounted_at==100);
  clock_at(1350); task_time[0]=150; mitosis_stopping(&task,true);
  CHECK(cpus[1].running_ns[0]==200); CHECK(cpus[0].running_ns[0]==50);
  CHECK(accounts[1][0].running_ns==200); CHECK(accounts[0][0].running_ns==50);
 } else if(!strcmp(name,"wall-demand-window")) {
  executing=1; clock_at(1000000); task_time[1]=1000; mitosis_running(&task);
  taskctx.demand_window_at=global_time;
  clock_at(1000000+2*DEMAND_TAU_NS); task_time[1]=1200; mitosis_tick(&task);
  CHECK(taskctx.demand_window_at==global_time); CHECK(taskctx.window_run_ns==0);
 } else if(!strcmp(name,"no-wait")) {
  map_fail=true; mitosis_quiescent(&task,0); CHECK(!errors); CHECK(taskctx.quiescent_at==1500);
 } else if(!strcmp(name,"shared-accounting")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  clock_at(1100); mitosis_tick(&task);
  clock_at(1150); mitosis_dispatch(1,&task);
  clock_at(1200); mitosis_stopping(&task,true);
  CHECK(!errors); CHECK(refills==1); CHECK(cpus[1].running_ns[0]==200);
  CHECK(accounts[1][0].running_ns==200); CHECK(taskctx.runnable_at==1200);
  CHECK(task.scx.dsq_vtime==200);
 } else { return 2; }
 return 0;
}
'''
notice = ('/* SPDX-License-Identifier: GPL-2.0-only */\n'
          '/* Extracted callback bodies: Copyright (c) Meta Platforms, Inc. and affiliates. */\n'
          '/* Source SHA-256: ' + hashlib.sha256(args.source.read_bytes()).hexdigest() + ' */\n')
code = notice + preamble + '\n'.join(extract(n) for n in names) + driver
(out/'accounting-test.c').write_text(code)
subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable',str(out/'accounting-test.c'),'-o',str(out/'accounting-test')],check=True)
cases = re.findall(r'!strcmp\(name,"([^"]+)"\)',driver)
results={}
for case in cases:
    p=subprocess.run([str(out/'accounting-test'),case],capture_output=True,text=True)
    results[case]={'passed':p.returncode==0,'detail':p.stderr.strip()}
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps({k: v['passed'] for k,v in results.items()},indent=2))
