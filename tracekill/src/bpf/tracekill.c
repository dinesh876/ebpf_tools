#include "common.h"
#include <stdlib.h>

#define  SIGKILL 9 

// Defining Map 
//
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __type(key,long);
    __type(value,char);
    __uint(max_entries,64);

} kill_map SEC(".maps");



// /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
/*
 * field:int common_pid;   offset:4;       size:4; signed:1;
 * field:int __syscall_nr; offset:8;       size:4; signed:1;
 * field:pid_t pid;        offset:16;      size:8; signed:0;
 * field:int sig;  offset:24;      size:8; signed:0;
*/

struct syscalls_enter_kill_args {
  long long pad;

  long syscall_nr;
  long pid;
  long sig;
};

SEC("tracepoint/syscalls/sys_enter_kill")
int bpf_kill_trace(struct syscalls_enter_kill_args *ctx){

  if(ctx->sig != SIGKILL){
       return 0;
   }
   
   long key = labs(ctx->pid);
   long value = 1;

   bpf_map_update_elem(&kill_map,&key,&value,BPF_NOEXIST);
   return 0;
}

char _license[] SEC("license") = "GPL";
