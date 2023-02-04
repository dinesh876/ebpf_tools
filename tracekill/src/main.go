package main

import (
	"log"
	"time"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-10  bpf ./bpf/tracekill.c -- -I ./headers
const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/syscalls/syscall_enter_kill
	//bpf_kill_trace: BpfKillTrace
	kp, err := link.Tracepoint("syscalls", "sys_enter_kill", objs.BpfKillTrace,nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	log.Println("Waiting for events..")
	var key int64
	var  prevkey int64
	time.Sleep(30 * time.Second)
	for {
        	if err:=objs.KillMap.NextKey(prevkey,&key); err != nil {
	               continue
		}
		log.Printf("%v  was forcefully killed",key)

	      prevkey =  key
	      //log.Printf("%v - %v",key,prevkey)
       }
}
