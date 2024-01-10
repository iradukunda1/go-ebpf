package v4

import (
	"fmt"
	"os"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const bpfText = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>


BPF_HASH(currsock, u32, struct sock *);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk){
    
	u32 pid = bpf_get_current_pid_tgid();
    
	// stash the sock ptr for lookup on return
    currsock.update(&pid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver){
    int ret = ctx->ax;
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }
    // pull in details
    struct sock *skp = *skpp;
}
`

func V4() {

	m := bpf.NewModule(bpfText, []string{})
	defer m.Close()

	connectEntryKprobe, err := m.LoadKprobe("trace_connect_entry")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_entry: %v\n", err)
		os.Exit(1)
	}

	connectReturnKprobe, err := m.LoadKprobe("trace_connect_return")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_connect_return: %v\n", err)
		os.Exit(1)
	}

	err = m.AttachKprobe("tcp_v4_connect", connectEntryKprobe, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_connect_entry: %v\n", err)
		os.Exit(1)
	}

	err = m.AttachKretprobe("tcp_v4_connect", connectReturnKprobe, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_connect_return: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Tracing TCP connects...")

	table := bpf.NewTable(m.TableId("currsock"), m)
	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %v\n", err)
		os.Exit(1)
	}

	go func() {
		for {
			data := <-channel
			key := *(*uint32)(unsafe.Pointer(&data[0]))
			value := *(*uint64)(unsafe.Pointer(&data[4]))
			fmt.Printf("PID: %d, Socket: %d\n", key, value)
		}
	}()

	perfMap.Start()
	defer perfMap.Stop()

	select {}
}
