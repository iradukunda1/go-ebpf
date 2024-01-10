// sudo ./tcpV4 -p 1234
// writte c code to trace tcp connect and disconnect
// use bcc to compile and run

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


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
    u32
}