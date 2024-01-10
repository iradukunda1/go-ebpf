#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	char comm[128];
	char filename[128];
} chroot_event_t;

BPF_PERF_OUTPUT(chroot_events);

int kprobe__sys_chroot(struct pt_regs *ctx, const char *filename)
{
	u64 pid = bpf_get_current_pid_tgid();
	chroot_event_t event = {
		.pid = pid >> 32,
	};
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
	chroot_events.perf_submit(ctx, &event, sizeof(event));
	return 0;
}