package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iradukunda1/go-ebpf/pkg"
)

import "C"

type chrootEvent struct {
	Pid      uint32
	Comm     [128]byte
	Filename [128]byte
}

const chrootProgramPath = "chroot/chroot.bpf.c"

func main() {

	srcCode, err := pkg.ReadbpfCode(chrootProgramPath)
	if err != nil {
		fmt.Println("Error reading ebpf source file:", err)
		os.Exit(1)
		return
	}

	m := bcc.NewModule(string(srcCode), []string{})
	defer m.Close()

	chrootKprobe, err := m.LoadKprobe("kprobe__sys_chroot")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kprobe__sys_chroot: %s\n", err)
		os.Exit(1)
	}

	// m.AttachKretprobe("sys_chroot", chrootKprobe, -1)

	//I have to use __x64_sys_execve because sys_chroot it is no longer exported to kallsyms so this is the regex to find it
	err = m.AttachKprobe("__x64_sys_execve", chrootKprobe, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kprobe__sys_chroot: %s\n", err)
		os.Exit(1)
	}

	chrootEventsTable := bcc.NewTable(0, m)

	chrootEventsChannel := make(chan []byte)
	chrootUint := make(chan uint64)

	chrootPerfMap, err := bcc.InitPerfMap(chrootEventsTable, chrootEventsChannel, chrootUint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		var chrootE chrootEvent
		for {
			data := <-chrootEventsChannel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &chrootE)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decode received chroot event data: %s\n", err)
				continue
			}
			comm := (*C.char)(unsafe.Pointer(&chrootE.Comm[0]))
			filename := (*C.char)(unsafe.Pointer(&chrootE.Filename[0]))
			fmt.Printf("pid %d application %s called chroot(2) on %s\n", chrootE.Pid, C.GoString(comm), C.GoString(filename))
		}
	}()

	chrootPerfMap.Start()
	<-sig
	chrootPerfMap.Stop()
}
