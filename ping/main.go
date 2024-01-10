package main

/*
#cgo CFLAGS: -I./cmd
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iradukunda1/go-ebpf/pkg"
)

const (
	xdpProgramPath  = "cmd/ping.bpf.c"
	interfaceName   = "lo"
	xdpFunctionName = "xdp"
)

func main() {

	srcCode, err := pkg.ReadbpfCode(xdpProgramPath)
	if err != nil {
		fmt.Println("Error reading ebpf source file:", err)
		os.Exit(1)
		return
	}

	module := bcc.NewModule(string(srcCode), []string{})
	defer module.Close()

	xdpFunction, err := module.LoadKprobe(xdpFunctionName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading XDP function: %v\n", err)
		os.Exit(1)
	}

	if err := module.AttachXDP(interfaceName, xdpFunction); err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching XDP program to interface: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("XDP program attached. Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	if err := module.RemoveXDP(interfaceName); err != nil {
		fmt.Fprintf(os.Stderr, "Error detaching XDP program from interface: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("XDP program detached.")
}
