//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// xdpPass attaches a program that passes every packet to the named veth and
// holds it until killed. A veth only receives native XDP_TX/redirected
// frames from its peer when it has XDP enabled itself.
func xdpPass(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: xdp-pass IFACE")
	}
	ifc, err := net.InterfaceByName(args[0])
	if err != nil {
		return err
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.XDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}, // XDP_PASS
		License:      "GPL",
	})
	if err != nil {
		return err
	}
	defer prog.Close()
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifc.Index, Flags: link.XDPDriverMode})
	if err != nil {
		return err
	}
	defer l.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	<-sig
	return nil
}
