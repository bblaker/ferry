// Command e2etool plays the backends and clients in test/e2e/e2e.sh.
//
//	e2etool serve ADDR...                 TCP and UDP echo servers that name themselves
//	e2etool dial -addr VIP -from IP ...   open N connections, report who answered
//	e2etool hold -addr VIP -from IP ...   keep one connection open across a restart
//	e2etool xdp-pass IFACE                attach an XDP_PASS program until killed
//
// Servers answer each line (TCP) or datagram (UDP) with
// "<server addr> <client addr as seen by the server>".
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e2etool serve|dial|hold|xdp-pass ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "dial":
		err = dial(os.Args[2:])
	case "hold":
		err = hold(os.Args[2:])
	case "xdp-pass":
		err = xdpPass(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2etool:", err)
		os.Exit(1)
	}
}

func serve(addrs []string) error {
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return err
		}
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					r := bufio.NewReader(c)
					for {
						if _, err := r.ReadString('\n'); err != nil {
							return
						}
						fmt.Fprintf(c, "%s %s\n", a, c.RemoteAddr())
					}
				}()
			}
		}()
		go func() {
			buf := make([]byte, 1500)
			for {
				_, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo(fmt.Appendf(nil, "%s %s\n", a, from), from)
			}
		}()
	}
	select {}
}

// answer is a parsed server reply.
type answer struct{ server, seen string }

func parse(line string) (answer, error) {
	f := strings.Fields(line)
	if len(f) != 2 {
		return answer{}, fmt.Errorf("unexpected reply %q", line)
	}
	return answer{f[0], f[1]}, nil
}

func dial(args []string) error {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := fs.String("addr", "", "VIP:port")
	from := fs.String("from", "", "client source address")
	proto := fs.String("proto", "tcp", "tcp or udp")
	n := fs.Int("n", 50, "connections (TCP) or sockets (UDP), each a new flow")
	wantServers := fs.Int("want-servers", 0, "fail unless this many distinct servers answered")
	wantSeen := fs.String("want-seen", "", "fail unless every server saw this client address (the SNAT address)")
	fs.Parse(args)

	counts := map[string]int{}
	for i := range *n {
		a, err := once(*proto, *addr, *from)
		if err != nil {
			return fmt.Errorf("%s flow %d: %w", *proto, i, err)
		}
		if *wantSeen != "" {
			if ap, err := netip.ParseAddrPort(a.seen); err != nil || ap.Addr().String() != *wantSeen {
				return fmt.Errorf("server %s saw client %s, want %s", a.server, a.seen, *wantSeen)
			}
		}
		counts[a.server]++
	}
	var servers []string
	for s := range counts {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	for _, s := range servers {
		fmt.Printf("  %s %d\n", s, counts[s])
	}
	if *wantServers > 0 && len(counts) != *wantServers {
		return fmt.Errorf("%d servers answered, want %d", len(counts), *wantServers)
	}
	return nil
}

func once(proto, addr, from string) (answer, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	if proto == "udp" {
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(from)}
	} else {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	c, err := d.Dial(proto, addr)
	if err != nil {
		return answer{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(c, "hi"); err != nil {
		return answer{}, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return answer{}, err
	}
	return parse(line)
}

// hold opens one TCP connection, reports which server answered to -ready,
// waits for -go to exist, then checks the same connection still reaches the
// same server.
func hold(args []string) error {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	addr := fs.String("addr", "", "VIP:port")
	from := fs.String("from", "", "client source address")
	ready := fs.String("ready", "", "file to write the server's address to once connected")
	goFile := fs.String("go", "", "file whose appearance means: send the second request")
	fs.Parse(args)

	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(*from)}}
	c, err := d.Dial("tcp", *addr)
	if err != nil {
		return err
	}
	defer c.Close()
	r := bufio.NewReader(c)
	ask := func() (answer, error) {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintln(c, "hi"); err != nil {
			return answer{}, err
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return answer{}, err
		}
		return parse(line)
	}
	first, err := ask()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*ready, []byte(first.server+"\n"), 0o644); err != nil {
		return err
	}
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(*goFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", *goFile)
		}
	}
	second, err := ask()
	if err != nil {
		return fmt.Errorf("held connection broke: %w", err)
	}
	if second != first {
		return fmt.Errorf("held connection moved from %v to %v", first, second)
	}
	fmt.Printf("  held connection to %s survived\n", first.server)
	return nil
}
