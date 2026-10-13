package discovery

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/bblaker/ferry/internal/dataplane"
)

func TestExampleConfigLoads(t *testing.T) {
	for _, path := range []string{"../../deploy/ferry.example.json"} {
		svcs, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(svcs) == 0 {
			t.Errorf("%s: no services", path)
		}
	}
}

func TestParse(t *testing.T) {
	svcs, err := Parse([]byte(`{"services": [
		{"name": "web", "vip": "192.168.1.240:443", "backends": ["10.0.0.1:8443", "10.0.0.2:8443"]},
		{"name": "dns", "vip": "192.168.1.240:53", "proto": "UDP", "backends": []}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Service{
		{
			Name:     "web",
			Key:      dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: dataplane.TCP},
			Backends: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:8443"), netip.MustParseAddrPort("10.0.0.2:8443")},
		},
		{
			Name: "dns",
			Key:  dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 53, Proto: dataplane.UDP},
		},
	}
	if len(svcs) != len(want) {
		t.Fatalf("got %d services, want %d", len(svcs), len(want))
	}
	for i := range want {
		g, w := svcs[i], want[i]
		if g.Name != w.Name || g.Key != w.Key || len(g.Backends) != len(w.Backends) {
			t.Errorf("service %d = %+v, want %+v", i, g, w)
			continue
		}
		for j := range w.Backends {
			if g.Backends[j] != w.Backends[j] {
				t.Errorf("service %d backend %d = %s, want %s", i, j, g.Backends[j], w.Backends[j])
			}
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, tc := range []struct{ name, json, wantErr string }{
		{"not json", `{`, "unexpected EOF"},
		{"trailing data", `{"services": []} {}`, "after the top-level object"},
		{"misspelled field", `{"services": [{"name": "a", "vip": "1.2.3.4:80", "backend": ["10.0.0.1:80"]}]}`, `unknown field "backend"`},
		{"no name", `{"services": [{"vip": "1.2.3.4:80"}]}`, "name is required"},
		{"duplicate name", `{"services": [{"name": "a", "vip": "1.2.3.4:80"}, {"name": "a", "vip": "1.2.3.4:81"}]}`, "duplicate name"},
		{"duplicate vip", `{"services": [{"name": "a", "vip": "1.2.3.4:80"}, {"name": "b", "vip": "1.2.3.4:80", "proto": "tcp"}]}`, `already used by "a"`},
		{"bad vip", `{"services": [{"name": "a", "vip": "1.2.3.4"}]}`, "vip"},
		{"ipv6 vip", `{"services": [{"name": "a", "vip": "[::1]:80"}]}`, "only IPv4"},
		{"port 0", `{"services": [{"name": "a", "vip": "1.2.3.4:0"}]}`, "port 0"},
		{"unspecified", `{"services": [{"name": "a", "vip": "0.0.0.0:80"}]}`, "not a unicast"},
		{"multicast", `{"services": [{"name": "a", "vip": "239.1.1.1:80"}]}`, "not a unicast"},
		{"bad proto", `{"services": [{"name": "a", "vip": "1.2.3.4:80", "proto": "sctp"}]}`, "unknown proto"},
		{"ipv6 backend", `{"services": [{"name": "a", "vip": "1.2.3.4:80", "backends": ["[fd00::1]:80"]}]}`, "only IPv4"},
		{"backend port 0", `{"services": [{"name": "a", "vip": "1.2.3.4:80", "backends": ["10.0.0.1:0"]}]}`, "port 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
