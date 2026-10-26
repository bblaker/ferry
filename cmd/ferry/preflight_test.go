package main

import (
	"strings"
	"testing"

	"github.com/bblaker/ferry/internal/dataplane"
)

func TestCheckSNATPorts(t *testing.T) {
	for _, tc := range []struct {
		name                string
		snat                dataplane.PortRange
		ephemeral, reserved string
		wantErr             string
	}{
		{"above ephemeral", dataplane.PortRange{Min: 61000, Max: 65535}, "32768\t60999", "", ""},
		{"below ephemeral", dataplane.PortRange{Min: 20000, Max: 30000}, "32768\t60999", "", ""},
		{"reserved", dataplane.PortRange{Min: 40000, Max: 59999}, "32768\t60999", "40000-59999\n", ""},
		{"reserved in pieces", dataplane.PortRange{Min: 40000, Max: 40002}, "32768\t60999", "40000,40001-40002", ""},
		{"overlap", dataplane.PortRange{Min: 40000, Max: 59999}, "32768\t60999", "", "overlap"},
		{"partly reserved", dataplane.PortRange{Min: 40000, Max: 59999}, "32768\t60999", "40000-50000", "overlap"},
		{"bad range sysctl", dataplane.PortRange{Min: 1, Max: 2}, "nope", "", "unexpected format"},
		{"bad reserved sysctl", dataplane.PortRange{Min: 1, Max: 2}, "32768 60999", "x-y", "ip_local_reserved_ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSNATPorts(tc.snat, tc.ephemeral, tc.reserved)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestParsePortRange(t *testing.T) {
	if r, err := dataplane.ParsePortRange("40000-59999"); err != nil || r != (dataplane.PortRange{Min: 40000, Max: 59999}) {
		t.Errorf("got %v, %v", r, err)
	}
	for _, bad := range []string{"", "40000", "0-10", "10-5", "1-70000", "a-b"} {
		if _, err := dataplane.ParsePortRange(bad); err == nil {
			t.Errorf("ParsePortRange(%q) accepted", bad)
		}
	}
}
