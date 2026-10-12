package outboundgroup

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// The root daemon switches ipconfig to verbose at startup, so its `ipconfig getsummary` shows the
// SSID and BSSID that macOS otherwise redacts.
func init() {
	if os.Geteuid() == 0 {
		go exec.Command("ipconfig", "setverbose", "1").Run()
	}
}

// CurrentNetwork reads the default route and `ipconfig getsummary` for its interface. Only the root
// daemon sees SSID and BSSID; a user-level core gets them redacted, so only ROUTER, CIDR and TYPE
// rules match there.
func CurrentNetwork() Network {
	var n Network
	route, _ := exec.Command("route", "-n", "get", "default").Output()
	iface := field(string(route), "interface", 0)
	n.Router = field(string(route), "gateway", 0)
	if iface == "" {
		return n
	}
	if ifc, err := net.InterfaceByName(iface); err == nil {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				n.Addrs = append(n.Addrs, p.Addr())
			}
		}
	}
	out, _ := exec.Command("ipconfig", "getsummary", iface).Output()
	sum := string(out)
	n.WiFi = field(sum, "InterfaceType", 2) == "WiFi"
	n.Wired = !n.WiFi
	if v := field(sum, "SSID", 2); v != "<redacted>" {
		n.SSID = v
	}
	if v := field(sum, "BSSID", 2); v != "<redacted>" {
		n.BSSID = v
	}
	return n
}

// field finds "key : value" (or "key: value") on a line indented by exactly indent spaces.
func field(out, key string, indent int) string {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if len(line)-len(trimmed) != indent && indent > 0 {
			continue
		}
		if k, v, ok := strings.Cut(trimmed, ":"); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
