package outboundgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// SubnetOption picks a member by the network this machine is on, like Surge's subnet groups.
// Rules map "SSID:name", "BSSID:mac", "ROUTER:ip", a CIDR holding a local address, or
// "TYPE:WIFI" / "TYPE:WIRED" to a member; default applies when none matches.
type SubnetOption struct {
	Default string            `group:"default"`
	Rules   map[string]string `group:"rules,omitempty"`
}

// Subnet follows the network on its own: it can't be selected by hand.
type Subnet struct {
	*GroupBase
	def        string
	rules      map[string]string
	disableUDP bool

	mu      sync.Mutex
	checked time.Time
	current string
}

func NewSubnet(option GroupCommonOption, opt SubnetOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*Subnet, error) {
	if opt.Default == "" {
		return nil, fmt.Errorf("%s: subnet group needs a default", option.Name)
	}
	return &Subnet{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Subnet,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		def:        opt.Default,
		rules:      opt.Rules,
		disableUDP: option.DisableUDP,
	}, nil
}

// subnetMembers is a subnet group's member list when it gives none: default, then every rule target.
func subnetMembers(config map[string]any) []any {
	members := []any{}
	add := func(v any) {
		if s, ok := v.(string); ok && s != "" && !slices.Contains(members, any(s)) {
			members = append(members, s)
		}
	}
	add(config["default"])
	rules, _ := config["rules"].(map[string]any)
	for _, k := range slices.Sorted(maps.Keys(rules)) {
		add(rules[k])
	}
	return members
}

// Network is what subnet rules match on, also served as the controller's GET /network; empty
// fields are unknown.
type Network struct {
	SSID   string       `json:"ssid"`
	BSSID  string       `json:"bssid"`
	Router string       `json:"router"`
	WiFi   bool         `json:"wifi"`
	Wired  bool         `json:"-"`
	Addrs  []netip.Addr `json:"-"`
}

// matchNetwork returns the target of the first matching rule, checking SSID, then BSSID, router,
// local subnet and interface type; def when none matches.
func matchNetwork(n Network, rules map[string]string, def string) string {
	keys := slices.Sorted(maps.Keys(rules))
	passes := []func(key string) bool{
		func(k string) bool { return n.SSID != "" && k == "SSID:"+n.SSID },
		func(k string) bool { return n.BSSID != "" && strings.EqualFold(k, "BSSID:"+n.BSSID) },
		func(k string) bool { return n.Router != "" && k == "ROUTER:"+n.Router },
		func(k string) bool {
			p, err := netip.ParsePrefix(k)
			return err == nil && slices.ContainsFunc(n.Addrs, p.Contains)
		},
		func(k string) bool { return k == "TYPE:WIFI" && n.WiFi || k == "TYPE:WIRED" && n.Wired },
	}
	for _, match := range passes {
		for _, k := range keys {
			if match(k) {
				return rules[k]
			}
		}
	}
	return def
}

// target is the member for the current network, re-read at most every 5s.
// ponytail: polled lazily on use; subscribe to SCDynamicStore network changes if 5s lag matters.
func (s *Subnet) target() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.checked) > 5*time.Second {
		s.checked = time.Now()
		s.current = matchNetwork(CurrentNetwork(), s.rules, s.def)
	}
	return s.current
}

func (s *Subnet) selectedProxy(touch bool) C.Proxy {
	proxies := s.GetProxies(touch)
	name := s.target()
	for _, p := range proxies {
		if p.Name() == name {
			return p
		}
	}
	return proxies[0]
}

// DialContext implements C.ProxyAdapter
func (s *Subnet) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := s.selectedProxy(true).DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(s)
	}
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Subnet) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := s.selectedProxy(true).ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(s)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (s *Subnet) SupportUDP() bool {
	return !s.disableUDP && s.selectedProxy(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (s *Subnet) IsL3Protocol(metadata *C.Metadata) bool {
	return s.selectedProxy(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (s *Subnet) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range s.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":    s.Type().String(),
		"now":     s.Now(),
		"all":     all,
		"default": s.def,
		"rules":   s.rules,
		"hidden":  s.Hidden(),
		"icon":    s.Icon(),
	})
}

func (s *Subnet) Now() string { return s.selectedProxy(false).Name() }

// Unwrap implements C.ProxyAdapter
func (s *Subnet) Unwrap(metadata *C.Metadata, touch bool) C.Proxy { return s.selectedProxy(touch) }

func (s *Subnet) Providers() []P.ProxyProvider { return s.providers }

func (s *Subnet) Proxies() []C.Proxy { return s.GetProxies(false) }
