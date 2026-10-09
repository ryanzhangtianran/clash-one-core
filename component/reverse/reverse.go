// Package reverse runs reverse tunnels (frpc, ssh -R) that expose local services through a remote server.
package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

const retryInterval = 10 * time.Second // ponytail: fixed retry, switch to backoff if servers get hammered

type Tunnel struct {
	Name        string
	DialerProxy string
	hash        string // raw config fingerprint, so a reload only restarts tunnels that changed
	run         func(ctx context.Context)
}

// Parse builds a tunnel from one `reverse-tunnels` entry. tunnel resolves dialer-proxy names
// and routes incoming connections by rules.
func Parse(mapping map[string]any, tunnel C.Tunnel) (*Tunnel, error) {
	name, _ := mapping["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}
	raw, err := json.Marshal(mapping)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var t *Tunnel
	switch typ, _ := mapping["type"].(string); typ {
	case "frp":
		t, err = parseFrp(name, mapping, tunnel)
	case "ssh":
		t, err = parseSSH(name, mapping, tunnel)
	default:
		err = fmt.Errorf("unsupported type %q", typ)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	t.Name, t.hash = name, string(raw)
	return t, nil
}

var (
	mu     sync.Mutex
	active = map[string]*running{}
)

type running struct {
	hash   string
	cancel context.CancelFunc
}

// Patch starts new or changed tunnels and stops removed or changed ones.
func Patch(tunnels []*Tunnel) {
	mu.Lock()
	defer mu.Unlock()
	next := make(map[string]*Tunnel, len(tunnels))
	for _, t := range tunnels {
		next[t.Name] = t
	}
	for name, r := range active {
		if t, ok := next[name]; !ok || t.hash != r.hash {
			log.Infoln("[ReverseTunnel] %s stopped", name)
			r.cancel()
			delete(active, name)
		}
	}
	for name, t := range next {
		if _, ok := active[name]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		active[name] = &running{hash: t.hash, cancel: cancel}
		log.Infoln("[ReverseTunnel] %s starting", name)
		go t.run(ctx)
	}
}

// route hands an incoming connection to mihomo's tunnel, so it is matched by rules
// (IN-TYPE TUNNEL, IN-NAME = tunnel name) like any other inbound.
func route(tunnel C.Tunnel, name string, conn net.Conn, target socks5.Addr, additions ...inbound.Addition) {
	tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.TUNNEL, append(additions, inbound.WithInName(name))...))
}

// retry calls serve until ctx is done, waiting retryInterval after each failure.
func retry(ctx context.Context, name string, serve func(ctx context.Context) error) {
	for {
		err := serve(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Warnln("[ReverseTunnel] %s: %v, retry in %s", name, err, retryInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}
}
