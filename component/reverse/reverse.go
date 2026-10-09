// Package reverse runs reverse tunnels (frpc, ssh -R) that expose local services through a remote server.
package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const retryInterval = 10 * time.Second // ponytail: fixed retry, switch to backoff if servers get hammered

const (
	StateConnecting = "connecting"
	StateRunning    = "running"
	StateRetrying   = "retrying"
)

type Tunnel struct {
	Name        string
	Type        string
	DialerProxy string
	hash        string // raw config fingerprint, so a reload only restarts tunnels that changed
	run         func(ctx context.Context)
	detail      func(s *Status) // fills Forwards, may refine State

	mu    sync.Mutex
	state Status // State/Error/Since, set by retry
}

// Status is a tunnel's live state, served by GET /reverse-tunnels.
type Status struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	State    string          `json:"state"`
	Error    string          `json:"error,omitempty"`
	Since    time.Time       `json:"since"`
	Forwards []ForwardStatus `json:"forwards"`
}

type ForwardStatus struct {
	Name   string `json:"name,omitempty"` // frp proxy name
	Type   string `json:"type,omitempty"` // frp proxy type
	Remote string `json:"remote,omitempty"`
	Local  string `json:"local"`
	State  string `json:"state,omitempty"` // frp proxy phase
	Error  string `json:"error,omitempty"`
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
	t := &Tunnel{Name: name, hash: string(raw)}
	switch t.Type, _ = mapping["type"].(string); t.Type {
	case "frp":
		err = parseFrp(t, mapping, tunnel)
	case "ssh":
		err = parseSSH(t, mapping, tunnel)
	default:
		err = fmt.Errorf("unsupported type %q", t.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return t, nil
}

func (t *Tunnel) setState(state string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.State != state {
		t.state.Since = time.Now()
	}
	t.state.State, t.state.Error = state, ""
	if err != nil {
		t.state.Error = err.Error()
	}
}

func (t *Tunnel) Status() Status {
	t.mu.Lock()
	s := t.state
	t.mu.Unlock()
	s.Name, s.Type = t.Name, t.Type
	t.detail(&s)
	return s
}

// retry calls serve until ctx is done, waiting retryInterval after each failure.
// serve calls up once its session is established.
func (t *Tunnel) retry(ctx context.Context, serve func(ctx context.Context, up func()) error) {
	for {
		t.setState(StateConnecting, nil)
		err := serve(ctx, func() { t.setState(StateRunning, nil) })
		if ctx.Err() != nil {
			return
		}
		t.setState(StateRetrying, err)
		log.Warnln("[ReverseTunnel] %s: %v, retry in %s", t.Name, err, retryInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryInterval):
		}
	}
}

var (
	mu     sync.Mutex
	active = map[string]*running{}
)

type running struct {
	tunnel *Tunnel
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
		if t, ok := next[name]; !ok || t.hash != r.tunnel.hash {
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
		active[name] = &running{tunnel: t, cancel: cancel}
		log.Infoln("[ReverseTunnel] %s starting", name)
		go t.run(ctx)
	}
}

// Statuses reports every active tunnel, sorted by name.
func Statuses() []Status {
	mu.Lock()
	tunnels := make([]*Tunnel, 0, len(active))
	for _, r := range active {
		tunnels = append(tunnels, r.tunnel)
	}
	mu.Unlock()
	slices.SortFunc(tunnels, func(a, b *Tunnel) int { return strings.Compare(a.Name, b.Name) })
	statuses := make([]Status, len(tunnels))
	for i, t := range tunnels {
		statuses[i] = t.Status()
	}
	return statuses
}
