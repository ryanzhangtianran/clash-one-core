package reverse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

const sshKeepAlive = 30 * time.Second

// sshOption reuses the ssh outbound options (auth, host-key, dialer-proxy) plus the -R forwards.
type sshOption struct {
	outbound.SshOption
	Forwards []sshForward `proxy:"forwards"`
}

type sshForward struct {
	Remote string      `proxy:"remote"` // address the SSH server listens on, e.g. 0.0.0.0:8080 (needs GatewayPorts for non-loopback)
	Local  string      `proxy:"local"`  // target routed by rules, e.g. 127.0.0.1:80
	target socks5.Addr `proxy:"-"`
}

func parseSSH(name string, mapping map[string]any, tunnel C.Tunnel) (*Tunnel, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := sshOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return nil, err
	}
	if len(opt.Forwards) == 0 {
		return nil, errors.New("forwards is empty")
	}
	for i, f := range opt.Forwards {
		if _, _, err := net.SplitHostPort(f.Remote); err != nil {
			return nil, fmt.Errorf("invalid forward remote %q: %w", f.Remote, err)
		}
		if opt.Forwards[i].target = socks5.ParseAddr(f.Local); opt.Forwards[i].target == nil {
			return nil, fmt.Errorf("invalid forward local %q", f.Local)
		}
	}
	opt.TunnelForAPI = tunnel
	out, err := outbound.NewSsh(opt.SshOption)
	if err != nil {
		return nil, err
	}
	return &Tunnel{DialerProxy: opt.DialerProxy, run: func(ctx context.Context) {
		defer out.Close()
		retry(ctx, name, func(ctx context.Context) error { return serveSSH(ctx, name, out, opt.Forwards, tunnel) })
	}}, nil
}

// serveSSH holds one SSH session with all forwards until the session dies or ctx is done.
func serveSSH(ctx context.Context, name string, out *outbound.Ssh, forwards []sshForward, tunnel C.Tunnel) error {
	client, err := out.Client(ctx)
	if err != nil {
		return err
	}
	defer client.Close() // also closes every remote listener below
	defer context.AfterFunc(ctx, func() { client.Close() })()
	for _, f := range forwards {
		ln, err := client.Listen("tcp", f.Remote)
		if err != nil {
			return fmt.Errorf("remote listen %s: %w", f.Remote, err)
		}
		go acceptLoop(tunnel, name, ln, f.target)
		log.Infoln("[ReverseTunnel] %s: remote %s -> local %s", name, f.Remote, f.Local)
	}

	ticker := time.NewTicker(sshKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		// closing the client (on timeout or ctx cancel) unblocks a hung request
		timeout := time.AfterFunc(sshKeepAlive, func() { client.Close() })
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		timeout.Stop()
		if err != nil {
			return fmt.Errorf("keepalive: %w", err)
		}
	}
}

func acceptLoop(tunnel C.Tunnel, name string, ln net.Listener, target socks5.Addr) {
	for {
		c, err := ln.Accept() // RemoteAddr is the originating user, so SRC-IP rules work
		if err != nil {
			return
		}
		go route(tunnel, name, c, target)
	}
}
