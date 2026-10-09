package reverse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const sshKeepAlive = 30 * time.Second

// sshOption reuses the ssh outbound options (auth, host-key, dialer-proxy) plus the -R forwards.
type sshOption struct {
	outbound.SshOption
	Forwards []sshForward `proxy:"forwards"`
}

type sshForward struct {
	Remote string `proxy:"remote"` // address the SSH server listens on, e.g. 0.0.0.0:8080 (needs GatewayPorts for non-loopback)
	Local  string `proxy:"local"`  // local target, e.g. 127.0.0.1:80
}

func parseSSH(mapping map[string]any, tunnel C.Tunnel) (*Tunnel, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := sshOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return nil, err
	}
	if len(opt.Forwards) == 0 {
		return nil, errors.New("forwards is empty")
	}
	for _, f := range opt.Forwards {
		for _, addr := range []string{f.Remote, f.Local} {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				return nil, fmt.Errorf("invalid forward address %q: %w", addr, err)
			}
		}
	}
	opt.TunnelForAPI = tunnel
	out, err := outbound.NewSsh(opt.SshOption)
	if err != nil {
		return nil, err
	}
	name := opt.Name
	return &Tunnel{DialerProxy: opt.DialerProxy, run: func(ctx context.Context) {
		defer out.Close()
		retry(ctx, name, func(ctx context.Context) error { return serveSSH(ctx, name, out, opt.Forwards) })
	}}, nil
}

// serveSSH holds one SSH session with all forwards until the session dies or ctx is done.
func serveSSH(ctx context.Context, name string, out *outbound.Ssh, forwards []sshForward) error {
	client, err := out.Client(ctx)
	if err != nil {
		return err
	}
	defer client.Close() // also closes every remote listener below
	for _, f := range forwards {
		ln, err := client.Listen("tcp", f.Remote)
		if err != nil {
			return fmt.Errorf("remote listen %s: %w", f.Remote, err)
		}
		go acceptLoop(ctx, name, ln, f.Local)
		log.Infoln("[ReverseTunnel] %s: remote %s -> local %s", name, f.Remote, f.Local)
	}

	ticker := time.NewTicker(sshKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			errCh := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				errCh <- err
			}()
			select {
			case err := <-errCh:
				if err != nil {
					return fmt.Errorf("keepalive: %w", err)
				}
			case <-time.After(sshKeepAlive):
				return errors.New("keepalive timeout")
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func acceptLoop(ctx context.Context, name string, ln net.Listener, local string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			lc, err := dialer.DialContext(ctx, "tcp", local)
			if err != nil {
				c.Close()
				log.Warnln("[ReverseTunnel] %s: dial local %s: %v", name, local, err)
				return
			}
			N.Relay(c, lc)
		}()
	}
}
