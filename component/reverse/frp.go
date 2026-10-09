package reverse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	frpclient "github.com/fatedier/frp/client"
	frpconfig "github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	frplog "github.com/fatedier/frp/pkg/util/log"
	golog "github.com/fatedier/golib/log"
	"github.com/samber/lo"
)

type frpOption struct {
	DialerProxy string         `proxy:"dialer-proxy,omitempty"`
	Config      map[string]any `proxy:"config"` // native frpc v1 config (serverAddr, auth, proxies, ...)
}

func parseFrp(mapping map[string]any, tunnel C.Tunnel) (*Tunnel, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := frpOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return nil, err
	}
	if len(opt.Config) == 0 {
		return nil, errors.New("config is empty")
	}
	b, err := json.Marshal(opt.Config)
	if err != nil {
		return nil, err
	}
	res, err := frpconfig.LoadClientConfigResultFromBytes(b, true)
	if err != nil {
		return nil, err
	}
	common := res.Common
	common.LoginFailExit = lo.ToPtr(false) // keep retrying like any other mihomo component
	// frp falls back to $http_proxy, which usually points at mihomo itself; only honor an explicit proxyURL.
	if transport, _ := opt.Config["transport"].(map[string]any); transport["proxyURL"] == nil {
		common.Transport.ProxyURL = ""
	}

	proxies, visitors := frpconfig.FilterClientConfigurers(common, res.Proxies, res.Visitors)
	proxies = frpconfig.CompleteProxyConfigurers(proxies)
	visitors = frpconfig.CompleteVisitorConfigurers(visitors)
	if _, err := validation.ValidateAllClientConfig(common, proxies, visitors, nil); err != nil {
		return nil, err
	}

	// The mihomo dialer carries tcp/websocket/wss; quic and kcp dial on their own.
	var connectorCreator func(context.Context, *v1.ClientCommonConfig) frpclient.Connector
	switch proto := common.Transport.Protocol; {
	case proto == "quic" || proto == "kcp":
		if opt.DialerProxy != "" {
			return nil, fmt.Errorf("dialer-proxy does not support frp transport.protocol %s", proto)
		}
	case common.Transport.ProxyURL != "":
		if opt.DialerProxy != "" {
			return nil, errors.New("dialer-proxy and transport.proxyURL are mutually exclusive")
		}
	default:
		d := newDialer(opt.DialerProxy, tunnel)
		connectorCreator = func(ctx context.Context, cfg *v1.ClientCommonConfig) frpclient.Connector {
			return frpclient.NewConnectorWithDialer(ctx, cfg, d.DialContext)
		}
	}

	name, _ := mapping["name"].(string)
	return &Tunnel{DialerProxy: opt.DialerProxy, run: func(ctx context.Context) {
		initFrpLog()
		retry(ctx, name, func(ctx context.Context) error {
			src := source.NewConfigSource()
			if err := src.ReplaceAll(res.Proxies, res.Visitors); err != nil {
				return err
			}
			svc, err := frpclient.NewService(frpclient.ServiceOptions{
				Common:                 common,
				ConfigSourceAggregator: source.NewAggregator(src),
				ConnectorCreator:       connectorCreator,
			})
			if err != nil {
				return err
			}
			return svc.Run(ctx)
		})
	}}, nil
}

var frpLogOnce sync.Once

// initFrpLog routes frp's global logger into mihomo's log; mihomo's log-level does the filtering.
func initFrpLog() {
	frpLogOnce.Do(func() {
		frplog.Logger = frplog.Logger.WithOptions(
			golog.WithOutput(frpLogWriter{}),
			golog.WithLevel(golog.DebugLevel),
			golog.WithCaller(false),
		)
	})
}

type frpLogWriter struct{}

// Write parses golib lines like "2006-01-02 15:04:05.000 [I] msg".
func (frpLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	level, msg := byte('I'), line
	if i := strings.Index(line, " ["); i >= 0 && len(line) > i+4 && line[i+3] == ']' {
		level, msg = line[i+2], strings.TrimSpace(line[i+4:])
	}
	switch level {
	case 'E':
		log.Errorln("[FRP] %s", msg)
	case 'W':
		log.Warnln("[FRP] %s", msg)
	case 'D', 'T':
		log.Debugln("[FRP] %s", msg)
	default:
		log.Infoln("[FRP] %s", msg)
	}
	return len(p), nil
}
