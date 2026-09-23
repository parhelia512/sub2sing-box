package parser

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/bestnite/sub2sing-box/constant"
	"github.com/bestnite/sub2sing-box/model"
	"github.com/sagernet/sing-box/option"
)

// ParseTUIC 解析 TUIC v5 分享链接：
// tuic://<uuid>:<password>@<host>:<port>?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=...#<label>
// TUIC 跑在 QUIC 上，TLS 必须开启；utls/reality 在 QUIC 上不适用，链接里带 fp 也不写入出站。
func ParseTUIC(proxy string) (model.Outbound, error) {
	if !strings.HasPrefix(proxy, constant.TUICPrefix) {
		return model.Outbound{}, &ParseError{Type: ErrInvalidPrefix, Raw: proxy}
	}

	link, err := url.Parse(proxy)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidStruct,
			Message: "url parse error",
			Raw:     proxy,
		}
	}

	server := link.Hostname()
	if server == "" {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidStruct,
			Message: "missing server host",
			Raw:     proxy,
		}
	}
	portStr := link.Port()
	port, err := ParsePort(portStr)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidPort,
			Message: err.Error(),
			Raw:     proxy,
		}
	}

	uuid := link.User.Username()
	if uuid == "" {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidStruct,
			Message: "missing uuid",
			Raw:     proxy,
		}
	}
	password, _ := link.User.Password()

	query := link.Query()
	// 枚举值不合法时丢弃而不是改写：写着 quic 却被换成 native，用户会以为链接生效了。
	congestionControl := query.Get("congestion_control")
	if !slices.Contains([]string{"cubic", "new_reno", "bbr"}, congestionControl) {
		congestionControl = ""
	}
	udpRelayMode := query.Get("udp_relay_mode")
	if !slices.Contains([]string{"native", "quic"}, udpRelayMode) {
		udpRelayMode = ""
	}

	remarks := link.Fragment
	if remarks == "" {
		remarks = fmt.Sprintf("%s:%s", server, portStr)
	}
	remarks = strings.TrimSpace(remarks)

	outboundOptions := option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     server,
			ServerPort: port,
		},
		UUID:              uuid,
		Password:          password,
		CongestionControl: congestionControl,
		UDPRelayMode:      udpRelayMode,
		ZeroRTTHandshake:  queryGetBool(query, "zero_rtt_handshake", "reduce_rtt"),
		Heartbeat:         parseDuration(query.Get("heartbeat")),
	}
	outboundOptions.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: query.Get("sni"),
			ALPN:       splitCSV(query.Get("alpn")),
			Insecure:   queryGetBool(query, "allow_insecure", "insecure", "allowInsecure"),
			DisableSNI: queryGetBool(query, "disable_sni"),
		},
	}

	return model.Outbound{
		Type:    constant.TypeTUIC,
		Tag:     remarks,
		Options: outboundOptions,
	}, nil
}
