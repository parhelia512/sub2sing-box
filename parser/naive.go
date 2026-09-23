package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bestnite/sub2sing-box/constant"
	"github.com/bestnite/sub2sing-box/model"
	"github.com/sagernet/sing-box/option"
)

// ParseNaive 解析 NaïveProxy 分享链接（DuckSoft 约定，NekoBox / v2rayN / Hiddify 同款）：
//
//	naive+https://<user>:<pass>@<host>:<port>/?extra-headers=...#<label>
//	naive+quic://<user>:<pass>@<host>:<port>/#<label>
//
// userinfo 的冒号决定语义：`pass@host` 是仅密码，`user:@host` 是仅用户名，`user:pass@host` 是两者都有。
// naive 出站只接受 TLS 的 enabled / server_name / certificate 等少数字段，链接里的 alpn、insecure、
// utls、reality 一律不写入出站（内核会直接拒绝），padding 参数内核没有对应项，直接忽略。
func ParseNaive(proxy string) (model.Outbound, error) {
	var useQUIC bool
	switch {
	case strings.HasPrefix(proxy, constant.NaiveHTTPSPrefix):
	case strings.HasPrefix(proxy, constant.NaiveQUICPrefix):
		useQUIC = true
	default:
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
	if portStr == "" {
		portStr = strconv.Itoa(constant.DefaultNaivePort)
	}
	port, err := ParsePort(portStr)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidPort,
			Message: err.Error(),
			Raw:     proxy,
		}
	}

	username := link.User.Username()
	password, hasPassword := link.User.Password()
	if !hasPassword {
		// 只有一段 userinfo 时它是密码，不是用户名
		password = username
		username = ""
	}

	query := link.Query()
	remarks := link.Fragment
	if remarks == "" {
		remarks = fmt.Sprintf("%s:%s", server, portStr)
	}
	remarks = strings.TrimSpace(remarks)

	outboundOptions := option.NaiveOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     server,
			ServerPort: port,
		},
		Username:     username,
		Password:     password,
		ExtraHeaders: parseHTTPHeader(query.Get("extra-headers")),
		QUIC:         useQUIC,
	}
	outboundOptions.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
		TLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: queryGetFirst(query, "sni", "peer", "host"),
		},
	}
	if useQUIC {
		outboundOptions.QUICCongestionControl = query.Get("quic_congestion_control")
	}

	return model.Outbound{
		Type:    constant.TypeNaive,
		Tag:     remarks,
		Options: outboundOptions,
	}, nil
}
