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

// ParseHTTP 解析 HTTP(S) 代理分享链接：
//
//	proxy-http://user:password@host:port?path=...&headers=...#label
//	proxy-https://user:password@host:port?path=...&headers=...&sni=...#label
//
// 用 proxy-http(s) 而不是裸 http(s)：裸 scheme 会和订阅地址、订阅正文里的推广链接撞车，
// 那些链接会被当成节点。scheme 本身就区分了要不要 TLS；缺省端口分别是 80 / 443。
func ParseHTTP(proxy string) (model.Outbound, error) {
	var useTLS bool
	defaultPort := constant.DefaultHTTPProxyPort
	switch {
	case strings.HasPrefix(proxy, constant.HTTPSProxyPrefix):
		useTLS = true
		defaultPort = constant.DefaultHTTPSProxyPort
	case strings.HasPrefix(proxy, constant.HTTPProxyPrefix):
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
		portStr = strconv.Itoa(defaultPort)
	}
	port, err := ParsePort(portStr)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidPort,
			Message: err.Error(),
			Raw:     proxy,
		}
	}

	password, _ := link.User.Password()
	query := link.Query()
	remarks := link.Fragment
	if remarks == "" {
		remarks = fmt.Sprintf("%s:%s", server, portStr)
	}
	remarks = strings.TrimSpace(remarks)

	outboundOptions := option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     server,
			ServerPort: port,
		},
		Username: link.User.Username(),
		Password: password,
		Path:     query.Get("path"),
		Headers:  parseHTTPHeader(query.Get("headers")),
	}

	if useTLS {
		serverName := queryGetFirst(query, "sni", "peer", "host")
		if serverName == "" {
			serverName = server
		}
		tlsOptions := &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
			ALPN:       splitCSV(query.Get("alpn")),
			Insecure:   queryGetBool(query, "allow_insecure", "insecure", "allowInsecure", "skip-cert-verify"),
		}
		if fingerprint := queryGetFirst(query, "fp", "fingerprint"); fingerprint != "" {
			tlsOptions.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fingerprint,
			}
		}
		outboundOptions.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: tlsOptions,
		}
	}

	return model.Outbound{
		Type:    constant.TypeHTTP,
		Tag:     remarks,
		Options: outboundOptions,
	}, nil
}
