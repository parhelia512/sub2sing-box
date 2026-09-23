package parser

import (
	"strings"

	"github.com/sagernet/sing-box/option"
)

// ParseNetworkList 把链接里的传输/网络参数转成 sing-box 出站的 network 字段。
// 该字段只接受 tcp / udp，链接里常见的却是传输类型（ws、grpc、quic…），
// 直接写进去会让内核拒绝整个出站：outbounds[n].network: unknown network: ws。
// 其它取值一律返回空（表示不限制网络）。
func ParseNetworkList(value string) option.NetworkList {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return option.NetworkList("tcp")
	case "udp":
		return option.NetworkList("udp")
	default:
		return ""
	}
}
