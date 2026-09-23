package parser

import (
	"strings"

	"github.com/bestnite/sub2sing-box/constant"
)

// unsupportedProxyReasons 列出无法从分享链接转换的格式及原因。
// 这些链接必须给出明确原因，不能笼统地报 "unknown proxy format"，
// 否则用户会以为是自己链接写错了，而不是协议本身不被内核支持（或压根没有通用链接格式）。
var unsupportedProxyReasons = map[string]string{
	constant.ShadowsocksRPrefix: "shadowsocksr is not supported: the shadowsocksr outbound was removed in sing-box 1.6.0",
	constant.WireGuardPrefix:    "the wireguard outbound was removed in sing-box 1.13.0: use the wireguard endpoint instead, which sub2sing-box cannot generate yet",
	constant.WireGuardPrefixAlt: "the wireguard outbound was removed in sing-box 1.13.0: use the wireguard endpoint instead, which sub2sing-box cannot generate yet",
	constant.JuicityPrefix:      "juicity is not supported: sing-box has no juicity outbound",
	constant.SnellPrefix:        "snell has no common share link format: write the snell outbound into the template directly",
}

// UnsupportedReason 判断链接是否属于已知的不支持格式，并返回原因。
func UnsupportedReason(proxy string) (string, bool) {
	for prefix, reason := range unsupportedProxyReasons {
		if strings.HasPrefix(proxy, prefix) {
			return reason, true
		}
	}
	return "", false
}
