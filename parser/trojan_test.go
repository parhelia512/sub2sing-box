package parser

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// 链接里的 type 是传输类型，不能被当成出站的 network（只接受 tcp/udp）。
// 老实现把 type 直接写进 Network，type=ws 的链接生成的配置会被内核拒绝：
// outbounds[n].network: unknown network: ws。
func TestParseTrojanTransportDoesNotBecomeNetwork(t *testing.T) {
	link := "trojan://pass@1.2.3.4:443?sni=a.example.com&type=ws&path=%2Fws#JP 01"
	outbound, err := ParseTrojan(link)
	if err != nil {
		t.Fatal(err)
	}
	options, ok := outbound.Options.(option.TrojanOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	if options.Network != "" {
		t.Errorf("transport type leaked into network: %q", options.Network)
	}
	if options.Transport == nil || options.Transport.Type != "ws" {
		t.Fatalf("ws transport missing: %+v", options.Transport)
	}
	content, err := json.Marshal(outbound.Options)
	if err != nil {
		t.Fatal(err)
	}
	// 出站序列化后不能出现 network 字段，否则内核直接拒绝整个出站
	if strings.Contains(string(content), `"network"`) {
		t.Errorf("network field still serialized: %s", content)
	}
}
