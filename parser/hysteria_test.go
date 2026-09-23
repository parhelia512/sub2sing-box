package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// hysteria 链接里的 upmbps/downmbps 是纯数字（单位 Mbps），sing-box 只接受
// "100 Mbps" 这类带单位的写法，老实现直接套用会失败：
// invalid network bytes compat: invalid format: 100
func TestParseHysteriaBandwidth(t *testing.T) {
	outbound, err := ParseHysteria("hysteria://1.2.3.4:36712?protocol=udp&auth=pwd&peer=d.example.com&insecure=1&upmbps=100&downmbps=50#HK 01")
	if err != nil {
		t.Fatal(err)
	}
	options, ok := outbound.Options.(option.HysteriaOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	// 100 Mbps = 100 * 1000 * 1000 / 8 字节每秒
	if options.Up == nil || options.Up.Value() != 12500000 {
		t.Errorf("unexpected up bandwidth: %+v", options.Up)
	}
	if options.Down == nil || options.Down.Value() != 6250000 {
		t.Errorf("unexpected down bandwidth: %+v", options.Down)
	}
}

// 链接里没写 upmbps/downmbps 时不能报错，只是不限制带宽。
func TestParseHysteriaWithoutBandwidth(t *testing.T) {
	outbound, err := ParseHysteria("hysteria://1.2.3.4:36712?auth=pwd&peer=d.example.com#HK 01")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.HysteriaOutboundOptions)
	if options.Up != nil || options.Down != nil {
		t.Errorf("unexpected bandwidth: up=%+v down=%+v", options.Up, options.Down)
	}
}

// 已经带单位的写法要原样接受。
func TestParseHysteriaBandwidthWithUnit(t *testing.T) {
	outbound, err := ParseHysteria("hysteria://1.2.3.4:36712?auth=pwd&upmbps=100%20Mbps&downmbps=100Mbps#HK 01")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.HysteriaOutboundOptions)
	if options.Up == nil || options.Up.Value() != 12500000 {
		t.Errorf("unexpected up bandwidth: %+v", options.Up)
	}
	if options.Down == nil || options.Down.Value() != 12500000 {
		t.Errorf("unexpected down bandwidth: %+v", options.Down)
	}
}
