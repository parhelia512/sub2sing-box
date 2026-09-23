package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseTUIC(t *testing.T) {
	outbound, err := ParseTUIC("tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:hello@1.2.3.4:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=a.example.com&allow_insecure=1&reduce_rtt=1#US TUIC 01")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != "tuic" {
		t.Errorf("unexpected type %q", outbound.Type)
	}
	if outbound.Tag != "US TUIC 01" {
		t.Errorf("unexpected tag %q", outbound.Tag)
	}
	options, ok := outbound.Options.(option.TUICOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	if options.Server != "1.2.3.4" || options.ServerPort != 443 {
		t.Errorf("unexpected server %s:%d", options.Server, options.ServerPort)
	}
	if options.UUID != "2dd61d93-75d8-4da4-ac0e-6aece7eac365" || options.Password != "hello" {
		t.Errorf("unexpected credentials %q/%q", options.UUID, options.Password)
	}
	if options.CongestionControl != "bbr" || options.UDPRelayMode != "quic" {
		t.Errorf("unexpected congestion/relay: %q/%q", options.CongestionControl, options.UDPRelayMode)
	}
	if !options.ZeroRTTHandshake {
		t.Error("reduce_rtt should enable zero_rtt_handshake")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		t.Fatal("tuic must always enable tls")
	}
	if options.TLS.ServerName != "a.example.com" || !options.TLS.Insecure {
		t.Errorf("unexpected tls options: %+v", options.TLS)
	}
	if len(options.TLS.ALPN) != 1 || options.TLS.ALPN[0] != "h3" {
		t.Errorf("unexpected alpn: %+v", options.TLS.ALPN)
	}
}

// 枚举值写错时丢弃而不是改写：把 quic 悄悄换成 native，用户会以为链接生效了。
func TestParseTUICDropsInvalidEnum(t *testing.T) {
	outbound, err := ParseTUIC("tuic://uuid:pass@1.2.3.4:443?congestion_control=vegas&udp_relay_mode=raw#TW 01")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.TUICOutboundOptions)
	if options.CongestionControl != "" {
		t.Errorf("invalid congestion control kept: %q", options.CongestionControl)
	}
	if options.UDPRelayMode != "" {
		t.Errorf("invalid udp relay mode kept: %q", options.UDPRelayMode)
	}
}

func TestParseTUICRequiresUUID(t *testing.T) {
	if _, err := ParseTUIC("tuic://1.2.3.4:443#no uuid"); err == nil {
		t.Fatal("expected error for missing uuid")
	}
}
