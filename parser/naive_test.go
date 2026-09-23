package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// userinfo 只有一段（没有冒号）时它是密码，不是用户名：
// NekoBox / NaiveGUI / Go 的分享链接写出方都按这个约定。
func TestParseNaivePasswordOnly(t *testing.T) {
	outbound, err := ParseNaive("naive+https://secret@1.2.3.4#JP Naive")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != "naive" {
		t.Errorf("unexpected type %q", outbound.Type)
	}
	options, ok := outbound.Options.(option.NaiveOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	if options.Username != "" || options.Password != "secret" {
		t.Errorf("single userinfo must be the password: %q/%q", options.Username, options.Password)
	}
	if options.ServerPort != 443 {
		t.Errorf("unexpected default port %d", options.ServerPort)
	}
	if options.QUIC {
		t.Error("naive+https must not enable quic")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		t.Fatal("naive must always enable tls")
	}
}

func TestParseNaiveQUIC(t *testing.T) {
	outbound, err := ParseNaive("naive+quic://user:pass@1.2.3.4:8443/?quic_congestion_control=bbr#US Naive QUIC")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.NaiveOutboundOptions)
	if !options.QUIC {
		t.Error("naive+quic must enable quic")
	}
	if options.QUICCongestionControl != "bbr" {
		t.Errorf("unexpected quic congestion control %q", options.QUICCongestionControl)
	}
	if options.Username != "user" || options.Password != "pass" {
		t.Errorf("unexpected credentials %q/%q", options.Username, options.Password)
	}
}

// extra-headers 是 URL 编码的「K: V\r\nK2: V2」；alpn/insecure 这类 naive 不支持的
// TLS 字段一律不写出站，否则内核会直接拒绝整个出站。
func TestParseNaiveExtraHeaders(t *testing.T) {
	outbound, err := ParseNaive("naive+https://u:p@1.2.3.4?extra-headers=X-User%3Aalice%0D%0AX-Token%3Axyz&alpn=h2&insecure=1&sni=x.example.com#DE Naive")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.NaiveOutboundOptions)
	if len(options.ExtraHeaders) != 2 {
		t.Fatalf("unexpected headers: %+v", options.ExtraHeaders)
	}
	if values := options.ExtraHeaders["X-User"]; len(values) != 1 || values[0] != "alice" {
		t.Errorf("unexpected X-User header: %+v", values)
	}
	if values := options.ExtraHeaders["X-Token"]; len(values) != 1 || values[0] != "xyz" {
		t.Errorf("unexpected X-Token header: %+v", values)
	}
	if options.TLS.ServerName != "x.example.com" {
		t.Errorf("unexpected server name %q", options.TLS.ServerName)
	}
	if len(options.TLS.ALPN) != 0 || options.TLS.Insecure {
		t.Errorf("naive rejects alpn/insecure, they must not be set: %+v", options.TLS)
	}
}
