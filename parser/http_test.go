package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseHTTPSProxy(t *testing.T) {
	outbound, err := ParseHTTP("proxy-https://user:pwd@1.2.3.4?path=%2Fproxy&headers=X-Token%3Aabc&sni=front.example.com&alpn=h2&fp=chrome&allowInsecure=1#US HTTP")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != "http" {
		t.Errorf("unexpected type %q", outbound.Type)
	}
	options, ok := outbound.Options.(option.HTTPOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	if options.Server != "1.2.3.4" || options.ServerPort != 443 {
		t.Errorf("unexpected server %s:%d", options.Server, options.ServerPort)
	}
	if options.Username != "user" || options.Password != "pwd" {
		t.Errorf("unexpected credentials %q/%q", options.Username, options.Password)
	}
	if options.Path != "/proxy" {
		t.Errorf("unexpected path %q", options.Path)
	}
	if values := options.Headers["X-Token"]; len(values) != 1 || values[0] != "abc" {
		t.Errorf("unexpected headers: %+v", options.Headers)
	}
	if options.TLS == nil || !options.TLS.Enabled {
		t.Fatal("proxy-https must enable tls")
	}
	if options.TLS.ServerName != "front.example.com" || !options.TLS.Insecure {
		t.Errorf("unexpected tls options: %+v", options.TLS)
	}
	if options.TLS.UTLS == nil || options.TLS.UTLS.Fingerprint != "chrome" {
		t.Errorf("unexpected utls options: %+v", options.TLS.UTLS)
	}
}

// 裸 http scheme 必须留给订阅地址/推广链接，只有 proxy-http 才当节点。
func TestParseHTTPWithoutTLS(t *testing.T) {
	outbound, err := ParseHTTP("proxy-http://user:pwd@1.2.3.4:8080#CN HTTP")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.HTTPOutboundOptions)
	if options.ServerPort != 8080 {
		t.Errorf("unexpected port %d", options.ServerPort)
	}
	if options.TLS != nil {
		t.Errorf("proxy-http must not enable tls: %+v", options.TLS)
	}
	if _, err := ParseHTTP("http://user:pwd@1.2.3.4:8080#CN HTTP"); err == nil {
		t.Fatal("bare http:// scheme must not be parsed as a proxy link")
	}
}

// sni 缺省取 host，和 trojan 的约定一致。
func TestParseHTTPSProxyDefaultSNI(t *testing.T) {
	outbound, err := ParseHTTP("proxy-https://1.2.3.4#JP HTTP")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.HTTPOutboundOptions)
	if options.TLS.ServerName != "1.2.3.4" {
		t.Errorf("unexpected default server name %q", options.TLS.ServerName)
	}
}
