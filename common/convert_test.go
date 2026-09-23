package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemplate(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "template.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func convertWithTemplate(t *testing.T, template string) string {
	t.Helper()
	result, err := Convert(
		nil,
		[]string{"trojan://pass@1.2.3.4:443#US 01"},
		template,
		"",
		nil,
		false,
		"selector",
		"tag",
		"asc",
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// 模板里的 dns server 字段必须原样保留：sing-box 的 option.DNSServerOptions
// 只在 MarshalJSONContext 里输出 server/path 等字段，普通 json.Marshal 会丢。
func TestMergeTemplatePreservesDNSServerOptions(t *testing.T) {
	template := writeTemplate(t, `{
  "dns": {
    "servers": [
      { "tag": "cn-udp", "type": "udp", "server": "223.5.5.5" },
      { "tag": "doh", "type": "https", "server": "dns.alidns.com", "path": "/dns-query" }
    ],
    "rules": [ { "domain_suffix": [".cn"], "server": "cn-udp" } ],
    "final": "doh"
  },
  "outbounds": [
    { "type": "selector", "tag": "default", "outbounds": ["<all-proxy-tags>", "direct"] },
    { "type": "direct", "tag": "direct" }
  ]
}`)

	result := convertWithTemplate(t, template)

	var parsed struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
			Final   string           `json:"final"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNS.Servers) != 2 {
		t.Fatalf("expected 2 dns servers, got %d: %s", len(parsed.DNS.Servers), result)
	}
	if got := parsed.DNS.Servers[0]["server"]; got != "223.5.5.5" {
		t.Errorf("dns server address dropped, got %v", got)
	}
	if got := parsed.DNS.Servers[1]["server"]; got != "dns.alidns.com" {
		t.Errorf("dns server name dropped, got %v", got)
	}
	if got := parsed.DNS.Servers[1]["path"]; got != "/dns-query" {
		t.Errorf("dns server path dropped, got %v", got)
	}
	if got := parsed.DNS.Final; got != "doh" {
		t.Errorf("dns final dropped, got %v", got)
	}
	if len(parsed.DNS.Rules) != 1 {
		t.Fatalf("dns rules dropped: %v", parsed.DNS.Rules)
	}
	if got := parsed.DNS.Rules[0]["server"]; got != "cn-udp" {
		t.Errorf("dns rule server dropped, got %v", got)
	}
	if got := parsed.DNS.Rules[0]["domain_suffix"]; got != ".cn" {
		t.Errorf("dns rule domain_suffix dropped, got %v", got)
	}
}

// 模板可以完全没有 dns 段，此时不能 panic。
func TestMergeTemplateWithoutDNS(t *testing.T) {
	template := writeTemplate(t, `{
  "outbounds": [
    { "type": "selector", "tag": "default", "outbounds": ["<all-proxy-tags>", "direct"] },
    { "type": "direct", "tag": "direct" }
  ]
}`)

	result := convertWithTemplate(t, template)

	if strings.Contains(result, "dns.alidns.com") {
		t.Errorf("unexpected dns content: %s", result)
	}
	if !strings.Contains(result, `"US 01"`) {
		t.Errorf("proxy missing from output: %s", result)
	}
}

// 模板块的其它段落（inbounds / route / experimental）也不能在往返中被清空。
func TestMergeTemplatePreservesOtherSections(t *testing.T) {
	template := writeTemplate(t, `{
  "log": { "level": "debug", "timestamp": true },
  "inbounds": [
    { "type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "stack": "system", "auto_route": true, "exclude_interface": ["tailscale0"] }
  ],
  "outbounds": [
    { "type": "selector", "tag": "default", "outbounds": ["<all-proxy-tags>", "direct"] },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [ { "port": [3478], "outbound": "direct" } ],
    "final": "default",
    "auto_detect_interface": true
  },
  "experimental": { "cache_file": { "enabled": true } }
}`)

	result := convertWithTemplate(t, template)

	for _, want := range []string{"172.19.0.1/30", "tailscale0", `"stack":"system"`, "auto_detect_interface", `"cache_file"`} {
		if !strings.Contains(result, want) {
			t.Errorf("field %q dropped from output: %s", want, result)
		}
	}
}
