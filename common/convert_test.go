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

// 生成的节点与地区分组必须出现在结果里。
// sing-box 1.14 起 option.Options 提供了值接收者的 MarshalJSONContext，它会被提升到
// model.Options 上，序列化时只输出 option.Options 自身的字段，把本类型附加的
// endpoints/inbounds/outbounds 整体丢掉——模板里的策略组照旧、check 也能过，
// 但订阅节点和地区分组全部消失。
func TestMergeTemplateKeepsGeneratedOutbounds(t *testing.T) {
	template := writeTemplate(t, `{
  "outbounds": [
    { "type": "selector", "tag": "节点选择", "outbounds": ["<all-country-tags>", "手动切换", "direct"] },
    { "type": "selector", "tag": "手动切换", "outbounds": ["<all-proxy-tags>"] },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "节点选择" }
}`)

	result := convertWithTemplate(t, template)

	var parsed struct {
		Outbounds []struct {
			Type  string   `json:"type"`
			Tag   string   `json:"tag"`
			Items []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}
	tags := make(map[string]bool, len(parsed.Outbounds))
	for _, outbound := range parsed.Outbounds {
		tags[outbound.Tag] = true
	}
	if !tags["US 01"] {
		t.Errorf("generated proxy outbound dropped: %s", result)
	}
	if !tags["美国(US)"] {
		t.Errorf("generated country group dropped: %s", result)
	}
	for _, outbound := range parsed.Outbounds {
		if outbound.Tag != "手动切换" {
			continue
		}
		if len(outbound.Items) != 1 || outbound.Items[0] != "US 01" {
			t.Errorf("proxy placeholder not expanded: %v", outbound.Items)
		}
	}
}
