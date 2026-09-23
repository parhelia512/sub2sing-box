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
	return convertLinkWithTemplate(t, "trojan://pass@1.2.3.4:443#US 01", template)
}

func convertLinkWithTemplate(t *testing.T, link string, template string) string {
	t.Helper()
	return convertLinksWithTemplate(t, []string{link}, template)
}

func convertLinks(t *testing.T, links []string) string {
	t.Helper()
	return convertLinksWithTemplate(t, links, "")
}

func convertLinksWithTemplate(t *testing.T, links []string, template string) string {
	t.Helper()
	result, err := Convert(
		nil,
		links,
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

func convertLink(t *testing.T, link string) string {
	t.Helper()
	return convertLinkWithTemplate(t, link, "")
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

// type=ws 的 trojan 链接不能生成带 network 字段的出站：链接里的 type 是传输类型，
// 写进 network 会让内核拒绝整个出站（outbounds[n].network: unknown network: ws）。
func TestConvertTrojanWebsocketTransport(t *testing.T) {
	result := convertLink(t, "trojan://pass@1.2.3.4:443?sni=a.example.com&type=ws&path=%2Fws#JP 01")

	if strings.Contains(result, `"network"`) {
		t.Errorf("transport type leaked into network field: %s", result)
	}
	if !strings.Contains(result, `"type":"ws"`) {
		t.Errorf("ws transport missing: %s", result)
	}
}

// sing-box 1.6.0 起没有 shadowsocksr 出站，ssr:// 必须给出明确原因。
func TestConvertUnsupportedProxyError(t *testing.T) {
	_, err := Convert(
		nil,
		[]string{"ssr://MS4yLjMuMTQ6ODM4OTphdXRoX2FlczEyOF9tZDU6cHdk"},
		"",
		"",
		nil,
		false,
		"selector",
		"tag",
		"asc",
		nil,
		"",
	)
	if err == nil {
		t.Fatal("expected an error for ssr:// link")
	}
	if !strings.Contains(err.Error(), "shadowsocksr") {
		t.Errorf("error should explain the real reason, got: %v", err)
	}
}

// 去重键必须包含出站的完整配置：不同服务器但同名的节点不能当成重复节点丢掉。
func TestConvertKeepsDistinctProxiesWithSameTag(t *testing.T) {
	result := convertLinks(t, []string{
		"trojan://passA@1.2.3.4:443?sni=a.example.com#US 01",
		"trojan://passB@5.6.7.8:443?sni=b.example.com#US 01",
	})

	servers := make(map[string]bool)
	for _, outbound := range parseOutbounds(t, result) {
		if outbound["type"] == "trojan" {
			servers[outbound["server"].(string)] = true
		}
	}
	if len(servers) != 2 {
		t.Fatalf("expected both nodes to survive, got %v", servers)
	}
}

// 重复 tag 必须改名，否则生成的配置会被内核拒绝：
// decode config: duplicate outbound/endpoint tag: US 01
func TestConvertRenamesDuplicateTags(t *testing.T) {
	result := convertLinks(t, []string{
		"trojan://pass@1.2.3.4:443?sni=a.example.com#US 01",
		"vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443?encryption=none&security=tls&sni=b.example.com#US 01",
	})

	tags := make(map[string]int)
	for _, outbound := range parseOutbounds(t, result) {
		tags[outbound["tag"].(string)]++
	}
	if len(tags) != 2 {
		t.Fatalf("expected both nodes to survive, got %v", tags)
	}
	for tag, count := range tags {
		if count > 1 {
			t.Errorf("duplicate tag %q", tag)
		}
	}
}

func parseOutbounds(t *testing.T, result string) []map[string]any {
	t.Helper()
	var outbounds []map[string]any
	if err := json.Unmarshal([]byte(result), &outbounds); err != nil {
		t.Fatalf("invalid output %q: %v", result, err)
	}
	return outbounds
}
