package parser

import "testing"

// sing-box 1.6.0 就删掉了 shadowsocksr 出站，ssr:// 永远转不出可用配置，
// 必须给出明确原因，而不是笼统的 unknown proxy format。
func TestUnsupportedReason(t *testing.T) {
	reason, unsupported := UnsupportedReason("ssr://MS4yLjMuMTQ6ODM4OTphdXRoX2FlczEyOF9tZDU6cHdk")
	if !unsupported {
		t.Fatal("ssr:// should be reported as unsupported")
	}
	if reason == "" {
		t.Fatal("missing reason")
	}
	if _, unsupported := UnsupportedReason("trojan://pass@1.2.3.4:443#JP 01"); unsupported {
		t.Fatal("supported link reported as unsupported")
	}
}
