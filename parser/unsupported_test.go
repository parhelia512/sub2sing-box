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

// 内核没有对应出站（juicity）或压根没有通用链接格式（snell）的链接同样要给原因，
// 不能掉到 unknown proxy format。
func TestUnsupportedReasonForOtherFormats(t *testing.T) {
	for _, link := range []string{
		"juicity://uuid:pass@1.2.3.4:443#JP 01",
		"snell://psk@1.2.3.4:443#JP 01",
		"wg://1.2.3.4:51820#JP 01",
	} {
		reason, unsupported := UnsupportedReason(link)
		if !unsupported {
			t.Errorf("%s should be reported as unsupported", link)
			continue
		}
		if reason == "" {
			t.Errorf("%s: missing reason", link)
		}
	}
	if _, unsupported := UnsupportedReason("tuic://uuid:pass@1.2.3.4:443#JP 01"); unsupported {
		t.Fatal("tuic is now supported and must not be reported as unsupported")
	}
}
