package model

import "testing"

// 国家名识别必须是确定性的：老实现直接遍历 map（顺序随机）并用宽松的子串匹配，
// 同一个 tag 会在不同国家之间跳变 —— "US Socks 01" 一会是 美国(US)，
// 一会是 库克群岛(CK)（"Socks" 里的 ck）。
func TestGetContryNameIsDeterministic(t *testing.T) {
	cases := map[string]string{
		"US 洛杉矶 01":   "美国(US)",
		"US Socks 01": "美国(US)",
		"JP01":        "日本(JP)",
		"香港 01":       "香港(HK)",
		"台湾(TW)":      "台湾(TW)",
		"中国台湾 01":     "台湾(TW)",
		"日本 东京 01":    "日本(JP)",
		"🇯🇵日本 01":     "日本(JP)",
		"Socks 01":    "其他地区",
		"Russia 01":   "其他地区",
	}
	for tag, want := range cases {
		first := GetContryName(tag)
		if first != want {
			t.Errorf("GetContryName(%q) = %q, want %q", tag, first, want)
		}
		for i := 0; i < 200; i++ {
			if got := GetContryName(tag); got != first {
				t.Fatalf("GetContryName(%q) not deterministic: %q then %q", tag, first, got)
			}
		}
	}
}
