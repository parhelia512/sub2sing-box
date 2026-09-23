package parser

import "testing"

func TestParseHTTPHeader(t *testing.T) {
	headers := parseHTTPHeader("X-User: alice\r\nX-Token: a:b:c")
	if len(headers) != 2 {
		t.Fatalf("unexpected headers: %+v", headers)
	}
	if values := headers["X-User"]; len(values) != 1 || values[0] != "alice" {
		t.Errorf("unexpected X-User: %+v", values)
	}
	// 值里带冒号时只按第一个冒号切分
	if values := headers["X-Token"]; len(values) != 1 || values[0] != "a:b:c" {
		t.Errorf("unexpected X-Token: %+v", values)
	}
	if parseHTTPHeader("") != nil {
		t.Error("empty header parameter must stay nil")
	}
	if parseHTTPHeader("not-a-header") != nil {
		t.Error("lines without a colon must be skipped")
	}
}

func TestSplitCSV(t *testing.T) {
	if got := splitCSV("h3, h3-29 ,"); len(got) != 2 || got[1] != "h3-29" {
		t.Errorf("unexpected result: %+v", got)
	}
	if splitCSV("") != nil || splitCSV(",") != nil {
		t.Error("empty values must be nil")
	}
}

func TestParseBoolValue(t *testing.T) {
	for _, value := range []string{"", "1", "true", "TRUE", "yes", "on"} {
		if !parseBoolValue(value) {
			t.Errorf("%q should be true", value)
		}
	}
	for _, value := range []string{"0", "false", "no", "off", "anything"} {
		if parseBoolValue(value) {
			t.Errorf("%q should be false", value)
		}
	}
}

func TestParseDuration(t *testing.T) {
	if got := parseDuration("10s"); got != 10000000000 {
		t.Errorf("unexpected duration %v", got)
	}
	// 非法值退化成零值（省略字段），不能让整条链接解析失败
	if got := parseDuration("ten seconds"); got != 0 {
		t.Errorf("invalid duration should be zero, got %v", got)
	}
	if got := parseDuration(""); got != 0 {
		t.Errorf("missing duration should be zero, got %v", got)
	}
}
