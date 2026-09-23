package parser

import (
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

// queryGetFirst 按顺序返回第一个非空参数值。
// 同一个语义在不同客户端里命名不一致（下划线 / 连字符 / 驼峰），约定俗成的链接两种写法都有。
func queryGetFirst(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

// parseBoolValue 解析布尔参数：1/true/yes/on 视为真，其余为假；裸参数（值为空）也视为真。
func parseBoolValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// queryGetBool 参数存在才生效：不存在返回 false，存在则按 parseBoolValue 判定。
func queryGetBool(query url.Values, keys ...string) bool {
	for _, key := range keys {
		if values, ok := query[key]; ok && len(values) > 0 {
			return parseBoolValue(values[0])
		}
	}
	return false
}

// splitCSV 把逗号分隔的参数拆成切片，去掉空项与首尾空白。
func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// parseHTTPHeader 解析 naive 的 extra-headers / http 出站的 headers 参数。
// 参数值是「Header1: Value1\r\nHeader2: Value2」经 URL 编码后的字符串，
// url.Parse 已经解过码，这里拿到的是带真实换行的文本。
func parseHTTPHeader(value string) badoption.HTTPHeader {
	if value == "" {
		return nil
	}
	headers := make(badoption.HTTPHeader)
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, headerValue, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		headers[name] = badoption.Listable[string]{strings.TrimSpace(headerValue)}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

// parseDuration 解析可选的时长参数，非法值返回 0（省略该字段，交由内核默认）。
func parseDuration(value string) badoption.Duration {
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return badoption.Duration(duration)
}
