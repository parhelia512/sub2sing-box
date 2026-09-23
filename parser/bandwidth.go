package parser

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/byteformats"
)

// ParseBandwidth 解析分享链接里的带宽参数（hysteria 的 upmbps / downmbps）。
// 链接里写的是纯数字，单位是 Mbps（如 upmbps=100）；sing-box 的
// byteformats.NetworkBytesCompat 只接受带单位的写法（"100 Mbps"），
// 直接套用会失败：invalid network bytes compat: invalid format: 100。
// 空值返回 nil，表示不限制带宽。
func ParseBandwidth(raw string) (*byteformats.NetworkBytesCompat, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if _, err := strconv.ParseFloat(raw, 64); err == nil {
		raw += " Mbps"
	}
	quoted, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	value := &byteformats.NetworkBytesCompat{}
	if err := json.Unmarshal(quoted, value); err != nil {
		return nil, err
	}
	return value, nil
}
