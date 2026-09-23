package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bestnite/sub2sing-box/constant"
	"github.com/bestnite/sub2sing-box/model"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// ParseSSH 解析 SSH 分享链接：ssh://user:password@host:port?private_key=...#<label>
// 端口缺省为 22；只支持密码或私钥认证，不支持 agent 转发。
func ParseSSH(proxy string) (model.Outbound, error) {
	if !strings.HasPrefix(proxy, constant.SSHPrefix) {
		return model.Outbound{}, &ParseError{Type: ErrInvalidPrefix, Raw: proxy}
	}

	link, err := url.Parse(proxy)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidStruct,
			Message: "url parse error",
			Raw:     proxy,
		}
	}

	server := link.Hostname()
	if server == "" {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidStruct,
			Message: "missing server host",
			Raw:     proxy,
		}
	}
	// SSH 链接允许省略端口，内核侧缺省就是 22。
	portStr := link.Port()
	if portStr == "" {
		portStr = strconv.Itoa(constant.DefaultSSHPort)
	}
	port, err := ParsePort(portStr)
	if err != nil {
		return model.Outbound{}, &ParseError{
			Type:    ErrInvalidPort,
			Message: err.Error(),
			Raw:     proxy,
		}
	}

	password, _ := link.User.Password()
	remarks := link.Fragment
	if remarks == "" {
		remarks = fmt.Sprintf("%s:%s", server, portStr)
	}
	remarks = strings.TrimSpace(remarks)

	query := link.Query()
	// private_key 是 URL 编码后的私钥内容，url.Parse 已解码，直接透传。
	outboundOptions := option.SSHOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     server,
			ServerPort: port,
		},
		User:                 link.User.Username(),
		Password:             password,
		PrivateKey:           badoption.Listable[string](splitCSV(queryGetFirst(query, "private_key", "privateKey"))),
		PrivateKeyPassphrase: query.Get("private_key_passphrase"),
		HostKey:              badoption.Listable[string](splitCSV(queryGetFirst(query, "host_key", "hostKey"))),
		HostKeyAlgorithms:    badoption.Listable[string](splitCSV(queryGetFirst(query, "host_key_algorithms", "hostKeyAlgorithms"))),
	}

	return model.Outbound{
		Type:    constant.TypeSSH,
		Tag:     remarks,
		Options: outboundOptions,
	}, nil
}
