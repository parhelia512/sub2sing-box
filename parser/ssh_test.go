package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseSSH(t *testing.T) {
	outbound, err := ParseSSH("ssh://root:pwd@1.2.3.4:2222?private_key=-----BEGIN%20KEY-----%0Aabc%0A-----END%20KEY-----&private_key_passphrase=k&host_key=ssh-ed25519%20AAAA,ssh-rsa%20BBBB&host_key_algorithms=ssh-ed25519,rsa-sha2-256#HK SSH")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != "ssh" {
		t.Errorf("unexpected type %q", outbound.Type)
	}
	options, ok := outbound.Options.(option.SSHOutboundOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", outbound.Options)
	}
	if options.Server != "1.2.3.4" || options.ServerPort != 2222 {
		t.Errorf("unexpected server %s:%d", options.Server, options.ServerPort)
	}
	if options.User != "root" || options.Password != "pwd" {
		t.Errorf("unexpected credentials %q/%q", options.User, options.Password)
	}
	// private_key 是 URL 编码的私钥内容，解码后必须带真实换行
	if len(options.PrivateKey) != 1 || options.PrivateKey[0] != "-----BEGIN KEY-----\nabc\n-----END KEY-----" {
		t.Errorf("unexpected private key: %+v", options.PrivateKey)
	}
	if options.PrivateKeyPassphrase != "k" {
		t.Errorf("unexpected passphrase %q", options.PrivateKeyPassphrase)
	}
	// 逗号分隔的 host_key / host_key_algorithms 必须拆成数组
	if len(options.HostKey) != 2 || options.HostKey[1] != "ssh-rsa BBBB" {
		t.Errorf("unexpected host key: %+v", options.HostKey)
	}
	if len(options.HostKeyAlgorithms) != 2 || options.HostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Errorf("unexpected host key algorithms: %+v", options.HostKeyAlgorithms)
	}
}

// 链接省略端口时用 22，而不是当成缺端口报错。
func TestParseSSHDefaultPort(t *testing.T) {
	outbound, err := ParseSSH("ssh://user:pwd@1.2.3.4#SG SSH")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(option.SSHOutboundOptions)
	if options.ServerPort != 22 {
		t.Errorf("unexpected default port %d", options.ServerPort)
	}
	if outbound.Tag != "SG SSH" {
		t.Errorf("unexpected tag %q", outbound.Tag)
	}
}
