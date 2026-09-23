package constant

const (
	HysteriaPrefix     string = "hysteria://"
	Hysteria2Prefix1   string = "hysteria2://"
	Hysteria2Prefix2   string = "hy2://"
	ShadowsocksPrefix  string = "ss://"
	ShadowsocksRPrefix string = "ssr://"
	TrojanPrefix       string = "trojan://"
	VLESSPrefix        string = "vless://"
	VMessPrefix        string = "vmess://"
	SocksPrefix        string = "socks"
	AnytlsPrefix       string = "anytls://"
	TUICPrefix         string = "tuic://"
	SSHPrefix          string = "ssh://"
	NaiveHTTPSPrefix   string = "naive+https://"
	NaiveQUICPrefix    string = "naive+quic://"
	HTTPProxyPrefix    string = "proxy-http://"
	HTTPSProxyPrefix   string = "proxy-https://"
	WireGuardPrefix    string = "wireguard://"
	WireGuardPrefixAlt string = "wg://"
	JuicityPrefix      string = "juicity://"
	SnellPrefix        string = "snell://"
)

const (
	// DefaultNaivePort / DefaultHTTPSProxyPort / DefaultSSHPort 是各协议在链接里省略端口时的缺省值。
	DefaultNaivePort      = 443
	DefaultHTTPSProxyPort = 443
	DefaultHTTPProxyPort  = 80
	DefaultSSHPort        = 22
)
