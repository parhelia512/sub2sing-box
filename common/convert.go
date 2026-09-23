package common

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/bestnite/sub2sing-box/constant"
	"github.com/bestnite/sub2sing-box/model"
	"github.com/bestnite/sub2sing-box/parser"
	"github.com/bestnite/sub2sing-box/util"
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing/common/json"
)

var globalCtx = box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())

// marshalOutbound 用 sing 的 context 编码器序列化出站。
// 必须传指针：model.Outbound 的 MarshalJSON 定义在指针接收者上，
// 序列化值副本会退化成结构体编码、丢掉 json:"-" 的 Options，
// 结果只剩 type+tag —— 输出里没有服务器信息，去重时还会把不同服务器但同名的节点当成重复节点。
func marshalOutbound(outbound *model.Outbound) ([]byte, error) {
	return J.MarshalContext(globalCtx, outbound)
}

func Convert(
	subscriptions []string,
	proxies []string,
	templatePath string,
	delete string,
	rename map[string]string,
	enableGroup bool,
	groupType string,
	sortKey string,
	sortType string,
	groupRules map[string][]string,
	userAgent string,
) (string, error) {
	result := ""
	var err error

	if groupType == "" {
		groupType = C.TypeSelector
	}

	outbounds, err := ConvertSubscriptionsToSProxy(subscriptions, userAgent)
	if err != nil {
		return "", err
	}
	for _, proxy := range proxies {
		p, err := ConvertCProxyToSProxy(proxy)
		if err != nil {
			return "", err
		}
		outbounds = append(outbounds, p)
	}

	if delete != "" {
		outbounds, err = DeleteProxy(outbounds, delete)
		if err != nil {
			return "", err
		}
	}

	for k, v := range rename {
		outbounds, err = RenameProxy(outbounds, k, v)
		if err != nil {
			return "", err
		}
	}

	set := make(map[string]bool)
	deduplicatedOutbounds := make([]model.Outbound, 0)
	for i := range outbounds {
		// 去重键必须包含出站的完整配置，不能只剩 type+tag：
		// 否则不同服务器但同名的两个节点会被当成重复节点丢掉。
		jsonBytes, err := marshalOutbound(&outbounds[i])
		if err != nil {
			return "", err
		}
		if _, exists := set[string(jsonBytes)]; !exists {
			set[string(jsonBytes)] = true
			deduplicatedOutbounds = append(deduplicatedOutbounds, outbounds[i])
		}
	}
	outbounds = deduplicatedOutbounds

	tagSet := make(map[string]bool)
	for i := range outbounds {
		tag := outbounds[i].Tag
		if _, exists := tagSet[tag]; exists {
			count := 1
			for {
				newTag := fmt.Sprintf("%s %d", tag, count)
				if _, exists := tagSet[newTag]; !exists {
					outbounds[i].Tag = newTag
					tag = newTag
					break
				} else {
					count++
				}
			}
		}
		// 必须登记已用过的 tag，否则重复 tag 永远检测不到，
		// 生成的配置会被内核拒绝：duplicate outbound/endpoint tag: US 01
		tagSet[tag] = true
	}

	if enableGroup {
		outbounds = AddCountryGroup(outbounds, groupType, sortKey, sortType, groupRules)
	}
	if templatePath != "" {
		templateData, err := ReadTemplate(templatePath, userAgent)
		if err != nil {
			return "", err
		}
		reg := regexp.MustCompile("\"<[A-Za-z]{2}>\"")
		group := false
		for _, v := range model.CountryEnglishName {
			if strings.Contains(templateData, v) {
				group = true
			}
		}
		if !enableGroup && (reg.MatchString(templateData) || strings.Contains(templateData, constant.AllCountryTags) || group) {
			outbounds = AddCountryGroup(outbounds, groupType, sortKey, sortType, groupRules)
		}
		var template model.Options
		if template, err = J.UnmarshalExtendedContext[model.Options](globalCtx, []byte(templateData)); err != nil {
			return "", err
		}
		for _, v := range template.Options.Outbounds {
			template.Outbounds = append(template.Outbounds, (model.Outbound)(v))
		}
		for _, v := range template.Options.Inbounds {
			template.Inbounds = append(template.Inbounds, (model.Inbound)(v))
		}
		for _, v := range template.Options.Endpoints {
			template.Endpoints = append(template.Endpoints, (model.Endpoint)(v))
		}
		result, err = MergeTemplate(outbounds, &template, groupRules)
		if err != nil {
			return "", err
		}
	} else {
		outboundJsons := make([]string, 0, len(outbounds))
		for i := range outbounds {
			b, err := marshalOutbound(&outbounds[i])
			if err != nil {
				return "", err
			}
			outboundJsons = append(outboundJsons, string(b))
		}
		result = fmt.Sprintf("[%s]", strings.Join(outboundJsons, ","))
	}

	return string(result), nil
}

func AddCountryGroup(proxies []model.Outbound, groupType string, sortKey string, sortType string, groupRules map[string][]string) []model.Outbound {
	newGroup := make(map[string]model.Outbound)
	groupRulesRegexps := make(map[string][]*regexp.Regexp)
	for k, v := range groupRules {
		for _, rule := range v {
			groupRulesRegexps[k] = append(groupRulesRegexps[k], regexp.MustCompile(rule))
		}
	}
	for _, p := range proxies {
		if p.Type != C.TypeSelector && p.Type != C.TypeURLTest {
			country := model.GetContryName(p.Tag)
			for k, rules := range groupRulesRegexps {
				for _, rule := range rules {
					if rule.MatchString(p.Tag) {
						country = k
						break
					}
				}
			}
			if group, ok := newGroup[country]; ok {
				AppendOutbound(&group, p.Tag)
				newGroup[country] = group
			} else {
				if groupType == C.TypeSelector {
					newGroup[country] = model.Outbound{
						Tag:  country,
						Type: groupType,
						Options: option.SelectorOutboundOptions{
							Outbounds:                 []string{p.Tag},
							InterruptExistConnections: true,
						},
					}
				} else if groupType == C.TypeURLTest {
					newGroup[country] = model.Outbound{
						Tag:  country,
						Type: groupType,
						Options: option.URLTestOutboundOptions{
							Outbounds:                 []string{p.Tag},
							InterruptExistConnections: true,
						},
					}
				}
			}
		}
	}
	var groups []model.Outbound
	for _, p := range newGroup {
		groups = append(groups, p)
	}
	if sortType != "" {
		if sortType == "asc" {
			switch sortKey {
			case "tag":
				sort.Sort(model.SortByTag(groups))
			case "num":
				sort.Sort(model.SortByNumber(groups))
			default:
				sort.Sort(model.SortByTag(groups))
			}
		} else {
			switch sortKey {
			case "tag":
				sort.Sort(sort.Reverse(model.SortByTag(groups)))
			case "num":
				sort.Sort(sort.Reverse(model.SortByNumber(groups)))
			default:
				sort.Sort(sort.Reverse(model.SortByTag(groups)))
			}
		}
	}
	return append(proxies, groups...)
}

func ReadTemplate(template string, userAgent string) (string, error) {
	var data string
	var err error
	isNetworkFile, _ := regexp.MatchString(`^https?://`, template)
	if isNetworkFile {
		data, err = util.Fetch(template, 3, userAgent)
		if err != nil {
			return "", err
		}
		return data, nil
	} else {
		if !strings.Contains(template, string(filepath.Separator)) {
			path := filepath.Join("templates", template)
			if _, err := os.Stat(path); err == nil {
				template = path
			}
		}
		dataBytes, err := os.ReadFile(template)
		if err != nil {
			return "", err
		}
		return string(dataBytes), nil
	}
}

func MergeTemplate(outbounds []model.Outbound, template *model.Options, groupRules map[string][]string) (string, error) {
	var err error
	proxyTags := make([]string, 0)
	groupTags := make([]string, 0)
	groups := make(map[string]model.Outbound)
	rulesKeys := make([]string, 0)
	for k := range groupRules {
		rulesKeys = append(rulesKeys, k)
	}
	for _, p := range outbounds {
		if slices.Contains(rulesKeys, p.Tag) || model.IsCountryGroup(p.Tag) {
			groupTags = append(groupTags, p.Tag)
			reg := regexp.MustCompile("[A-Za-z]{2}")
			country := reg.FindString(p.Tag)
			groups[country] = p
		} else {
			proxyTags = append(proxyTags, p.Tag)
		}
	}
	reg := regexp.MustCompile("<[A-Za-z]{2}>")
	for i, o := range template.Outbounds {
		outbound := (model.Outbound)(o)
		if outbound.Type == C.TypeSelector || outbound.Type == C.TypeURLTest {
			var parsedOutbound []string = make([]string, 0)
			for _, o := range GetOutbounds(&outbound) {
				if o == constant.AllProxyTags {
					parsedOutbound = append(parsedOutbound, proxyTags...)
				} else if o == constant.AllCountryTags {
					parsedOutbound = append(parsedOutbound, groupTags...)
				} else if reg.MatchString(o) {
					country := strings.ToUpper(strings.Trim(reg.FindString(o), "<>"))
					if group, ok := groups[country]; ok {
						parsedOutbound = append(parsedOutbound, GetOutbounds(&group)...)
					}
				} else {
					parsedOutbound = append(parsedOutbound, o)
				}
			}
			SetOutbounds(&template.Outbounds[i], parsedOutbound)
		}
	}
	template.Outbounds = append(template.Outbounds, outbounds...)

	// option.DNSOptions.Servers 等字段的内容存放在 json:"-" 的 Options 字段里，
	// 序列化依赖 MarshalJSONContext；用 encoding/json 直接 Marshal 会丢掉
	// server/path 等除 type/tag 以外的全部字段，必须走带 context 的编码器。
	// 另外模板可以没有 dns 段，这里要判空，否则 template.DNS.Rules 会 panic。
	if template.DNS != nil {
		for i := range template.DNS.Rules {
			if template.DNS.Rules[i].Type == "" {
				template.DNS.Rules[i].Type = C.RuleTypeDefault
			}
		}
	}

	data, err := J.MarshalContext(globalCtx, template)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ConvertCProxyToSProxy(proxy string) (model.Outbound, error) {
	for prefix, parseFunc := range parser.ParserMap {
		if strings.HasPrefix(proxy, prefix) {
			proxy, err := parseFunc(proxy)
			if err != nil {
				return model.Outbound{}, err
			}
			return proxy, nil
		}
	}
	if reason, unsupported := parser.UnsupportedReason(proxy); unsupported {
		return model.Outbound{}, &parser.ParseError{
			Type:    parser.ErrUnsupportedProxy,
			Message: reason,
			Raw:     proxy,
		}
	}
	return model.Outbound{}, errors.New("unknown proxy format")
}

func ConvertSubscriptionsToSProxy(urls []string, userAgent string) ([]model.Outbound, error) {
	proxyList := make([]model.Outbound, 0)
	unsupportedLinks := make(map[string]int)
	for _, url := range urls {
		data, err := util.Fetch(url, 3, userAgent)
		if err != nil {
			return nil, err
		}
		proxy := data
		if !strings.Contains(data, "://") {
			proxy, err = util.DecodeBase64(data)
		}
		if err != nil {
			return nil, err
		}
		proxies := strings.Split(proxy, "\n")
		for _, p := range proxies {
			matched := false
			for prefix, parseFunc := range parser.ParserMap {
				if strings.HasPrefix(p, prefix) {
					matched = true
					proxy, err := parseFunc(p)
					if err != nil {
						return nil, err
					}
					proxyList = append(proxyList, proxy)
					break
				}
			}
			if !matched {
				if reason, unsupported := parser.UnsupportedReason(p); unsupported {
					unsupportedLinks[reason]++
				}
			}
		}
	}
	// sing-box 没有对应出站的链接（如 shadowsocksr）不能静默丢掉，
	// 但也不该让整份订阅转换失败：只跳过，并把原因写到 stderr。
	reasons := make([]string, 0, len(unsupportedLinks))
	for reason := range unsupportedLinks {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		fmt.Fprintf(os.Stderr, "skipped %d unsupported proxy link(s): %s\n", unsupportedLinks[reason], reason)
	}
	return proxyList, nil
}

func DeleteProxy(proxies []model.Outbound, regex string) ([]model.Outbound, error) {
	reg, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	var newProxies []model.Outbound
	for _, p := range proxies {
		if !reg.MatchString(p.Tag) {
			newProxies = append(newProxies, p)
		}
	}
	return newProxies, nil
}

func RenameProxy(proxies []model.Outbound, regex string, replaceText string) ([]model.Outbound, error) {
	reg, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	for i, p := range proxies {
		if reg.MatchString(p.Tag) {
			proxies[i].Tag = reg.ReplaceAllString(p.Tag, replaceText)
		}
	}
	return proxies, nil
}

func SetOutbounds(outbound *model.Outbound, outbounds []string) {
	switch v := outbound.Options.(type) {
	case option.SelectorOutboundOptions:
		v.Outbounds = outbounds
		outbound.Options = v
	case option.URLTestOutboundOptions:
		v.Outbounds = outbounds
		outbound.Options = v
	case *option.SelectorOutboundOptions:
		v.Outbounds = outbounds
		outbound.Options = v
	case *option.URLTestOutboundOptions:
		v.Outbounds = outbounds
		outbound.Options = v
	}
}

func AppendOutbound(outbound *model.Outbound, outboundTag string) {
	switch v := outbound.Options.(type) {
	case option.SelectorOutboundOptions:
		v.Outbounds = append(v.Outbounds, outboundTag)
		outbound.Options = v
	case option.URLTestOutboundOptions:
		v.Outbounds = append(v.Outbounds, outboundTag)
		outbound.Options = v
	case *option.SelectorOutboundOptions:
		v.Outbounds = append(v.Outbounds, outboundTag)
		outbound.Options = v
	case *option.URLTestOutboundOptions:
		v.Outbounds = append(v.Outbounds, outboundTag)
		outbound.Options = v
	}
}

func GetOutbounds(outbound *model.Outbound) []string {
	switch v := outbound.Options.(type) {
	case option.SelectorOutboundOptions:
		return v.Outbounds
	case option.URLTestOutboundOptions:
		return v.Outbounds
	case *option.SelectorOutboundOptions:
		return v.Outbounds
	case *option.URLTestOutboundOptions:
		return v.Outbounds
	}
	return nil
}
