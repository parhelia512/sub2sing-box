package model

import (
	"bytes"
	"context"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _Options struct {
	option.Options
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	Inbounds  []Inbound  `json:"inbounds,omitempty"`
	Outbounds []Outbound `json:"outbounds,omitempty"`
}

type Options _Options

func (o *Options) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	decoder := json.NewDecoderContext(ctx, bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	err := decoder.Decode((*_Options)(o))
	if err != nil {
		return err
	}
	o.RawMessage = content
	return nil
}

// _OptionsExtra 只用于序列化时把下面三个字段合并回 option.Options 生成的对象里。
type _OptionsExtra struct {
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	Inbounds  []Inbound  `json:"inbounds,omitempty"`
	Outbounds []Outbound `json:"outbounds,omitempty"`
}

// MarshalJSONContext 必须显式实现：sing-box 1.14 起 option.Options 提供了值接收者的
// MarshalJSONContext，它会被提升到本类型上，序列化时只输出 option.Options 自身的字段，
// 导致这里附加的 endpoints/inbounds/outbounds 被整体丢弃（转换结果里生成的节点全部消失）。
// 这里先序列化 option.Options，再把三个字段合并进去覆盖同名键。
func (o Options) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return badjson.MarshallObjectsContext(ctx, o.Options, _OptionsExtra{
		Endpoints: o.Endpoints,
		Inbounds:  o.Inbounds,
		Outbounds: o.Outbounds,
	})
}

type LogOptions struct {
	Disabled     bool   `json:"disabled,omitempty"`
	Level        string `json:"level,omitempty"`
	Output       string `json:"output,omitempty"`
	Timestamp    bool   `json:"timestamp,omitempty"`
	DisableColor bool   `json:"-"`
}

type StubOptions struct{}

type Endpoint option.Endpoint

func (e *Endpoint) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects((*option.Endpoint)(e), e.Options)
}

type Inbound option.Inbound

func (i *Inbound) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects((*option.Inbound)(i), i.Options)
}

type Outbound option.Outbound

func (o *Outbound) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects((*option.Outbound)(o), o.Options)
}
