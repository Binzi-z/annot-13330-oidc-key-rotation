package oidc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Header 是 JWT 受保护头部的最小字段集合。
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Claims 是校验器关心的注册声明。
type Claims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience Audience        `json:"aud"`
	Expiry   int64           `json:"exp"`
	IssuedAt int64           `json:"iat"`
	Raw      json.RawMessage `json:"-"`
}

// Audience 同时兼容 aud 为字符串或字符串数组的写法。
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*a = Audience(multi)
	return nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Sign 使用 ES256 签发 token。
func Sign(priv *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	hb, err := json.Marshal(Header{Alg: "ES256", Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return "", err
	}
	size := ecCoordLen(priv.Curve)
	sig := make([]byte, 0, size*2)
	sig = append(sig, padLeft(r.Bytes(), size)...)
	sig = append(sig, padLeft(s.Bytes(), size)...)
	return signingInput + "." + b64(sig), nil
}

// Parse 解析并使用给定公钥验证 ES256 签名，同时返回头部与声明。
// 不做 exp/iss 等语义校验——那些由 Validator 按租户策略处理。
func Parse(token string, key *ecdsa.PublicKey) (*Header, *Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("oidc: JWT 段数不为 3")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	var header Header
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, err
	}
	if header.Alg != "ES256" {
		return nil, nil, errors.New("oidc: 仅接受 alg=ES256")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, err
	}
	size := ecCoordLen(key.Curve)
	if len(sig) != size*2 {
		return nil, nil, errors.New("oidc: ES256 签名长度非法")
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], r, s) {
		return nil, nil, ErrSignature
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, err
	}
	claims.Raw = cb
	return &header, &claims, nil
}

// NotExpired 在 now 时刻判断 token 是否仍在有效期内（含 1 秒容差）。
func (c *Claims) NotExpired(now time.Time) bool {
	return c.Expiry >= now.Unix()-1
}

// HeaderOf 仅解码 JWT 头部，不验证签名，用于在拿到公钥前读取 kid。
func HeaderOf(token string) (*Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: JWT 段数不为 3")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header Header
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

// ClaimsUnverified 仅解码声明段，用于按 iss 路由到对应租户。
// 调用方必须在之后使用对应公钥完成完整签名校验，不得信任此处的内容做安全决策。
func ClaimsUnverified(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: JWT 段数不为 3")
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, err
	}
	claims.Raw = cb
	return &claims, nil
}
