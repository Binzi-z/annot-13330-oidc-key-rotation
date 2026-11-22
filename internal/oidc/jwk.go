package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
)

// JWK 是 JSON Web Key 的最小子集，仅支持 ES256（P-256）。
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKSet 对应 RFC 7517 的 JWKS 文档。
// Version/Revoked 是模拟签发服务在标准字段之外附加的单调版本号与撤销列表，
// 校验器据此丢弃迟到的旧响应、识别已撤销密钥。
type JWKSet struct {
	Keys    []JWK `json:"keys"`
	Version int   `json:"version"`
	Revoked []string `json:"revoked"`
}

func ecCoordLen(c elliptic.Curve) int {
	// P-256 坐标固定 32 字节；参数化以兼容其他曲线。
	return (c.Params().BitSize + 7) / 8
}

// EncodeECKey 将公钥编码为 JWK。
func EncodeECKey(kid string, pub *ecdsa.PublicKey) JWK {
	size := ecCoordLen(pub.Curve)
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	return JWK{
		Kid: kid,
		Kty: "EC",
		Crv: pub.Params().Name,
		X:   base64.RawURLEncoding.Encode(padLeft(x, size)),
		Y:   base64.RawURLEncoding.Encode(padLeft(y, size)),
	}
}

// PublicKey 将 JWK 还原为 EC 公钥。
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" {
		return nil, errors.New("oidc: 仅支持 EC 类型 JWK")
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	default:
		return nil, errors.New("oidc: 不支持的曲线 " + k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
