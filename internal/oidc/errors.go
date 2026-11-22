package oidc

import "errors"

var (
	// ErrUnknownTenant 表示 token 的签发者没有注册到校验器。
	ErrUnknownTenant = errors.New("oidc: 未知签发者（租户未注册）")
	// ErrIssuerMismatch 表示签发者绑定校验失败。
	ErrIssuerMismatch = errors.New("oidc: 签发者绑定不匹配")
	// ErrSignature 表示 ES256 签名验证失败。
	ErrSignature = errors.New("oidc: 签名验证失败")
	// ErrKeyRevoked 表示命中的 kid 已在撤销列表中——撤销不享受故障宽限。
	ErrKeyRevoked = errors.New("oidc: 签名密钥已被撤销")
	// ErrKeyNotFound 表示 JWKS 中不存在该 kid。
	ErrKeyNotFound = errors.New("oidc: JWKS 中找不到对应 kid")
	// ErrNoCache 表示冷启动且网关不可用，本地没有任何可用缓存。
	ErrNoCache = errors.New("oidc: 冷启动且无法获取 JWKS")
	// ErrGraceExpired 表示刷新失败，且已超出有限故障宽限窗口。
	ErrGraceExpired = errors.New("oidc: 刷新失败且故障宽限已耗尽")
	// ErrTokenExpired 表示 token 自身的 exp 已过期。
	ErrTokenExpired = errors.New("oidc: token 已过期")
)
