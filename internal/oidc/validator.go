package oidc

import (
	"context"
	"time"

	"oidc-validator/internal/clock"
)

// 默认策略参数，可被 TenantConfig 覆盖。
const (
	defaultTTL   = 10 * time.Minute
	defaultGrace = 2 * time.Minute
)

// Validator 是面向多家子公司的 OIDC 登录校验器。
// 每个注册签发者拥有彼此隔离的缓存与刷新协调器，互不影响。
type Validator struct {
	tenants map[string]*TenantConfig
	caches  map[string]*issuerCache
	fetcher JWKSFetcher
	clk     clock.Clock
}

// New 构造校验器。clock 传 nil 时使用系统时钟。
func New(fetcher JWKSFetcher, tenants []TenantConfig, clk clock.Clock) *Validator {
	if clk == nil {
		clk = clock.Real{}
	}
	v := &Validator{
		tenants: make(map[string]*TenantConfig, len(tenants)),
		caches:  make(map[string]*issuerCache, len(tenants)),
		fetcher: fetcher,
		clk:     clk,
	}
	for i := range tenants {
		t := tenants[i]
		if t.TTL <= 0 {
			t.TTL = defaultTTL
		}
		if t.GracePeriod <= 0 {
			t.GracePeriod = defaultGrace
		}
		v.tenants[t.Issuer] = &t
		v.caches[t.Issuer] = newIssuerCache()
	}
	return v
}

// Result 是一次成功校验的结果。
type Result struct {
	Issuer string
	Kid    string
	Sub    string
	Claims *Claims
}

// Validate 校验一个 ES256 JWT：
//  1. 按 iss 查找租户并做签发者绑定（两个租户即使 kid 相同也不会串用公钥）；
//  2. 在该租户隔离缓存中按 kid 解析公钥，必要时合并刷新；
//  3. 完整验证签名与 exp。
func (v *Validator) Validate(ctx context.Context, token string) (*Result, error) {
	claims, err := ClaimsUnverified(token)
	if err != nil {
		return nil, err
	}
	tenant, ok := v.tenants[claims.Issuer]
	if !ok {
		return nil, ErrUnknownTenant
	}
	header, err := HeaderOf(token)
	if err != nil {
		return nil, err
	}

	entry, err := v.resolveKey(ctx, tenant, header.Kid)
	if err != nil {
		return nil, err
	}
	// 已撤销密钥不享受任何故障宽限：无论刷新成功与否一律拒绝。
	if entry.revoked {
		return nil, ErrKeyRevoked
	}

	verified, parsedClaims, err := Parse(token, entry.key)
	if err != nil {
		return nil, err
	}
	if parsedClaims.Issuer != tenant.Issuer {
		return nil, ErrIssuerMismatch
	}
	if !parsedClaims.NotExpired(v.clk.Now()) {
		return nil, ErrTokenExpired
	}
	return &Result{
		Issuer: tenant.Issuer,
		Kid:    verified.Kid,
		Sub:    parsedClaims.Subject,
		Claims: parsedClaims,
	}, nil
}

// resolveKey 在租户隔离缓存中解析 kid，处理刷新、宽限与撤销语义。
func (v *Validator) resolveKey(ctx context.Context, tenant *TenantConfig, kid string) (*keyEntry, error) {
	cache := v.caches[tenant.Issuer]
	now := v.clk.Now()
	snap := cache.current()

	entry, found := snapKey(snap, kid)
	// 命中且缓存仍新鲜：直接使用（撤销判定留给调用方，保证无宽限）。
	if found && !cache.stale(now, tenant.TTL) {
		return entry, nil
	}

	// 缓存缺失（含未知 kid）或已过 TTL：按签发者合并刷新。
	if err := v.refreshCoalesced(ctx, tenant, cache); err != nil {
		// 冷启动没有任何缓存时，网关不可用 = 直接拒绝，不存在宽限。
		fresh := cache.current()
		if !fresh.hasData {
			return nil, ErrNoCache
		}
		// 故障期间的有限宽限：仅在宽限窗口内允许沿用旧缓存。
		if !cache.withinGrace(now, tenant.GracePeriod) {
			return nil, ErrGraceExpired
		}
		if e, ok := snapKey(fresh, kid); ok {
			return e, nil // 是否撤销由调用方统一裁决
		}
		return nil, ErrKeyNotFound
	}

	entry, found = snapKey(cache.current(), kid)
	if !found {
		return nil, ErrKeyNotFound
	}
	return entry, nil
}

// refreshCoalesced 通过 single-flight 合并同一签发者的并发刷新请求。
// 缓存合并必须由先到者在放行搭车者之前完成，否则搭车者可能读到合并前的空快照。
func (v *Validator) refreshCoalesced(ctx context.Context, tenant *TenantConfig, cache *issuerCache) error {
	_, err, _ := cache.flight.do(func() (*JWKSet, error) {
		// 本闭包仅由先到者执行一次，因此计数与缓存写入都不会重复。
		set, fetchErr := v.fetcher.FetchJWKS(ctx, tenant.Issuer)
		cache.mu.Lock()
		cache.stats.Refreshes++
		cache.mu.Unlock()
		if fetchErr != nil {
			cache.markFailure(v.clk.Now())
			return nil, fetchErr
		}
		if cache.merge(set) {
			cache.markFetched(v.clk.Now())
		}
		// 迟到的旧响应被 merge 丢弃时，不更新时间戳、不覆盖缓存。
		return set, nil
	})
	// 搭车者在此等待通道关闭，关闭时缓存已完成合并，直接共享错误结果即可。
	return err
}

// Stats 返回指定签发者的刷新统计。
func (v *Validator) Stats(issuer string) (Stats, bool) {
	c, ok := v.caches[issuer]
	if !ok {
		return Stats{}, false
	}
	return c.snapshotStats(), true
}

// AllStats 按签发者返回全部统计，供演示与验收打印。
func (v *Validator) AllStats() map[string]Stats {
	out := make(map[string]Stats, len(v.caches))
	for issuer, c := range v.caches {
		out[issuer] = c.snapshotStats()
	}
	return out
}
