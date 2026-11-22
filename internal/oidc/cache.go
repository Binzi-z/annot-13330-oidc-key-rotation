package oidc

import (
	"crypto/ecdsa"
	"sync"
	"time"
)

// keyEntry 是缓存中的单个公钥条目。
type keyEntry struct {
	key     *ecdsa.PublicKey
	revoked bool
}

// Stats 是按签发者维度统计的刷新计数，用于演示与验收。
type Stats struct {
	FetchOK      int // 成功拉取（含被判定为迟到而丢弃的响应，因为请求确实发出了）
	FetchFailed  int // 网络/网关失败
	StaleIgnored int // 版本号不大于当前缓存、被丢弃的迟到/乱序响应
	Refreshes    int // 实际触发的刷新调用次数（合并后）
}

// snapshot 是某签发者某一时刻的不可变缓存视图。
type snapshot struct {
	version    int
	keys       map[string]*keyEntry // kid -> entry，轮换期新旧公钥并存
	fetchedAt  time.Time
	lastFailAt time.Time
	hasData    bool
}

func snapKey(s *snapshot, kid string) (*keyEntry, bool) {
	if s == nil {
		return nil, false
	}
	e, ok := s.keys[kid]
	return e, ok
}

// issuerCache 是单个签发者（租户）的隔离缓存与合并刷新协调器。
type issuerCache struct {
	mu        sync.RWMutex
	snap      *snapshot
	flight    *flightGroup
	stats     Stats
}

// TenantConfig 描述一家子公司的租户策略。
type TenantConfig struct {
	Issuer      string        // 期望的 iss 声明值，同时是 JWKS 来源
	GracePeriod time.Duration // 刷新失败后允许使用旧缓存的有限宽限
	TTL         time.Duration // 缓存新鲜期；超过后下一次校验触发刷新
}

func newIssuerCache() *issuerCache {
	return &issuerCache{
		snap:   &snapshot{keys: map[string]*keyEntry{}},
		flight: &flightGroup{},
	}
}

func (c *issuerCache) current() *snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// merge 将一份新 JWKS 合并进缓存。
// 返回 true 表示版本更新已接受；false 表示这是迟到/乱序的旧响应，被丢弃。
// 关键点：只有版本严格变大才整体替换，旧响应永远无法覆盖新版本。
func (c *issuerCache) merge(set *JWKSet) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.FetchOK++
	if c.snap.hasData && set.Version <= c.snap.version {
		c.stats.StaleIgnored++
		return false
	}
	next := &snapshot{
		version: set.Version,
		keys:    make(map[string]*keyEntry, len(set.Keys)),
		hasData: true,
	}
	for _, jwk := range set.Keys {
		pub, err := jwk.PublicKey()
		if err != nil {
			continue
		}
		next.keys[jwk.Kid] = &keyEntry{key: pub}
	}
	for _, kid := range set.Revoked {
		if e, ok := next.keys[kid]; ok {
			e.revoked = true
		}
	}
	next.fetchedAt = c.snap.fetchedAt
	next.lastFailAt = c.snap.lastFailAt
	c.snap = next
	return true
}

// markFetched 在成功接受新版本后记录拉取时间。
func (c *issuerCache) markFetched(now time.Time) {
	c.mu.Lock()
	c.snap.fetchedAt = now
	c.mu.Unlock()
}

// markFailure 记录一次刷新失败，供宽限窗口计算使用。
func (c *issuerCache) markFailure(now time.Time) {
	c.mu.Lock()
	c.stats.FetchFailed++
	c.snap.lastFailAt = now
	c.mu.Unlock()
}

// withinGrace 判断当前是否仍处于有限故障宽限内。
func (c *issuerCache) withinGrace(now time.Time, grace time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.snap.hasData || c.snap.lastFailAt.IsZero() {
		return false
	}
	return now.Sub(c.snap.lastFailAt) <= grace
}

// stale 判断缓存是否已过 TTL。
func (c *issuerCache) stale(now time.Time, ttl time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.snap.hasData {
		return true
	}
	return now.Sub(c.snap.fetchedAt) >= ttl
}

func (c *issuerCache) snapshotStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// flightGroup 实现按签发者的 single-flight：同一时刻同一签发者只允许一个在途刷新，
// 其余并发调用共享同一个结果（按签发者合并刷新）。
type flightGroup struct {
	mu      sync.Mutex
	running bool
	done    chan struct{}
	set     *JWKSet
	err     error
}

func (g *flightGroup) do(fn func() (*JWKSet, error)) (*JWKSet, error, bool) {
	g.mu.Lock()
	if g.running {
		ch := g.done
		g.mu.Unlock()
		<-ch // 等待先到者完成
		g.mu.Lock()
		set, err := g.set, g.err
		g.mu.Unlock()
		return set, err, false // false 表示本次是搭车者，不计刷新次数
	}
	g.running = true
	g.done = make(chan struct{})
	g.mu.Unlock()

	set, err := fn()

	g.mu.Lock()
	g.set, g.err = set, err
	g.running = false
	close(g.done)
	g.mu.Unlock()
	return set, err, true
}
