package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"
	"time"

	"oidc-validator/internal/clock"
	"oidc-validator/internal/mockissuer"
	"oidc-validator/internal/oidc"
)

const (
	ttl   = time.Minute
	grace = 2 * time.Minute
)

// 两家子公司刻意使用相同 kid，但各自持有独立密钥。
const sharedKid = "shared-kid"

type fixture struct {
	issA  string
	issB  string
	privA *ecdsa.PrivateKey
	privB *ecdsa.PrivateKey
	srvA  *mockissuer.Server
	srvB  *mockissuer.Server
	clk   *clock.Fake
	v     *oidc.Validator
	exp   int64
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := mockissuer.NewPrivateKey()
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return k
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srvA := mockissuer.New()
	srvB := mockissuer.New()
	t.Cleanup(srvA.Close)
	t.Cleanup(srvB.Close)

	kA := mustKey(t)
	kB := mustKey(t)
	clk := clock.NewFake(time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC))

	v := oidc.New(oidc.NewHTTPFetcher(), []oidc.TenantConfig{
		{Issuer: srvA.Issuer(), TTL: ttl, GracePeriod: grace},
		{Issuer: srvB.Issuer(), TTL: ttl, GracePeriod: grace},
	}, clk)

	return &fixture{
		issA: srvA.Issuer(), issB: srvB.Issuer(),
		privA: kA, privB: kB,
		srvA: srvA, srvB: srvB,
		clk: clk, v: v,
		exp: clk.Now().Add(10 * time.Minute).Unix(),
	}
}

func (f *fixture) tokenA(kid string) string {
	tok, err := mockissuer.Sign(f.privA, kid, f.issA, "user-A", f.exp)
	if err != nil {
		panic(err)
	}
	return tok
}

func (f *fixture) tokenB(kid string) string {
	tok, err := mockissuer.Sign(f.privB, kid, f.issB, "user-B", f.exp)
	if err != nil {
		panic(err)
	}
	return tok
}

func waitRequests(t *testing.T, srv *mockissuer.Server, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.RequestCount() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待 %d 个在途请求超时，实际 %d", want, srv.RequestCount())
}

// 验收 1：签发者绑定 + 相同 kid 的租户隔离。
func TestIssuerBindingAndTenantIsolation(t *testing.T) {
	f := newFixture(t)
	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	f.srvB.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privB.PublicKey},
	}))

	resA, err := f.v.Validate(context.Background(), f.tokenA(sharedKid))
	if err != nil {
		t.Fatalf("租户 A 登录失败: %v", err)
	}
	if resA.Issuer != f.issA || resA.Sub != "user-A" {
		t.Fatalf("租户 A 结果异常: %+v", resA)
	}
	resB, err := f.v.Validate(context.Background(), f.tokenB(sharedKid))
	if err != nil {
		t.Fatalf("租户 B 登录失败: %v", err)
	}
	if resB.Issuer != f.issB {
		t.Fatalf("租户 B 结果异常: %+v", resB)
	}

	// 跨租户伪造：声称来自 A（iss=A），却用 B 的私钥签名。
	// 两个租户 kid 刻意相同，若缓存串用或不做签发者绑定，此 token 会被误接受。
	forged, err := mockissuer.Sign(f.privB, sharedKid, f.issA, "attacker", f.exp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.Validate(context.Background(), forged); !errors.Is(err, oidc.ErrSignature) {
		t.Fatalf("租户 A 不应接受 B 私钥签发的 token，期望签名失败，得到 %v", err)
	}

	// 未知签发者直接拒绝。
	foreign, err := mockissuer.Sign(f.privA, sharedKid, "https://evil.example", "x", f.exp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.Validate(context.Background(), foreign); !errors.Is(err, oidc.ErrUnknownTenant) {
		t.Fatalf("期望未知签发者错误，得到 %v", err)
	}
}

// 验收 2：轮换期新旧公钥并存，TTL 过后再次刷新。
func TestRotationBothKeysCoexist(t *testing.T) {
	f := newFixture(t)
	newKey := mustKey(t)
	const newKid = "rotated-kid"

	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	oldTok := f.tokenA(sharedKid)
	if _, err := f.v.Validate(context.Background(), oldTok); err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}

	// v2：新旧两把公钥并存（kid 不同）。
	f.srvA.QueueSet(mockissuer.KeySet(2, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
		{Kid: newKid, Pub: &newKey.PublicKey},
	}))
	newTok, err := mockissuer.Sign(newKey, newKid, f.issA, "user-A2", f.exp)
	if err != nil {
		t.Fatal(err)
	}

	// TTL 内使用缓存：新 kid 尚不可见。
	if _, err := f.v.Validate(context.Background(), newTok); !errors.Is(err, oidc.ErrKeyNotFound) {
		t.Fatalf("期望 kid 未找到，得到 %v", err)
	}
	f.clk.Advance(ttl + time.Second)

	if _, err := f.v.Validate(context.Background(), newTok); err != nil {
		t.Fatalf("轮换后新 token 校验失败: %v", err)
	}
	// 旧 token 在轮换并存期内仍可登录。
	if _, err := f.v.Validate(context.Background(), oldTok); err != nil {
		t.Fatalf("旧公钥应在并存期内继续有效，得到 %v", err)
	}
}

// 验收 3：并发未知 kid 只触发一次上游刷新（按签发者合并），所有请求成功。
func TestConcurrentUnknownKidCoalesced(t *testing.T) {
	f := newFixture(t)
	block := make(chan struct{})
	f.srvA.Queue(&mockissuer.Stub{
		Block: block,
		Set: mockissuer.KeySet(1, []mockissuer.PublishedKey{
			{Kid: sharedKid, Pub: &f.privA.PublicKey},
		}),
	})

	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.v.Validate(context.Background(), f.tokenA(sharedKid))
		}(i)
	}
	waitRequests(t, f.srvA, 1)
	// 给并发 goroutine 足够时间抵达后，确认在途请求始终只有一个。
	time.Sleep(20 * time.Millisecond)
	if got := f.srvA.RequestCount(); got != 1 {
		t.Fatalf("合并刷新失效：期望 1 个上游请求，得到 %d", got)
	}
	close(block)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发校验 #%d 失败: %v", i, err)
		}
	}
	stats, _ := f.v.Stats(f.issA)
	if stats.Refreshes != 1 {
		t.Fatalf("期望刷新计数 1，得到 %d", stats.Refreshes)
	}
	if stats.FetchFailed != 0 || stats.StaleIgnored != 0 {
		t.Fatalf("统计异常: %+v", stats)
	}
}

// 验收 4：迟到的旧版本刷新响应不能覆盖新版本缓存。
func TestStaleRefreshCannotOverwrite(t *testing.T) {
	f := newFixture(t)
	newKey := mustKey(t)
	const newKid = "rotated-kid"

	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	oldTok := f.tokenA(sharedKid)
	if _, err := f.v.Validate(context.Background(), oldTok); err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}

	// 下一次刷新先返回 v3（新），再返回迟到的 v2（旧，不含新 kid）。
	f.srvA.QueueSet(mockissuer.KeySet(3, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
		{Kid: newKid, Pub: &newKey.PublicKey},
	}))
	f.srvA.QueueSet(mockissuer.KeySet(2, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	newTok, err := mockissuer.Sign(newKey, newKid, f.issA, "user-A2", f.exp)
	if err != nil {
		t.Fatal(err)
	}

	f.clk.Advance(ttl + time.Second)
	if _, err := f.v.Validate(context.Background(), newTok); err != nil {
		t.Fatalf("v3 刷新后新 token 应可用: %v", err)
	}
	f.clk.Advance(ttl + time.Second)
	// 触发迟到的 v2 响应：必须被版本号判定丢弃。
	if _, err := f.v.Validate(context.Background(), oldTok); err != nil {
		t.Fatalf("旧 token 仍应可校验: %v", err)
	}
	stats, _ := f.v.Stats(f.issA)
	if stats.StaleIgnored != 1 {
		t.Fatalf("期望 1 次迟到响应被丢弃，得到 %+v", stats)
	}
	// 新 kid 依旧存在，证明旧响应没有覆盖新缓存。
	if _, err := f.v.Validate(context.Background(), newTok); err != nil {
		t.Fatalf("新版本缓存被旧响应覆盖: %v", err)
	}
}

// 验收 5：撤销事件乱序到达——先到 v3（含撤销），迟到 v2（不含撤销），撤销状态保持。
func TestOutOfOrderRevocationKeepsRevoked(t *testing.T) {
	f := newFixture(t)
	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	tok := f.tokenA(sharedKid)
	if _, err := f.v.Validate(context.Background(), tok); err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}

	// v3 撤销 shared-kid；随后乱序/迟到的 v2 不含撤销信息。
	f.srvA.QueueSet(mockissuer.KeySet(3,
		[]mockissuer.PublishedKey{{Kid: sharedKid, Pub: &f.privA.PublicKey}},
		sharedKid))
	f.srvA.QueueSet(mockissuer.KeySet(2, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))

	f.clk.Advance(ttl + time.Second)
	if _, err := f.v.Validate(context.Background(), tok); !errors.Is(err, oidc.ErrKeyRevoked) {
		t.Fatalf("期望密钥已撤销错误，得到 %v", err)
	}
	f.clk.Advance(ttl + time.Second)
	if _, err := f.v.Validate(context.Background(), tok); !errors.Is(err, oidc.ErrKeyRevoked) {
		t.Fatalf("乱序旧响应不得清除撤销标记，得到 %v", err)
	}
	stats, _ := f.v.Stats(f.issA)
	if stats.StaleIgnored != 1 {
		t.Fatalf("期望乱序响应被丢弃 1 次，得到 %+v", stats)
	}
}

// 验收 6：已撤销密钥在网关故障期间没有任何宽限。
func TestRevokedKeyHasNoGrace(t *testing.T) {
	f := newFixture(t)
	f.srvA.QueueSet(mockissuer.KeySet(1,
		[]mockissuer.PublishedKey{{Kid: sharedKid, Pub: &f.privA.PublicKey}},
		sharedKid))
	tok := f.tokenA(sharedKid)
	if _, err := f.v.Validate(context.Background(), tok); !errors.Is(err, oidc.ErrKeyRevoked) {
		t.Fatalf("撤销应立即生效，得到 %v", err)
	}

	// 网关彻底不可用 + TTL 过期 + 时钟推进到宽限窗口内：撤销仍然拒绝。
	f.srvA.SetOffline(true)
	f.clk.Advance(ttl + time.Second)
	if _, err := f.v.Validate(context.Background(), tok); !errors.Is(err, oidc.ErrKeyRevoked) {
		t.Fatalf("已撤销密钥不得享受故障宽限，得到 %v", err)
	}
}

// 验收 7：冷启动网关不可用 -> ErrNoCache；宽限窗口内旧缓存可用，超出窗口拒绝。
func TestColdStartAndGraceWindow(t *testing.T) {
	f := newFixture(t)
	f.srvA.SetOffline(true)
	if _, err := f.v.Validate(context.Background(), f.tokenA(sharedKid)); !errors.Is(err, oidc.ErrNoCache) {
		t.Fatalf("冷启动应返回 ErrNoCache，得到 %v", err)
	}

	// 网关恢复，建立缓存。
	f.srvA.SetOffline(false)
	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	tok := f.tokenA(sharedKid)
	if _, err := f.v.Validate(context.Background(), tok); err != nil {
		t.Fatalf("网关恢复后登录失败: %v", err)
	}

	// 再次故障 + TTL 过期。
	f.srvA.SetOffline(true)
	f.clk.Advance(ttl + time.Second)
	if _, err := f.v.Validate(context.Background(), tok); err != nil {
		t.Fatalf("宽限窗口内应允许沿用旧缓存: %v", err)
	}
	// 推进到宽限窗口之外。
	f.clk.Advance(grace + time.Second)
	if _, err := f.v.Validate(context.Background(), tok); !errors.Is(err, oidc.ErrGraceExpired) {
		t.Fatalf("宽限耗尽应返回 ErrGraceExpired，得到 %v", err)
	}
}

// 验收 8：一家租户网关故障期间，另一家租户登录完全不受影响。
func TestOtherTenantUnaffectedDuringOutage(t *testing.T) {
	f := newFixture(t)
	f.srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privA.PublicKey},
	}))
	f.srvB.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: sharedKid, Pub: &f.privB.PublicKey},
	}))
	if _, err := f.v.Validate(context.Background(), f.tokenA(sharedKid)); err != nil {
		t.Fatalf("A 预热失败: %v", err)
	}
	if _, err := f.v.Validate(context.Background(), f.tokenB(sharedKid)); err != nil {
		t.Fatalf("B 预热失败: %v", err)
	}

	f.srvA.SetOffline(true)
	f.clk.Advance(ttl + time.Second)

	// A 在宽限内仍可登录；B 的缓存独立且新鲜，正常登录。
	if _, err := f.v.Validate(context.Background(), f.tokenA(sharedKid)); err != nil {
		t.Fatalf("A 宽限内登录失败: %v", err)
	}
	if _, err := f.v.Validate(context.Background(), f.tokenB(sharedKid)); err != nil {
		t.Fatalf("B 不应受 A 故障影响: %v", err)
	}

	// A 的故障计数不应出现在 B 的统计中。
	statsA, _ := f.v.Stats(f.issA)
	statsB, _ := f.v.Stats(f.issB)
	if statsA.FetchFailed == 0 {
		t.Fatalf("A 应记录刷新失败: %+v", statsA)
	}
	if statsB.FetchFailed != 0 {
		t.Fatalf("B 不应有任何失败计数: %+v", statsB)
	}
}
