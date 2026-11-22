// 离线演示：整个演练只访问进程内 httptest 模拟签发服务，不访问任何外部网络。
// 运行：go run ./cmd/demo
package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"time"

	"oidc-validator/internal/clock"
	"oidc-validator/internal/mockissuer"
	"oidc-validator/internal/oidc"
)

const (
	kidOld = "shared-kid"
	kidNew = "rotated-kid"
	ttl    = time.Minute
	grace  = 2 * time.Minute
)

func main() {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC))
	exp := clk.Now().Add(30 * time.Minute).Unix()

	srvA := mockissuer.New()
	srvB := mockissuer.New()
	defer srvA.Close()
	defer srvB.Close()

	privA, err := mockissuer.NewPrivateKey()
	must(err)
	privB, err := mockissuer.NewPrivateKey()
	must(err)
	privRotated, err := mockissuer.NewPrivateKey()
	must(err)

	v := oidc.New(oidc.NewHTTPFetcher(), []oidc.TenantConfig{
		{Issuer: srvA.Issuer(), TTL: ttl, GracePeriod: grace},
		{Issuer: srvB.Issuer(), TTL: ttl, GracePeriod: grace},
	}, clk)

	tokenA := sign(privA, kidOld, srvA.Issuer(), "alice", exp)
	tokenB := sign(privB, kidOld, srvB.Issuer(), "bob", exp)
	tokenRotated := sign(privRotated, kidNew, srvA.Issuer(), "alice", exp)

	fmt.Println("== 离线 OIDC 校验演示（两家子公司，相同 kid，本地模拟签发） ==")
	fmt.Printf("租户 A 签发者: %s\n租户 B 签发者: %s\n\n", srvA.Issuer(), srvB.Issuer())

	// 阶段 1：正常上线，两租户各自拉取 JWKS。
	srvA.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: kidOld, Pub: &privA.PublicKey},
	}))
	srvB.QueueSet(mockissuer.KeySet(1, []mockissuer.PublishedKey{
		{Kid: kidOld, Pub: &privB.PublicKey},
	}))
	step("1. 正常登录（缓存冷启动，各刷新一次）", func() {
		check(v, ctx, "A/alice", tokenA, true)
		check(v, ctx, "B/bob", tokenB, true)
	})

	// 阶段 2：轮换，新旧公钥并存；旧响应（v2）比新响应（v3）迟到。
	srvA.QueueSet(mockissuer.KeySet(3, []mockissuer.PublishedKey{
		{Kid: kidOld, Pub: &privA.PublicKey},
		{Kid: kidNew, Pub: &privRotated.PublicKey},
	}))
	srvA.QueueSet(mockissuer.KeySet(2, []mockissuer.PublishedKey{
		{Kid: kidOld, Pub: &privA.PublicKey}, // 迟到的旧响应，缺少 rotated-kid
	}))
	clk.Advance(ttl + time.Second)
	step("2. 密钥轮换 + 迟到旧响应（新版本不得被覆盖）", func() {
		check(v, ctx, "A/新kid", tokenRotated, true) // 触发 v3
		clk.Advance(ttl + time.Second)
		check(v, ctx, "A/旧kid(并存)", tokenA, true) // 触发迟到的 v2，应被丢弃
		check(v, ctx, "A/新kid(仍有效)", tokenRotated, true)
	})

	// 阶段 3：撤销事件乱序：v5 先到（含撤销），迟到的 v4 不含撤销。
	srvA.QueueSet(mockissuer.KeySet(5,
		[]mockissuer.PublishedKey{{Kid: kidOld, Pub: &privA.PublicKey}},
		kidOld))
	srvA.QueueSet(mockissuer.KeySet(4,
		[]mockissuer.PublishedKey{{Kid: kidOld, Pub: &privA.PublicKey}}))
	clk.Advance(ttl + time.Second)
	step("3. 撤销事件乱序（撤销状态不得被旧响应复活）", func() {
		check(v, ctx, "A/旧kid 撤销生效", tokenA, false)
		clk.Advance(ttl + time.Second)
		check(v, ctx, "A/旧kid 乱序后仍拒绝", tokenA, false)
	})

	// 阶段 4：A 网关故障。已撤销密钥无宽限；B 凭隔离缓存正常登录（冷启动无宽限见验收测试 7）。
	srvA.SetOffline(true)
	clk.Advance(ttl + time.Second)
	step("4. 网关故障演练（撤销无宽限 / 其他租户不受影响）", func() {
		// A：已撤销密钥即使在故障期也一律拒绝，而不是走宽限。
		check(v, ctx, "A/已撤销密钥(故障期)", tokenA, false)
		// B：缓存隔离且仍新鲜，登录完全正常。
		check(v, ctx, "B/bob(故障隔离)", tokenB, true)
	})

	// 阶段 5：B 也过 TTL 后进入故障宽限，窗口内放行、窗口外拒绝。
	clk.Advance(ttl)
	step("5. 有限故障宽限（窗口内可用，超出即拒绝）", func() {
		srvB.SetOffline(true)
		clk.Advance(time.Second)
		check(v, ctx, "B/宽限窗口内", tokenB, true)
		clk.Advance(grace + time.Second)
		check(v, ctx, "B/宽限耗尽", tokenB, false)
	})

	fmt.Println("\n== 按签发者统计的刷新次数 ==")
	for issuer, s := range v.AllStats() {
		tag := "租户A"
		if issuer == srvB.Issuer() {
			tag = "租户B"
		}
		fmt.Printf("%s 刷新=%d 成功=%d 失败=%d 迟到丢弃=%d\n",
			tag, s.Refreshes, s.FetchOK, s.FetchFailed, s.StaleIgnored)
	}
}

func sign(priv *ecdsa.PrivateKey, kid, issuer, sub string, exp int64) string {
	tok, err := mockissuer.Sign(priv, kid, issuer, sub, exp)
	must(err)
	return tok
}

func step(title string, fn func()) {
	fmt.Printf("\n--- %s ---\n", title)
	fn()
}

func check(v *oidc.Validator, ctx context.Context, name, token string, wantOK bool) {
	_, err := v.Validate(ctx, token)
	gotOK := err == nil
	status := "通过"
	if gotOK != wantOK {
		status = "不符合预期"
	}
	if err != nil {
		fmt.Printf("  %-24s 结果=拒绝(%v) 期望=%-4s %s\n", name, sanitize(err), want(wantOK), status)
	} else {
		fmt.Printf("  %-24s 结果=放行           期望=%-4s %s\n", name, want(wantOK), status)
	}
}

func want(ok bool) string {
	if ok {
		return "放行"
	}
	return "拒绝"
}

func sanitize(err error) string {
	for _, target := range []error{
		oidc.ErrNoCache, oidc.ErrGraceExpired, oidc.ErrKeyRevoked,
		oidc.ErrKeyNotFound, oidc.ErrSignature, oidc.ErrUnknownTenant,
	} {
		if errors.Is(err, target) {
			return target.Error()
		}
	}
	return err.Error()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "演示失败:", err)
		os.Exit(1)
	}
}
