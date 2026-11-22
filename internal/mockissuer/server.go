// Package mockissuer 提供进程内的本地模拟 OIDC 签发服务，
// 不依赖任何外部网络，支持脚本化 JWKS、网关故障注入、阻塞式响应（确定性并发）
// 以及迟到/乱序响应的编排。
package mockissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"

	"oidc-validator/internal/oidc"
)

// PublishedKey 是模拟服务对外发布的一把密钥。
type PublishedKey struct {
	Kid string
	Pub *ecdsa.PublicKey
}

// KeySet 按版本构造一份 JWKS 脚本。
func KeySet(version int, keys []PublishedKey, revoked ...string) *oidc.JWKSet {
	set := &oidc.JWKSet{Version: version, Revoked: revoked}
	for _, k := range keys {
		set.Keys = append(set.Keys, oidc.EncodeECKey(k.Kid, k.Pub))
	}
	return set
}

// NewPrivateKey 生成一把 P-256 私钥。
func NewPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Sign 使用给定私钥与 kid 签发 ES256 token。
func Sign(priv *ecdsa.PrivateKey, kid, issuer, sub string, expUnix int64) (string, error) {
	return oidc.Sign(priv, kid, map[string]any{
		"iss": issuer,
		"sub": sub,
		"aud": "gateway",
		"exp": expUnix,
		"iat": expUnix - 60,
	})
}

// Stub 是一次 JWKS 请求的脚本响应。
type Stub struct {
	Set      *oidc.JWKSet // 成功响应；nil 时按 StatusCode 返回故障
	StatusCode int        // 非 200 时模拟网关错误
	Block    chan struct{} // 非 nil 时阻塞直到该通道关闭，用于确定性并发编排
	Offline  bool         // 模拟网关整体不可用（连接层之外的 503）
}

// Server 是一个脚本驱动的模拟签发服务。
type Server struct {
	issuer   string
	mu       sync.Mutex
	stubs    []*Stub
	offline  bool
	reqCount int
	srv      *httptest.Server
}

// New 启动模拟服务并返回其实例，Issuer() 即签发者标识。
func New() *Server {
	s := &Server{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	s.issuer = s.srv.URL
	return s
}

func (s *Server) Issuer() string { return s.issuer }

func (s *Server) Close() { s.srv.Close() }

// SetOffline 切换网关整体可用状态（冷启动故障演练用）。
func (s *Server) SetOffline(off bool) {
	s.mu.Lock()
	s.offline = off
	s.mu.Unlock()
}

// Queue 将一个响应脚本入队，按 FIFO 响应后续 JWKS 请求。
func (s *Server) Queue(stub *Stub) {
	s.mu.Lock()
	s.stubs = append(s.stubs, stub)
	s.mu.Unlock()
}

// QueueSet 是 Queue(KeySet(...)) 的便捷封装。
func (s *Server) QueueSet(set *oidc.JWKSet) { s.Queue(&Stub{Set: set}) }

// RequestCount 返回 JWKS 端点实际收到的请求数（配合阻塞脚本可验证合并刷新）。
func (s *Server) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqCount
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/jwks.json" {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	if s.offline {
		s.mu.Unlock()
		http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(s.stubs) == 0 {
		s.mu.Unlock()
		http.Error(w, "no scripted response", http.StatusServiceUnavailable)
		return
	}
	stub := s.stubs[0]
	s.stubs = s.stubs[1:]
	s.reqCount++
	s.mu.Unlock()

	if stub.Block != nil {
		<-stub.Block // 确定性挂起，直到测试放行
	}
	if stub.Offline || stub.StatusCode == http.StatusServiceUnavailable {
		http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	if stub.StatusCode != 0 && stub.StatusCode != http.StatusOK {
		http.Error(w, "upstream error", stub.StatusCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stub.Set)
}
