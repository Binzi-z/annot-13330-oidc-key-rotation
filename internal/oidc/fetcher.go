package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// JWKSFetcher 抽象 JWKS 获取通道，便于注入可控的模拟实现。
type JWKSFetcher interface {
	FetchJWKS(ctx context.Context, issuer string) (*JWKSet, error)
}

// HTTPFetcher 通过 issuer + "/.well-known/jwks.json" 拉取 JWKS。
type HTTPFetcher struct {
	Client *http.Client
}

func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{Client: &http.Client{Timeout: 5 * time.Second}}
}

func (f *HTTPFetcher) FetchJWKS(ctx context.Context, issuer string) (*JWKSet, error) {
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: JWKS 端点返回状态码 %d", resp.StatusCode)
	}
	var set JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	return &set, nil
}
