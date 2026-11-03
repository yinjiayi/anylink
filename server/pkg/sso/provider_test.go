package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

const testNonce = "server-generated-oidc-nonce"

var testVerifier = strings.Repeat("v", 64)

type providerFixture struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	tokenCalls    atomic.Int32
	userInfoCalls atomic.Int32
	mode          string
	userinfo      string
	redirect      string
	metadataHTTP  bool
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &providerFixture{key: key, userinfo: `{"id":"stable-123"}`}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			tokenURL := f.server.URL + "/token"
			if f.metadataHTTP {
				tokenURL = "http://idp.invalid/token"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize",
				"token_endpoint": tokenURL, "jwks_uri": f.server.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		case "/token":
			f.tokenCalls.Add(1)
			if f.mode == "token-redirect" {
				http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("code_verifier") != testVerifier || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != "https://vpn.example.test/+CSCOE+/sso/callback" {
				t.Error("token request omitted PKCE, code grant or fixed callback")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			client, secret, basic := r.BasicAuth()
			if !basic {
				client, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
			}
			if client != "vpn-client" || secret != "client-secret" {
				t.Error("token request client authentication missing")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			code := r.Form.Get("code")
			if code == "bad-code" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_grant","error_description":"sensitive-provider-details"}`)
				return
			}
			claims := jwt.MapClaims{
				"iss": f.server.URL, "aud": "vpn-client", "sub": "stable-123", "nonce": testNonce,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			}
			switch code {
			case "wrong-issuer":
				claims["iss"] = "https://another-idp.invalid"
			case "wrong-audience":
				claims["aud"] = "another-client"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "wrong-nonce":
				claims["nonce"] = "other-session"
			case "missing-nonce":
				delete(claims, "nonce")
			case "missing-subject":
				delete(claims, "sub")
			case "wrong-azp":
				claims["azp"] = "another-client"
			case "multi-audience-no-azp":
				claims["aud"] = []string{"vpn-client", "another-client"}
			case "multi-audience":
				claims["aud"] = []string{"vpn-client", "another-client"}
				claims["azp"] = "vpn-client"
			case "wrong-access-hash":
				claims["at_hash"] = "wrong"
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test-key"
			signingKey := key
			if code == "wrong-signature" {
				var err error
				signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Error(err)
				}
			}
			signed, err := token.SignedString(signingKey)
			if err != nil {
				t.Error(err)
			}
			response := map[string]any{"access_token": "access-secret", "token_type": "Bearer", "expires_in": 60, "id_token": signed}
			if code == "missing-id-token" {
				delete(response, "id_token")
			}
			if code == "wrong-token-type" {
				response["token_type"] = "mac"
			}
			if code == "expired-access-token" {
				response["expires_in"] = -60
			}
			json.NewEncoder(w).Encode(response)
		case "/userinfo":
			f.userInfoCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer access-secret" {
				t.Error("userinfo request omitted bearer token")
			}
			if f.mode == "userinfo-redirect" {
				http.Redirect(w, r, f.redirect, http.StatusFound)
				return
			}
			if f.mode == "userinfo-error" {
				w.WriteHeader(http.StatusUnauthorized)
			}
			fmt.Fprint(w, f.userinfo)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *providerFixture) config(kind string) Config {
	return Config{
		Type: kind, Issuer: f.server.URL, ClientID: "vpn-client", ClientSecret: "client-secret",
		PublicURL: "https://vpn.example.test", Scopes: []string{"profile"}, BrowserMode: "auto",
		AuthorizationURL: f.server.URL + "/authorize", TokenURL: f.server.URL + "/token",
		UserInfoURL: f.server.URL + "/userinfo", SubjectClaim: map[string]string{"oidc": "sub", "oauth2": "id"}[kind],
		SubjectUsers: map[string]string{"stable-123": "alice"},
	}
}

func (f *providerFixture) provider(t *testing.T, kind string) *Provider {
	t.Helper()
	p, err := NewProvider(oidc.ClientContext(context.Background(), f.server.Client()), f.config(kind))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProviderAuthorizationCodePKCE(t *testing.T) {
	f := newProviderFixture(t)
	p := f.provider(t, "oidc")
	u, err := url.Parse(p.AuthorizationURL("bound-state", testNonce, testVerifier))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(testVerifier))
	expected := map[string]string{
		"response_type": "code", "client_id": "vpn-client", "state": "bound-state", "nonce": testNonce,
		"redirect_uri": "https://vpn.example.test/+CSCOE+/sso/callback", "scope": "openid profile",
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(hash[:]),
	}
	for key, value := range expected {
		if got := u.Query().Get(key); got != value {
			t.Errorf("authorization parameter %s = %q, want %q", key, got, value)
		}
	}
	if u.Query().Has("client_secret") {
		t.Fatal("authorization URL exposed client secret")
	}
	for _, values := range [][3]string{{"", testNonce, testVerifier}, {"state", "", testVerifier}, {"state", testNonce, "short"}} {
		if p.AuthorizationURL(values[0], values[1], values[2]) != "" {
			t.Fatal("accepted incomplete transaction secrets")
		}
	}
}

func TestOIDCValidateIdentity(t *testing.T) {
	f := newProviderFixture(t)
	p := f.provider(t, "oidc")
	for _, code := range []string{"good-code", "multi-audience"} {
		subject, err := p.Authenticate(context.Background(), code, testNonce, testVerifier)
		if err != nil || subject != "stable-123" {
			t.Fatalf("valid identity: subject=%q, err=%v", subject, err)
		}
	}
	for _, code := range []string{
		"wrong-issuer", "wrong-audience", "expired", "wrong-nonce", "missing-nonce",
		"wrong-signature", "missing-subject", "missing-id-token", "bad-code", "wrong-azp",
		"multi-audience-no-azp", "wrong-access-hash", "wrong-token-type", "expired-access-token",
	} {
		t.Run(code, func(t *testing.T) {
			subject, err := p.Authenticate(context.Background(), code, testNonce, testVerifier)
			if subject != "" || !errors.Is(err, ErrAuthentication) {
				t.Fatalf("accepted invalid OIDC response: subject=%q, err=%v", subject, err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive-provider-details") {
				t.Fatal("error exposed provider response")
			}
		})
	}
	if f.userInfoCalls.Load() != 0 {
		t.Fatal("OIDC must use verified ID-token identity, not unverified userinfo")
	}
	before := f.tokenCalls.Load()
	for _, nonce := range []string{""} {
		if _, err := p.Authenticate(context.Background(), "good-code", nonce, testVerifier); err == nil {
			t.Fatal("accepted an absent nonce")
		}
	}
	if _, err := p.Authenticate(context.Background(), "good-code", testNonce, "bad verifier"); err == nil {
		t.Fatal("accepted an invalid verifier")
	}
	if f.tokenCalls.Load() != before {
		t.Fatal("invalid local transaction reached provider")
	}
}

func TestOAuth2UserInfoIdentity(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"string", `{"id":"stable-123"}`, "stable-123"},
		{"large-integer", `{"id":9007199254740993}`, "9007199254740993"},
		{"missing", `{"email":"alice@example.test"}`, ""},
		{"empty", `{"id":""}`, ""},
		{"null", `{"id":null}`, ""},
		{"object", `{"id":{"sub":"123"}}`, ""},
		{"float", `{"id":123.4}`, ""},
		{"noncanonical-number", `{"id":1e3}`, ""},
		{"control", `{"id":"a\nb"}`, ""},
		{"trailing-json", `{"id":"stable-123"}{}`, ""},
		{"malformed", `{"id":`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFixture(t)
			f.userinfo = tc.body
			p := f.provider(t, "oauth2")
			subject, err := p.Authenticate(context.Background(), "good-code", testNonce, testVerifier)
			if tc.want != "" {
				if err != nil || subject != tc.want {
					t.Fatalf("subject=%q, err=%v", subject, err)
				}
			} else if subject != "" || !errors.Is(err, ErrAuthentication) {
				t.Fatalf("accepted malformed identity: subject=%q, err=%v", subject, err)
			}
		})
	}
}

func TestProviderRefusesCredentialRedirect(t *testing.T) {
	var leaked atomic.Int32
	trap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer trap.Close()
	for _, mode := range []string{"token-redirect", "userinfo-redirect"} {
		t.Run(mode, func(t *testing.T) {
			f := newProviderFixture(t)
			f.mode, f.redirect = mode, trap.URL
			p := f.provider(t, "oauth2")
			if _, err := p.Authenticate(context.Background(), "good-code", testNonce, testVerifier); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("accepted redirect: %v", err)
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("followed a redirect carrying provider credentials")
	}
}

func TestProviderTransportAndDiscovery(t *testing.T) {
	f := newProviderFixture(t)
	if _, err := NewProvider(context.Background(), f.config("oidc")); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("untrusted TLS certificate accepted: %v", err)
	}
	f.metadataHTTP = true
	if _, err := NewProvider(oidc.ClientContext(context.Background(), f.server.Client()), f.config("oidc")); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("discovered plaintext endpoint accepted: %v", err)
	}
	p := f.provider(t, "oauth2")
	if p.client.Timeout != 10*time.Second || p.client.Jar != nil {
		t.Fatal("provider HTTP client is not isolated and bounded")
	}
	if p.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("provider redirects not refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Authenticate(ctx, "good-code", testNonce, testVerifier); !errors.Is(err, ErrAuthentication) {
		t.Fatal("canceled request accepted")
	}
}

func TestProviderSurvivesDiscoveryRequestCancellation(t *testing.T) {
	f := newProviderFixture(t)
	discoveryCtx, cancel := context.WithCancel(oidc.ClientContext(context.Background(), f.server.Client()))
	p, err := NewProvider(discoveryCtx, f.config("oidc"))
	if err != nil {
		t.Fatal(err)
	}
	// The browser initiation request has now finished. Callback authentication
	// must use its new context, including a first uncached JWKS fetch.
	cancel()
	subject, err := p.Authenticate(context.Background(), "good-code", testNonce, testVerifier)
	if err != nil || subject != "stable-123" {
		t.Fatalf("discovery context cancellation leaked into callback: subject=%q, err=%v", subject, err)
	}
}

func TestConfigRejectsUnsafeInputs(t *testing.T) {
	valid := Config{Type: "oidc", Issuer: "https://idp.example.test/realms/test", ClientID: "vpn", PublicURL: "https://vpn.example.test"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://vpn.example.test", "https://vpn.example.test/path", "https://vpn.example.test/", "https://vpn.example.test?x=1", "https://vpn.example.test#frag", "https://user:pass@vpn.example.test", "//vpn.example.test"} {
		c := valid
		c.PublicURL = raw
		if c.Validate() == nil {
			t.Errorf("accepted public origin %q", raw)
		}
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Type = "local" },
		func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.Issuer = "http://idp.example.test" },
		func(c *Config) { c.BrowserMode = "unexpected" },
		func(c *Config) { c.SubjectClaim = "email" },
		func(c *Config) { c.Scopes = []string{"profile email"} },
		func(c *Config) { c.SubjectUsers = map[string]string{"": "alice"} },
		func(c *Config) { c.SubjectUsers = map[string]string{"subject": ""} },
	} {
		c := valid
		mutate(&c)
		if c.Validate() == nil {
			t.Error("accepted invalid config")
		}
	}
	c := valid
	c.Type, c.SubjectClaim = "oauth2", "id"
	c.AuthorizationURL, c.TokenURL, c.UserInfoURL = "https://idp.example.test/auth", "https://idp.example.test/token", "https://idp.example.test/user"
	if c.Validate() != nil {
		t.Fatal("valid OAuth2 configuration rejected")
	}
	c.UserInfoURL = "http://idp.example.test/user"
	if c.Validate() == nil {
		t.Fatal("plaintext OAuth2 userinfo accepted")
	}
}

func TestOAuth2RefusesFailedOrOversizedUserInfo(t *testing.T) {
	for _, mode := range []string{"userinfo-error", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := newProviderFixture(t)
			f.mode = mode
			if mode == "oversize" {
				f.userinfo = `{"id":"` + strings.Repeat("a", maxUserInfoBytes) + `"}`
			}
			p := f.provider(t, "oauth2")
			if _, err := p.Authenticate(context.Background(), "good-code", testNonce, testVerifier); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("accepted invalid userinfo response: %v", err)
			}
		})
	}
}

// Compile-time guard that the context hook accepted by the package is the same
// standard oauth2 client hook used by oidc.ClientContext.
func TestCustomHTTPContext(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	ctx := oidc.ClientContext(context.Background(), client)
	if ctx.Value(oauth2.HTTPClient) != client {
		t.Fatal("unexpected HTTP client context key")
	}
}
