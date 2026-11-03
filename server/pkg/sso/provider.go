package sso

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config is stored on a VPN group. SubjectUsers maps an immutable identity at
// this provider to an existing local user; authorization is checked by dbdata.
// OAuth2 alone is not an identity protocol, so its userinfo endpoint and stable
// subject claim must be explicitly configured by the administrator.
type Config struct {
	Type             string            `json:"type"`
	Issuer           string            `json:"issuer"`
	ClientID         string            `json:"client_id"`
	ClientSecret     string            `json:"client_secret"`
	PublicURL        string            `json:"public_url"`
	Scopes           []string          `json:"scopes"`
	AuthorizationURL string            `json:"authorization_url"`
	TokenURL         string            `json:"token_url"`
	UserInfoURL      string            `json:"userinfo_url"`
	SubjectClaim     string            `json:"subject_claim"`
	BrowserMode      string            `json:"browser_mode"`
	SubjectUsers     map[string]string `json:"subject_users"`
}

const (
	callbackPath      = "/+CSCOE+/sso/callback"
	providerTimeout   = 10 * time.Second
	maxUserInfoBytes  = 1 << 20
	maxIdentityLength = 1024
)

var (
	ErrProviderUnavailable = errors.New("SSO provider unavailable")
	ErrAuthentication      = errors.New("SSO authentication failed")
)

// Validate performs no network I/O and never includes secret values in errors.
func (c Config) Validate() error {
	if c.Type != "oidc" && c.Type != "oauth2" {
		return errors.New("SSO type must be oidc or oauth2")
	}
	if strings.TrimSpace(c.ClientID) == "" || len(c.ClientID) > 1024 {
		return errors.New("SSO client_id is required and must be at most 1024 bytes")
	}
	public, err := httpsURL(c.PublicURL)
	if err != nil || public.Path != "" || public.RawQuery != "" || public.ForceQuery {
		return errors.New("SSO public_url must be an HTTPS origin without a path or query")
	}
	switch c.BrowserMode {
	case "", "auto", "internal", "external":
	default:
		return errors.New("SSO browser_mode must be auto, internal or external")
	}
	for _, scope := range c.Scopes {
		if scope == "" || strings.ContainsFunc(scope, unicode.IsSpace) || strings.ContainsFunc(scope, unicode.IsControl) {
			return errors.New("SSO scopes must contain individual nonempty scope names")
		}
	}
	if len(c.SubjectUsers) > 10000 {
		return errors.New("SSO subject_users must contain at most 10000 mappings")
	}
	for subject, username := range c.SubjectUsers {
		if !validSubject(subject) || !validSubject(username) || len(username) > 128 {
			return errors.New("SSO subject_users contains an invalid subject or local username")
		}
	}
	if c.Type == "oidc" {
		issuer, err := httpsURL(c.Issuer)
		if err != nil || issuer.RawQuery != "" || issuer.ForceQuery {
			return errors.New("OIDC issuer must be an HTTPS URL without a query")
		}
		if c.SubjectClaim != "" && c.SubjectClaim != "sub" {
			return errors.New("OIDC identity mapping must use the verified sub claim")
		}
	} else {
		for _, endpoint := range []string{c.AuthorizationURL, c.TokenURL, c.UserInfoURL} {
			if _, err := httpsURL(endpoint); err != nil {
				return errors.New("OAuth2 authorization_url, token_url and userinfo_url must be HTTPS URLs")
			}
		}
		if !validSubject(c.SubjectClaim) || strings.ContainsAny(c.SubjectClaim, ".[]") {
			return errors.New("OAuth2 subject_claim must name one top-level userinfo claim")
		}
	}
	return nil
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") || u.Opaque != "" {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

type Provider struct {
	config   Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// NewProvider discovers OIDC metadata once for a login transaction. The custom
// client context is also used for JWKS verification (e.g. an enterprise CA), but
// certificate verification is never disabled by this package. Redirects are
// refused so token credentials and bearer tokens cannot cross endpoint origins.
func NewProvider(ctx context.Context, c Config) (*Provider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	client := &http.Client{}
	if supplied, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && supplied != nil {
		*client = *supplied
	}
	client.Timeout = providerTimeout
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	p := &Provider{config: c, client: client}
	p.oauth = oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		RedirectURL: strings.TrimRight(c.PublicURL, "/") + callbackPath,
		Scopes:      append([]string(nil), c.Scopes...),
	}
	if c.Type == "oauth2" {
		p.oauth.Endpoint = oauth2.Endpoint{AuthURL: c.AuthorizationURL, TokenURL: c.TokenURL}
		return p, nil
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), providerTimeout)
	defer cancel()
	discovered, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	// Validate all discovered endpoints before either the browser or backend uses
	// them. The issuer check itself is performed by go-oidc during discovery.
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := discovered.Claims(&metadata); err != nil {
		return nil, ErrProviderUnavailable
	}
	p.oauth.Endpoint = discovered.Endpoint()
	for _, endpoint := range []string{p.oauth.Endpoint.AuthURL, p.oauth.Endpoint.TokenURL, metadata.JWKSURL} {
		if _, err := httpsURL(endpoint); err != nil {
			return nil, ErrProviderUnavailable
		}
	}
	if !contains(p.oauth.Scopes, oidc.ScopeOpenID) {
		p.oauth.Scopes = append([]string{oidc.ScopeOpenID}, p.oauth.Scopes...)
	}
	// Key retrieval must outlive discovery's bounded context, but each actual
	// request is still bounded by the HTTP client's timeout.
	p.verifier = discovered.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: c.ClientID})
	return p, nil
}

// AuthorizationURL always uses code flow and S256 PKCE. All three random values
// belong to the server-side transaction; callers must not accept them from a
// provider callback or reuse them for another VPN session.
func (p *Provider) AuthorizationURL(state, nonce, verifier string) string {
	if state == "" || nonce == "" || !validVerifier(verifier) {
		return ""
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if p.config.Type == "oidc" {
		opts = append(opts, oidc.Nonce(nonce))
	}
	return p.oauth.AuthCodeURL(state, opts...)
}

// Authenticate returns only the provider's stable subject. Access and refresh
// tokens never become VPN credentials and are not retained after this call.
func (p *Provider) Authenticate(ctx context.Context, code, nonce, verifier string) (string, error) {
	if code == "" || nonce == "" || !validVerifier(verifier) {
		return "", ErrAuthentication
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, p.client), providerTimeout)
	defer cancel()
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil || !token.Valid() || !strings.EqualFold(token.Type(), "Bearer") {
		return "", ErrAuthentication
	}
	if p.config.Type == "oidc" {
		raw, ok := token.Extra("id_token").(string)
		if !ok || raw == "" {
			return "", ErrAuthentication
		}
		idToken, err := p.verifier.Verify(ctx, raw)
		if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 || !validSubject(idToken.Subject) {
			return "", ErrAuthentication
		}
		var claims struct {
			AuthorizedParty string `json:"azp"`
		}
		if idToken.Claims(&claims) != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != p.config.ClientID) || (len(idToken.Audience) > 1 && claims.AuthorizedParty == "") {
			return "", ErrAuthentication
		}
		if idToken.AccessTokenHash != "" && idToken.VerifyAccessToken(token.AccessToken) != nil {
			return "", ErrAuthentication
		}
		return idToken.Subject, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.UserInfoURL, nil)
	if err != nil {
		return "", ErrAuthentication
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", ErrAuthentication
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ErrAuthentication
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUserInfoBytes+1))
	if err != nil || len(body) > maxUserInfoBytes {
		return "", ErrAuthentication
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var claims map[string]any
	if decoder.Decode(&claims) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", ErrAuthentication
	}
	var subject string
	switch claim := claims[p.config.SubjectClaim].(type) {
	case string:
		subject = claim
	case json.Number:
		// Preserve integer IDs larger than 2^53 without float64 conversion. Only
		// canonical unsigned integer JSON identities are accepted.
		subject = claim.String()
		for _, r := range subject {
			if r < '0' || r > '9' {
				return "", ErrAuthentication
			}
		}
	default:
		return "", ErrAuthentication
	}
	if !validSubject(subject) {
		return "", ErrAuthentication
	}
	return subject, nil
}

func validSubject(value string) bool {
	return value != "" && len(value) <= maxIdentityLength && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// String deliberately omits credentials and endpoint query strings.
func (p *Provider) String() string { return fmt.Sprintf("SSO provider (%s)", p.config.Type) }
