package handler

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/pkg/sso"
)

type fakeSSOProvider struct {
	state, nonce, verifier string
	calls                  int
	deny                   bool
}

func (p *fakeSSOProvider) AuthorizationURL(state, nonce, verifier string) string {
	p.state, p.nonce, p.verifier = state, nonce, verifier
	return "https://idp.example/authorize?state=" + state
}
func (p *fakeSSOProvider) Authenticate(_ context.Context, code, nonce, verifier string) (string, error) {
	p.calls++
	if p.deny || code != "valid-code" || nonce != p.nonce || verifier != p.verifier {
		return "", errors.New("rejected")
	}
	return "immutable-subject", nil
}

func testSSOConfig() sso.Config {
	return sso.Config{Type: "oidc", Issuer: "https://idp.example", ClientID: "vpn", PublicURL: "https://vpn.example",
		BrowserMode: "internal", SubjectUsers: map[string]string{"immutable-subject": "alice"}}
}

func testSSOClient() ClientRequest {
	cr := ClientRequest{Type: "init", GroupSelect: "R&D", UserAgent: "anyconnect", RemoteAddr: "192.0.2.1:12345"}
	cr.Capabilities.AuthMethods = []string{"single-sign-on-v2", "single-sign-on-external-browser"}
	cr.DeviceId.UniqueIdGlobal = "original-device"
	return cr
}

type ssoChallengeResponse struct {
	Opaque struct {
		Challenge string `xml:"sso-session-id"`
		Group     string `xml:"tunnel-group"`
	} `xml:"opaque"`
	Auth struct {
		Login string `xml:"sso-v2-login"`
		Final string `xml:"sso-v2-login-final"`
		Mode  string `xml:"sso-v2-browser-mode"`
	} `xml:"auth"`
}

func testSSOGateway(t *testing.T) (*ssoGateway, *fakeSSOProvider, *string) {
	t.Helper()
	base.Test()
	p := &fakeSSOProvider{}
	completed := new(string)
	g := &ssoGateway{store: newSSOStore(),
		newProvider: func(context.Context, sso.Config) (ssoProvider, error) { return p, nil },
		authorize: func(group, subject string, c sso.Config) (string, error) {
			if group != "R&D" || c.SubjectUsers[subject] == "" {
				return "", errors.New("denied")
			}
			return c.SubjectUsers[subject], nil
		},
		complete: func(w http.ResponseWriter, r *http.Request, a *AuthSession) {
			*completed = a.ClientRequest.Auth.Username
			if a.ClientRequest.DeviceId.UniqueIdGlobal != "original-device" {
				t.Error("lost original device binding")
			}
			w.WriteHeader(http.StatusOK)
		},
	}
	return g, p, completed
}

func beginTestSSO(t *testing.T, g *ssoGateway, c sso.Config, key string) ssoChallengeResponse {
	t.Helper()
	cr := testSSOClient()
	r := httptest.NewRequest(http.MethodPost, "https://host-header-attacker.example/", nil)
	r.Header.Set("X-AnyConnect-STRAP-DH-Pubkey", key)
	w := httptest.NewRecorder()
	g.begin(w, r, &cr, c)
	if w.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	var response ssoChallengeResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Opaque.Group != "R&D" || response.Opaque.Challenge == "" {
		t.Fatal("invalid escaped group/challenge")
	}
	if !strings.HasPrefix(response.Auth.Login, c.PublicURL+"/") || response.Auth.Final != c.PublicURL+ssoFinalPath {
		t.Fatal("untrusted host affected endpoints")
	}
	if strings.Contains(response.Auth.Login, response.Opaque.Challenge) {
		t.Fatal("VPN binding leaked into browser URL")
	}
	return response
}

func startTestSSO(t *testing.T, g *ssoGateway, response ssoChallengeResponse) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	g.start(w, httptest.NewRequest(http.MethodGet, response.Auth.Login, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe browser cookie")
	}
	return cookies[0]
}

func callbackTestSSO(g *ssoGateway, p *fakeSSOProvider, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://vpn.example"+ssoCallbackPath+"?state="+p.state+"&code=valid-code", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.callback(w, r)
	return w
}

func TestSSOBrowserFlowAndReplay(t *testing.T) {
	g, p, completed := testSSOGateway(t)
	response := beginTestSSO(t, g, testSSOConfig(), "")
	cookie := startTestSSO(t, g, response)
	if w := callbackTestSSO(g, p, nil); w.Code != http.StatusBadRequest {
		t.Fatal("accepted callback without browser cookie")
	}
	wrong := *cookie
	wrong.Value = "attacker"
	if w := callbackTestSSO(g, p, &wrong); w.Code != http.StatusBadRequest {
		t.Fatal("accepted wrong browser")
	}
	w := callbackTestSSO(g, p, cookie)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://vpn.example"+ssoFinalPath {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	if p.calls != 1 {
		t.Fatal("unexpected code exchange count")
	}
	var ticket string
	for _, c := range w.Result().Cookies() {
		if c.Name == "acSamlv2Token" {
			ticket = c.Value
		}
	}
	if len(ticket) != 64 || ticket == p.state || ticket == response.Opaque.Challenge {
		t.Fatal("invalid ticket separation")
	}
	if w := callbackTestSSO(g, p, cookie); w.Code != http.StatusBadRequest || p.calls != 1 {
		t.Fatal("callback replay")
	}
	cr := testSSOClient()
	cr.Type = "auth-reply"
	cr.Auth.SsoToken = ticket
	cr.Opaque.SSOChallenge = "attacker"
	ua := &dbdata.UserActLog{}
	r := httptest.NewRequest(http.MethodPost, "https://vpn.example/", nil)
	w = httptest.NewRecorder()
	g.redeem(w, r, &cr, ua)
	if w.Code != http.StatusUnauthorized || *completed != "" {
		t.Fatal("accepted cross-session ticket")
	}
	cr.Opaque.SSOChallenge = response.Opaque.Challenge
	cr.GroupSelect = "wrong"
	w = httptest.NewRecorder()
	g.redeem(w, r, &cr, ua)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("accepted cross-group ticket")
	}
	cr.GroupSelect = ""
	cr.DeviceId = deviceId{} // Some clients omit metadata in auth-reply.
	cr.Auth.Username = "attacker-controlled"
	w = httptest.NewRecorder()
	g.redeem(w, r, &cr, ua)
	if w.Code != http.StatusOK || *completed != "alice" || ua.GroupName != "R&D" {
		t.Fatalf("redeem failed %d %s", w.Code, *completed)
	}
	w = httptest.NewRecorder()
	g.redeem(w, r, &cr, ua)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("ticket replay accepted")
	}
}

func TestSSOExternalCallback(t *testing.T) {
	g, p, _ := testSSOGateway(t)
	c := testSSOConfig()
	c.BrowserMode = "auto"
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	response := beginTestSSO(t, g, c, base64.StdEncoding.EncodeToString(der))
	if response.Auth.Mode != "external" {
		t.Fatal("external capability not selected")
	}
	cookie := startTestSSO(t, g, response)
	w := callbackTestSSO(g, p, cookie)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusFound || u.Scheme != "http" || u.Host != "localhost:29786" || !strings.HasPrefix(u.Path, "/api/sso/") || u.Query().Get("return") != c.PublicURL+ssoDonePath {
		t.Fatal("invalid external return")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "acSamlv2Token" {
			t.Fatal("external ticket exposed in cookie")
		}
	}
	for _, tx := range g.store.entries {
		if strings.Contains(u.String(), tx.Ticket) {
			t.Fatal("external ticket was not encrypted")
		}
	}
}

func TestSSOCapabilitiesAndAuthorization(t *testing.T) {
	t.Run("auto without external key uses advertised internal mode", func(t *testing.T) {
		g, _, _ := testSSOGateway(t)
		c := testSSOConfig()
		c.BrowserMode = "auto"
		response := beginTestSSO(t, g, c, "")
		if response.Auth.Mode != "" {
			t.Fatal("auto chose external without an encryption key")
		}
	})
	for _, test := range []struct {
		name string
		caps []string
		mode string
		key  string
	}{
		{"unsupported", nil, "internal", ""},
		{"no external capability", []string{"single-sign-on-v2"}, "external", ""},
		{"missing encryption key", []string{"single-sign-on-external-browser"}, "external", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, _, _ := testSSOGateway(t)
			cr := testSSOClient()
			cr.Capabilities.AuthMethods = test.caps
			c := testSSOConfig()
			c.BrowserMode = test.mode
			w := httptest.NewRecorder()
			g.begin(w, httptest.NewRequest("POST", "https://vpn.example/", nil), &cr, c)
			if w.Code != http.StatusBadRequest || len(g.store.entries) != 0 {
				t.Fatal("unsupported client accepted")
			}
		})
	}
	for _, phase := range []string{"callback", "redeem"} {
		t.Run("deny "+phase, func(t *testing.T) {
			g, p, completed := testSSOGateway(t)
			response := beginTestSSO(t, g, testSSOConfig(), "")
			cookie := startTestSSO(t, g, response)
			deny := func(string, string, sso.Config) (string, error) { return "", errors.New("disabled") }
			if phase == "callback" {
				g.authorize = deny
			}
			w := callbackTestSSO(g, p, cookie)
			if phase == "callback" {
				if w.Code != http.StatusForbidden || len(g.store.entries) != 0 {
					t.Fatal("unauthorized callback accepted")
				}
				return
			}
			g.authorize = deny
			cr := testSSOClient()
			cr.Type = "auth-reply"
			cr.Opaque.SSOChallenge = response.Opaque.Challenge
			for _, c := range w.Result().Cookies() {
				if c.Name == "acSamlv2Token" {
					cr.Auth.SsoToken = c.Value
				}
			}
			w = httptest.NewRecorder()
			g.redeem(w, httptest.NewRequest("POST", "https://vpn.example/", nil), &cr, &dbdata.UserActLog{})
			if w.Code != http.StatusForbidden || *completed != "" {
				t.Fatal("authorization not rechecked")
			}
		})
	}
}

func TestSSOStoreExpiryBoundAndConcurrentConsumption(t *testing.T) {
	s := newSSOStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	tx, err := s.create(testSSOClient(), testSSOConfig(), "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = s.claimStart(tx.ID)
	if err != nil {
		t.Fatal(err)
	}
	tx.State, tx.BrowserSecret = "state", "browser"
	if err = s.started(tx); err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.callback("state", "browser"); err == nil {
				callbacks.Add(1)
			}
		}()
	}
	wg.Wait()
	if callbacks.Load() != 1 {
		t.Fatal("callback not single-use")
	}
	tx, err = s.issue(tx.ID, "immutable-subject", "alice")
	if err != nil {
		t.Fatal(err)
	}
	cr := testSSOClient()
	cr.Auth.SsoToken = tx.Ticket
	cr.Opaque.SSOChallenge = tx.Challenge
	var redemptions atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.redeem(cr); err == nil {
				redemptions.Add(1)
			}
		}()
	}
	wg.Wait()
	if redemptions.Load() != 1 {
		t.Fatal("ticket not single-use")
	}
	tx, _ = s.create(testSSOClient(), testSSOConfig(), "internal", nil)
	now = now.Add(ssoLifetime)
	if _, err := s.claimStart(tx.ID); err == nil {
		t.Fatal("expired transaction accepted")
	}
	for i := 0; i < ssoMaxPending; i++ {
		client := testSSOClient()
		client.RemoteAddr = fmt.Sprintf("198.51.100.%d:12345", i)
		if _, err := s.create(client, testSSOConfig(), "internal", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.create(testSSOClient(), testSSOConfig(), "internal", nil); err == nil {
		t.Fatal("unbounded store")
	}
	now = now.Add(ssoLifetime)
	if _, err := s.create(testSSOClient(), testSSOConfig(), "internal", nil); err != nil || len(s.entries) != 1 {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestSSOStorePerPeerBound(t *testing.T) {
	s := newSSOStore()
	for i := 0; i < ssoMaxPendingPerIP; i++ {
		client := testSSOClient()
		client.RemoteAddr = fmt.Sprintf("192.0.2.1:%d", 1000+i)
		if _, err := s.create(client, testSSOConfig(), "internal", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.create(testSSOClient(), testSSOConfig(), "internal", nil); err == nil {
		t.Fatal("per-peer bound not enforced")
	}
	client := testSSOClient()
	client.RemoteAddr = "192.0.2.2:1234"
	if _, err := s.create(client, testSSOConfig(), "internal", nil); err != nil {
		t.Fatal("unrelated peer denied")
	}
}

func TestSSOLinkAuthAndLegacyBypassGuards(t *testing.T) {
	oldCfg := *base.Cfg
	t.Cleanup(func() { *base.Cfg = oldCfg })
	preIpData(t)
	defer closeIpdata()
	base.Cfg.AuthOnlyCert = false
	base.Cfg.AuthCert = false
	config := testSSOConfig()
	group := &dbdata.Group{Name: "R&D", Status: 1, RouteInclude: []dbdata.ValData{{Val: "10.0.0.0/8"}},
		Auth: map[string]interface{}{"type": "oidc", "oidc": config}}
	if err := dbdata.SetGroup(group); err != nil {
		t.Fatal(err)
	}
	request := func(cr ClientRequest) *http.Request {
		b, err := xml.Marshal(cr)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://vpn.example/", strings.NewReader(string(b)))
		r.Header.Set("User-Agent", "Cisco AnyConnect")
		r.Header.Set("X-Aggregate-Auth", "1")
		r.Header.Set("X-Transcend-Version", "1")
		return r
	}
	client := testSSOClient()
	w := httptest.NewRecorder()
	LinkAuth(w, request(client))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sso-v2-login") || strings.Contains(w.Body.String(), "type=\"complete\"") {
		t.Fatal("SSO init was not routed to browser login")
	}
	client.Type = "auth-reply"
	client.Auth.Username = "alice"
	client.Auth.Password = "password"
	w = httptest.NewRecorder()
	LinkAuth(w, request(client))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sso-v2-login") {
		t.Fatal("SSO group password request did not require browser login")
	}
	// Certificate OU identifies the protected group even when group-select is omitted.
	base.Cfg.AuthCert = true
	client = testSSOClient()
	client.GroupSelect = ""
	r := request(client)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"R&D"}}}}}
	w = httptest.NewRecorder()
	LinkAuth(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("certificate bypassed SSO group")
	}
	r.TLS.PeerCertificates[0].Subject.OrganizationalUnit = nil
	w = httptest.NewRecorder()
	LinkAuth(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal("missing certificate OU was not rejected")
	}
	base.Cfg.AuthCert = false
	// A still-live legacy SSO/OTP transaction must not survive a group policy switch.
	session := &AuthSession{ClientRequest: &ClientRequest{GroupSelect: "R&D", Auth: auth{Username: "alice"}}, UserActLog: &dbdata.UserActLog{Username: "alice"}}
	SessStore.SaveAuthSession("legacy-sso-guard", session)
	t.Cleanup(func() { SessStore.DeleteAuthSession("legacy-sso-guard") })
	client = ClientRequest{Type: "auth-reply", Auth: auth{SsoToken: "legacy-sso-guard"}}
	w = httptest.NewRecorder()
	LinkAuth(w, request(client))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("legacy SSO bypassed new group policy")
	}
	SessStore.SaveAuthSession("legacy-otp-guard", session)
	r = request(ClientRequest{Type: "auth-reply", Auth: auth{SecondaryPassword: "123456"}})
	r.AddCookie(&http.Cookie{Name: "auth-session-id", Value: "legacy-otp-guard"})
	w = httptest.NewRecorder()
	LinkAuth_otp(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("legacy OTP bypassed new group policy")
	}
	if _, err := SessStore.GetAuthSession("legacy-otp-guard"); err == nil {
		t.Fatal("old OTP transaction retained")
	}
}
