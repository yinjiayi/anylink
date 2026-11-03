package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func negotiationRequest(kind string, methods []string, key string, cookie *http.Cookie) (*http.Request, *ClientRequest) {
	r := httptest.NewRequest(http.MethodPost, "https://vpn.example/", nil)
	r.RemoteAddr = "192.0.2.1:12345"
	if key != "" {
		r.Header.Set(ssoSTRAPHeader, key)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	cr := &ClientRequest{Type: kind}
	cr.Capabilities.AuthMethods = methods
	return r, cr
}

func initialNegotiation(t *testing.T, s *ssoNegotiations, key string) *http.Cookie {
	t.Helper()
	r, cr := negotiationRequest("init", []string{"single-sign-on-v2", "single-sign-on-external-browser", "multiple-cert"}, key, nil)
	w := httptest.NewRecorder()
	if err := s.remember(w, r, cr); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != ssoNegotiationCookie || len(cookies[0].Value) != 64 ||
		!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" || cookies[0].MaxAge != 300 {
		t.Fatalf("invalid negotiation cookie: %v", cookies)
	}
	return cookies[0]
}

func TestSSONegotiationCiscoGroupReply(t *testing.T) {
	s := newSSONegotiations()
	cookie := initialNegotiation(t, s, "initial-key")
	r, cr := negotiationRequest("auth-reply", nil, "", cookie)
	// Address and user agent are not lookup credentials. A valid cookie is.
	r.RemoteAddr = "198.51.100.2:54321"
	r.Header.Set("User-Agent", "different-agent")
	if err := s.remember(httptest.NewRecorder(), r, cr); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cr.Capabilities.AuthMethods, []string{"single-sign-on-v2", "single-sign-on-external-browser"}) || r.Header.Get(ssoSTRAPHeader) != "initial-key" {
		t.Fatal("omitted Cisco auth-reply metadata was not restored")
	}
	for _, supplied := range []*http.Cookie{nil, {Name: ssoNegotiationCookie, Value: strings.Repeat("0", 64)}} {
		r, cr = negotiationRequest("auth-reply", nil, "", supplied)
		if err := s.remember(httptest.NewRecorder(), r, cr); err != nil || len(cr.Capabilities.AuthMethods) != 0 || r.Header.Get(ssoSTRAPHeader) != "" {
			t.Fatal("restored metadata without the correct cookie")
		}
	}
}

func TestSSONegotiationExplicitValuesAndConflict(t *testing.T) {
	s := newSSONegotiations()
	cookie := initialNegotiation(t, s, "initial-key")
	r, cr := negotiationRequest("auth-reply", []string{"single-sign-on-v2"}, "initial-key", cookie)
	if err := s.remember(httptest.NewRecorder(), r, cr); err != nil || !reflect.DeepEqual(cr.Capabilities.AuthMethods, []string{"single-sign-on-v2"}) {
		t.Fatal("explicit capabilities were overwritten")
	}
	r, cr = negotiationRequest("auth-reply", nil, "different-key", cookie)
	w := httptest.NewRecorder()
	if err := s.remember(w, r, cr); err == nil || len(s.entries) != 0 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("key substitution did not reject and clear the negotiation")
	}
	if r.Header.Get(ssoSTRAPHeader) != "different-key" || len(cr.Capabilities.AuthMethods) != 0 {
		t.Fatal("conflicting request was partly restored")
	}
	// An init is a new connection. Its explicit key may replace the old key,
	// while its cookie rotates and the old lookup becomes unusable.
	cookie = initialNegotiation(t, s, "old-key")
	r, cr = negotiationRequest("init", []string{"single-sign-on-v2"}, "new-key", cookie)
	w = httptest.NewRecorder()
	if err := s.remember(w, r, cr); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 || cookies[1].Value == cookie.Value || len(s.entries) != 1 {
		t.Fatal("new init failed to rotate its cookie")
	}
	r, cr = negotiationRequest("auth-reply", nil, "", cookie)
	_ = s.remember(httptest.NewRecorder(), r, cr)
	if len(cr.Capabilities.AuthMethods) != 0 {
		t.Fatal("old init cookie remains usable")
	}
}

func TestSSONegotiationExpiryAndLimits(t *testing.T) {
	s := newSSONegotiations()
	now := time.Now()
	s.now = func() time.Time { return now }
	cookie := initialNegotiation(t, s, "initial-key")
	now = now.Add(ssoNegotiationTTL - time.Second)
	r, cr := negotiationRequest("auth-reply", nil, "", cookie)
	_ = s.remember(httptest.NewRecorder(), r, cr)
	now = now.Add(time.Second)
	r, cr = negotiationRequest("auth-reply", nil, "", cookie)
	_ = s.remember(httptest.NewRecorder(), r, cr)
	if len(s.entries) != 0 || len(cr.Capabilities.AuthMethods) != 0 {
		t.Fatal("expired negotiation restored or deadline extended")
	}
	for i := 0; i < ssoNegotiationPerIP+1; i++ {
		r, cr = negotiationRequest("init", []string{"single-sign-on-v2"}, "key", nil)
		w := httptest.NewRecorder()
		if err := s.remember(w, r, cr); err != nil || len(cr.Capabilities.AuthMethods) != 1 || r.Header.Get(ssoSTRAPHeader) != "key" {
			t.Fatal("resource limit disrupted the explicit request")
		}
		if i == ssoNegotiationPerIP && len(w.Result().Cookies()) != 0 {
			t.Fatal("per-address cache bound not enforced")
		}
	}
	if len(s.entries) != ssoNegotiationPerIP {
		t.Fatal("incorrect per-address cache size")
	}
	s = newSSONegotiations()
	for i := 0; i <= ssoNegotiationMax; i++ {
		r, cr = negotiationRequest("init", []string{"single-sign-on-v2"}, "key", nil)
		r.RemoteAddr = fmt.Sprintf("198.51.%d.%d:12345", i/256, i%256)
		w := httptest.NewRecorder()
		if err := s.remember(w, r, cr); err != nil {
			t.Fatal(err)
		}
		if i == ssoNegotiationMax && len(w.Result().Cookies()) != 0 {
			t.Fatal("global cache bound not enforced")
		}
	}
	if len(s.entries) != ssoNegotiationMax {
		t.Fatal("incorrect global cache size")
	}
}

func TestSSONegotiationIgnoresLocalAndBoundsMetadata(t *testing.T) {
	for _, test := range []struct {
		kind, key string
		methods   []string
	}{
		{"init", "key", []string{"multiple-cert"}},
		{"unknown", "key", []string{"single-sign-on-v2"}},
		{"init", strings.Repeat("x", 257), []string{"single-sign-on-v2"}},
	} {
		s := newSSONegotiations()
		r, cr := negotiationRequest(test.kind, test.methods, test.key, nil)
		w := httptest.NewRecorder()
		if err := s.remember(w, r, cr); err != nil || len(s.entries) != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatal("irrelevant or oversized metadata retained")
		}
	}
}

func TestSSONegotiationConcurrentReplies(t *testing.T) {
	s := newSSONegotiations()
	cookie := initialNegotiation(t, s, "initial-key")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, cr := negotiationRequest("auth-reply", nil, "", cookie)
			if err := s.remember(httptest.NewRecorder(), r, cr); err != nil || r.Header.Get(ssoSTRAPHeader) != "initial-key" {
				t.Error("concurrent restoration failed")
			}
			// The returned slice must not alias the shared cache.
			cr.Capabilities.AuthMethods[0] = "caller-owned"
		}()
	}
	wg.Wait()
}
