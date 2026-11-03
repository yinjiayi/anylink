package handler

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	ssoNegotiationCookie = "anylink-sso-negotiation"
	ssoSTRAPHeader       = "X-AnyConnect-STRAP-DH-Pubkey"
	ssoNegotiationTTL    = 5 * time.Minute
	ssoNegotiationMax    = 256
	ssoNegotiationPerIP  = 16
)

type ssoNegotiation struct {
	methods []string
	key     string
	ip      string // Used only for resource limits, never as a session binding.
	expires time.Time
}

type ssoNegotiations struct {
	mu      sync.Mutex
	entries map[string]ssoNegotiation
	now     func() time.Time
}

func newSSONegotiations() *ssoNegotiations {
	return &ssoNegotiations{entries: make(map[string]ssoNegotiation), now: time.Now}
}

var browserSSONegotiations = newSSONegotiations()

func ssoNegotiationSetCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: ssoNegotiationCookie, Value: value,
		Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func ssoNegotiationMethods(methods []string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, method := range methods {
		if (method == "single-sign-on-v2" || method == "single-sign-on-external-browser") && !seen[method] {
			result = append(result, method)
			seen[method] = true
		}
	}
	return result
}

// remember preserves negotiation metadata when a native client omits it from a
// group-selection auth-reply. The random cookie is the sole lookup credential;
// these entries are never authorization records or a source of VPN tickets.
// Every init starts afresh, so a new VPN connection may generate a new DH key.
func (s *ssoNegotiations) remember(w http.ResponseWriter, r *http.Request, cr *ClientRequest) error {
	if cr == nil || (cr.Type != "init" && cr.Type != "auth-reply") {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, id)
		}
	}
	var id string
	if cookie, err := r.Cookie(ssoNegotiationCookie); err == nil {
		id = cookie.Value
	}
	entry, found := s.entries[id]
	if cr.Type == "init" {
		// Rotation does not affect SSO transactions: they hold their own key copy.
		delete(s.entries, id)
		if id != "" {
			ssoNegotiationSetCookie(w, "", -1)
		}
		found = false
	}
	key := r.Header.Get(ssoSTRAPHeader)
	if found {
		if key != "" && entry.key != "" && key != entry.key {
			delete(s.entries, id)
			ssoNegotiationSetCookie(w, "", -1)
			return errors.New("SSO negotiation key changed; restart VPN login")
		}
		if len(cr.Capabilities.AuthMethods) == 0 {
			cr.Capabilities.AuthMethods = append([]string(nil), entry.methods...)
		} else {
			entry.methods = ssoNegotiationMethods(cr.Capabilities.AuthMethods)
		}
		if key == "" {
			if entry.key != "" {
				r.Header.Set(ssoSTRAPHeader, entry.key)
			}
		} else if len(key) <= 256 {
			entry.key = key
		}
		// Do not extend the absolute deadline on every request.
		s.entries[id] = entry
		return nil
	}
	methods := ssoNegotiationMethods(cr.Capabilities.AuthMethods)
	if len(methods) == 0 || len(key) > 256 || len(s.entries) >= ssoNegotiationMax {
		return nil
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil {
		return nil
	}
	ip := net.ParseIP(peer).String()
	count := 0
	for _, existing := range s.entries {
		if existing.ip == ip {
			count++
		}
	}
	if count >= ssoNegotiationPerIP {
		return nil
	}
	id, err = ssoRandom()
	if err != nil {
		return err
	}
	s.entries[id] = ssoNegotiation{methods: methods, key: key, ip: ip, expires: now.Add(ssoNegotiationTTL)}
	ssoNegotiationSetCookie(w, id, int(ssoNegotiationTTL.Seconds()))
	return nil
}
