package handler

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/bjdgyc/anylink/pkg/sso"
)

const ssoLifetime = 5 * time.Minute
const ssoTicketLifetime = time.Minute
const ssoMaxPending = 256
const ssoMaxPendingPerIP = 16

var errSSOTransaction = errors.New("invalid or expired SSO transaction")

type ssoTransaction struct {
	ID, Challenge, Phase, Mode            string
	Config                                sso.Config
	Client                                ClientRequest
	PublicKey                             *ecdh.PublicKey
	Expires                               time.Time
	State, BrowserSecret, Nonce, Verifier string
	Provider                              ssoProvider
	Subject, Username, Ticket             string
}

type ssoStore struct {
	mu      sync.Mutex
	entries map[string]ssoTransaction
	now     func() time.Time
}

func newSSOStore() *ssoStore {
	return &ssoStore{entries: make(map[string]ssoTransaction), now: time.Now}
}

func ssoRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func ssoEqual(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *ssoStore) prune() {
	for id, tx := range s.entries {
		if !s.now().Before(tx.Expires) {
			delete(s.entries, id)
		}
	}
}

func (s *ssoStore) create(cr ClientRequest, c sso.Config, mode string, key *ecdh.PublicKey) (ssoTransaction, error) {
	id, err := ssoRandom()
	if err != nil {
		return ssoTransaction{}, err
	}
	challenge, err := ssoRandom()
	if err != nil {
		return ssoTransaction{}, err
	}
	// Never retain a submitted password, OTP or another authentication token.
	cr.Auth = auth{}
	cr.SessionToken = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.entries) >= ssoMaxPending {
		return ssoTransaction{}, errors.New("too many pending SSO logins")
	}
	ip, _, err := net.SplitHostPort(cr.RemoteAddr)
	if err != nil || net.ParseIP(ip) == nil {
		return ssoTransaction{}, errors.New("invalid VPN peer address")
	}
	count := 0
	for _, pending := range s.entries {
		peer, _, _ := net.SplitHostPort(pending.Client.RemoteAddr)
		if peer == ip {
			count++
		}
	}
	if count >= ssoMaxPendingPerIP {
		return ssoTransaction{}, errors.New("too many pending SSO logins from this address")
	}
	tx := ssoTransaction{ID: id, Challenge: challenge, Phase: "pending", Config: c,
		Client: cr, Mode: mode, PublicKey: key, Expires: s.now().Add(ssoLifetime)}
	s.entries[id] = tx
	return tx, nil
}

func (s *ssoStore) claimStart(id string) (ssoTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	tx, ok := s.entries[id]
	if !ok || tx.Phase != "pending" {
		return ssoTransaction{}, errSSOTransaction
	}
	tx.Phase = "starting"
	s.entries[id] = tx
	return tx, nil
}

func (s *ssoStore) started(tx ssoTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	old, ok := s.entries[tx.ID]
	if !ok || old.Phase != "starting" {
		return errSSOTransaction
	}
	tx.Phase = "auth"
	s.entries[tx.ID] = tx
	return nil
}

// A callback is consumed atomically BEFORE any code exchange. Invalid browser
// cookies cannot consume somebody else's pending transaction.
func (s *ssoStore) callback(state, browserSecret string) (ssoTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	for id, tx := range s.entries {
		if tx.Phase == "auth" && ssoEqual(tx.State, state) && ssoEqual(tx.BrowserSecret, browserSecret) {
			tx.Phase = "exchanging"
			s.entries[id] = tx
			return tx, nil
		}
	}
	return ssoTransaction{}, errSSOTransaction
}

func (s *ssoStore) issue(id, subject, username string) (ssoTransaction, error) {
	ticket, err := ssoRandom()
	if err != nil {
		return ssoTransaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	tx, ok := s.entries[id]
	if !ok || tx.Phase != "exchanging" {
		return ssoTransaction{}, errSSOTransaction
	}
	tx.Phase, tx.Subject, tx.Username, tx.Ticket = "issued", subject, username, ticket
	if deadline := s.now().Add(ssoTicketLifetime); deadline.Before(tx.Expires) {
		tx.Expires = deadline
	}
	tx.State, tx.BrowserSecret, tx.Nonce, tx.Verifier, tx.Provider = "", "", "", "", nil
	s.entries[id] = tx
	return tx, nil
}

// The random opaque challenge travels ONLY through the VPN XML handshake. It
// does not appear in the browser URL, OAuth state, cookies or IdP requests.
func (s *ssoStore) redeem(cr ClientRequest) (ssoTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	for id, tx := range s.entries {
		if tx.Phase != "issued" || !ssoEqual(tx.Ticket, cr.Auth.SsoToken) {
			continue
		}
		if !ssoEqual(tx.Challenge, cr.Opaque.SSOChallenge) ||
			(cr.GroupSelect != "" && cr.GroupSelect != tx.Client.GroupSelect) ||
			(cr.Opaque.Group != "" && cr.Opaque.Group != tx.Client.GroupSelect) ||
			(cr.DeviceId.UniqueIdGlobal != "" && cr.DeviceId.UniqueIdGlobal != tx.Client.DeviceId.UniqueIdGlobal) {
			return ssoTransaction{}, errSSOTransaction
		}
		delete(s.entries, id)
		return tx, nil
	}
	return ssoTransaction{}, errSSOTransaction
}

func (s *ssoStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
}
