package dbdata

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/pkg/sso"
)

// xdb and base.Cfg are package globals. These tests intentionally run serially,
// use a database unique to each test, and restore the previous state on cleanup.
func setupSSODB(t *testing.T) {
	t.Helper()
	previousConfig := *base.Cfg
	previousDB := xdb
	base.Cfg.DbType = "sqlite3"
	base.Cfg.DbSource = filepath.Join(t.TempDir(), "sso.db")
	base.Test()
	initDb()
	testDB := GetXdb()
	t.Cleanup(func() {
		if err := testDB.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
		xdb = previousDB
		*base.Cfg = previousConfig
	})
}

func browserAuthData(typ string) map[string]interface{} {
	config := map[string]interface{}{
		"client_id":     "anylink-test",
		"client_secret": "test-only-secret",
		"public_url":    "https://vpn.example.test",
		"browser_mode":  "auto",
		"subject_users": map[string]string{"immutable-subject": "alice"},
	}
	if typ == "oidc" {
		config["issuer"] = "https://idp.example.test/realms/company"
		config["scopes"] = []string{"openid", "profile"}
	} else {
		config["authorization_url"] = "https://idp.example.test/authorize"
		config["token_url"] = "https://idp.example.test/token"
		config["userinfo_url"] = "https://idp.example.test/user"
		config["subject_claim"] = "id"
		config["scopes"] = []string{"read:user"}
	}
	return map[string]interface{}{"type": typ, typ: config}
}

type ssoDBFixture struct {
	group    Group
	user     User
	expected sso.Config
}

func seedSSODB(t *testing.T, typ string) *ssoDBFixture {
	t.Helper()
	setupSSODB(t)
	f := &ssoDBFixture{
		group: Group{
			Name: "sso-users", Status: 1, Auth: browserAuthData(typ),
			ClientDns:    []ValData{{Val: "10.0.0.53"}},
			RouteInclude: []ValData{{Val: "10.0.0.0/8"}},
		},
		user: User{
			Username: "alice", Status: 1, PinCode: "test-only-password",
			Type: "local", DisableOtp: true, Groups: []string{"sso-users"},
		},
	}
	if err := SetGroup(&f.group); err != nil {
		t.Fatalf("create SSO group: %v", err)
	}
	if err := SetUser(&f.user); err != nil {
		t.Fatalf("create mapped local user: %v", err)
	}
	var err error
	f.expected, err = GetSSOConfig(f.group.Name)
	if err != nil {
		t.Fatalf("load SSO configuration: %v", err)
	}
	return f
}

func TestSSOConfigNestedTypes(t *testing.T) {
	for _, typ := range []string{"oidc", "oauth2"} {
		t.Run(typ, func(t *testing.T) {
			auth := browserAuthData(typ)
			// An inner type cannot override the selected group authentication type.
			auth[typ].(map[string]interface{})["type"] = "local"
			before, err := json.Marshal(auth)
			if err != nil {
				t.Fatal(err)
			}
			config, err := SSOConfig(auth)
			if err != nil {
				t.Fatalf("parse nested config: %v", err)
			}
			if config.Type != typ || config.ClientID != "anylink-test" ||
				config.SubjectUsers["immutable-subject"] != "alice" {
				t.Fatalf("incorrect parsed configuration: type=%q client=%q mappings=%v",
					config.Type, config.ClientID, config.SubjectUsers)
			}
			if err := (BrowserAuth{}).checkData(auth); err != nil {
				t.Fatalf("registered browser configuration validation: %v", err)
			}
			after, err := json.Marshal(auth)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("configuration parsing mutated the caller's auth object")
			}
		})
	}
}

func TestSSOConfigRejectsMalformedNestedData(t *testing.T) {
	oversized := browserAuthData("oidc")
	oversized["oidc"].(map[string]interface{})["client_secret"] = strings.Repeat("x", 65537)
	cases := []struct {
		name string
		auth map[string]interface{}
	}{
		{"nil", nil},
		{"local", map[string]interface{}{"type": "local"}},
		{"unknown type", map[string]interface{}{"type": "saml"}},
		{"wrong type value", map[string]interface{}{"type": 123}},
		{"missing nested", map[string]interface{}{"type": "oidc"}},
		{"flat config", map[string]interface{}{"type": "oidc", "issuer": "https://idp.example.test", "client_id": "vpn", "public_url": "https://vpn.example.test"}},
		{"wrong nested type", map[string]interface{}{"type": "oidc", "oidc": "not an object"}},
		{"unmarshalable nested", map[string]interface{}{"type": "oidc", "oidc": make(chan int)}},
		{"oversized nested", oversized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SSOConfig(tc.auth); err == nil {
				t.Fatal("malformed SSO configuration was accepted")
			}
			if err := (BrowserAuth{}).checkData(tc.auth); err == nil {
				t.Fatal("registered configuration check accepted malformed input")
			}
		})
	}
}

func TestBrowserAuthNeverAcceptsPassword(t *testing.T) {
	for _, typ := range []string{"oidc", "oauth2"} {
		t.Run(typ, func(t *testing.T) {
			f := seedSSODB(t, typ)
			local := Group{
				Name: "password-users", Status: 1,
				ClientDns:    []ValData{{Val: "10.0.0.53"}},
				RouteInclude: []ValData{{Val: "10.0.0.0/8"}},
				Auth:         map[string]interface{}{"type": "local"},
			}
			if err := SetGroup(&local); err != nil {
				t.Fatal(err)
			}
			f.user.Groups = append(f.user.Groups, local.Name)
			if err := Set(&f.user); err != nil {
				t.Fatal(err)
			}
			// Establish that these exact credentials work on a local-auth group.
			if err := CheckUser(f.user.Username, "test-only-password", local.Name, nil); err != nil {
				t.Fatalf("local-auth control failed: %v", err)
			}
			for _, password := range []string{"test-only-password", "", "anything", "fake-id-token"} {
				if err := CheckUser(f.user.Username, password, f.group.Name, nil); err == nil {
					t.Fatalf("%s password path accepted credentials without browser SSO", typ)
				}
			}
		})
	}
}

func TestAuthorizeSSOExistingEnabledMember(t *testing.T) {
	for _, typ := range []string{"oidc", "oauth2"} {
		t.Run(typ, func(t *testing.T) {
			f := seedSSODB(t, typ)
			username, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected)
			if err != nil || username != "alice" {
				t.Fatalf("mapped enabled member denied: username=%q err=%v", username, err)
			}
			future := time.Now().Add(time.Hour)
			f.user.LimitTime = &future
			if err := Set(&f.user); err != nil {
				t.Fatal(err)
			}
			if _, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected); err != nil {
				t.Fatalf("account with future expiration denied: %v", err)
			}
			for _, subject := range []string{"", "alice", "unmapped", "IMMUTABLE-SUBJECT"} {
				if name, err := AuthorizeSSO(f.group.Name, subject, f.expected); err == nil || name != "" {
					t.Fatalf("unmapped identity %q was authorized as %q", subject, name)
				}
			}
		})
	}
}

func TestAuthorizeSSORechecksAccountAndGroup(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ssoDBFixture) error
	}{
		{"disabled user", func(f *ssoDBFixture) error { f.user.Status = 0; return Set(&f.user) }},
		{"expired status", func(f *ssoDBFixture) error { f.user.Status = 2; return Set(&f.user) }},
		{"expired timestamp", func(f *ssoDBFixture) error {
			past := time.Now().Add(-time.Minute)
			f.user.LimitTime = &past
			return Set(&f.user)
		}},
		{"removed membership", func(f *ssoDBFixture) error { f.user.Groups = []string{"other"}; return Set(&f.user) }},
		{"deleted user", func(f *ssoDBFixture) error { return Del(&f.user) }},
		{"disabled group", func(f *ssoDBFixture) error { f.group.Status = 0; return Set(&f.group) }},
		{"deleted group", func(f *ssoDBFixture) error { return Del(&f.group) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := seedSSODB(t, "oidc")
			if _, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected); err != nil {
				t.Fatalf("initial authorization failed: %v", err)
			}
			if err := tc.mutate(f); err != nil {
				t.Fatalf("change authorization state: %v", err)
			}
			if name, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected); err == nil || name != "" {
				t.Fatalf("stale authorization survived %s: %q", tc.name, name)
			}
		})
	}
}

func TestAuthorizeSSORejectsChangedConfiguration(t *testing.T) {
	changes := []struct {
		field string
		value interface{}
	}{
		{"issuer", "https://other-idp.example.test"},
		{"client_id", "different-client"},
		{"client_secret", "different-test-only-secret"},
		{"public_url", "https://other-vpn.example.test"},
		{"browser_mode", "internal"},
		{"scopes", []string{"openid", "profile", "email"}},
		{"subject_users", map[string]string{"immutable-subject": "another-account"}},
	}
	for _, change := range changes {
		t.Run(change.field, func(t *testing.T) {
			f := seedSSODB(t, "oidc")
			f.group.Auth["oidc"].(map[string]interface{})[change.field] = change.value
			if err := SetGroup(&f.group); err != nil {
				t.Fatalf("save updated configuration: %v", err)
			}
			if name, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected); err == nil || name != "" {
				t.Fatalf("old transaction accepted after changing %s", change.field)
			}
		})
	}
	t.Run("changed authentication type", func(t *testing.T) {
		f := seedSSODB(t, "oidc")
		f.group.Auth = map[string]interface{}{"type": "local"}
		if err := SetGroup(&f.group); err != nil {
			t.Fatal(err)
		}
		if _, err := GetSSOConfig(f.group.Name); err == nil {
			t.Fatal("local-auth group exposed SSO configuration")
		}
		if name, err := AuthorizeSSO(f.group.Name, "immutable-subject", f.expected); err == nil || name != "" {
			t.Fatal("old SSO transaction survived an authentication type change")
		}
	})
}

func TestSSOEmptyMappingDoesNotProvisionUsers(t *testing.T) {
	f := seedSSODB(t, "oidc")
	f.group.Auth["oidc"].(map[string]interface{})["subject_users"] = map[string]string{}
	if err := SetGroup(&f.group); err != nil {
		t.Fatalf("empty allowlist should be valid configuration: %v", err)
	}
	config, err := GetSSOConfig(f.group.Name)
	if err != nil {
		t.Fatal(err)
	}
	before, err := GetXdb().Count(&User{})
	if err != nil {
		t.Fatal(err)
	}
	if name, err := AuthorizeSSO(f.group.Name, "new-subject", config); err == nil || name != "" {
		t.Fatal("empty mapping permitted an identity")
	}
	after, err := GetXdb().Count(&User{})
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("authorization created a user")
	}
}

func TestSSOGroupLargeConfigurationRoundTrip(t *testing.T) {
	f := seedSSODB(t, "oidc")
	mappings := map[string]string{}
	for i := 0; i < 100; i++ {
		mappings[fmt.Sprintf("immutable-subject-%04d-abcdefghijklmnop", i)] = "alice"
	}
	f.group.Auth["oidc"].(map[string]interface{})["subject_users"] = mappings
	encoded, err := json.Marshal(f.group.Auth)
	if err != nil || len(encoded) <= 500 {
		t.Fatalf("test configuration must exceed old 500-byte column: len=%d err=%v", len(encoded), err)
	}
	if err := SetGroup(&f.group); err != nil {
		t.Fatalf("save large SSO configuration: %v", err)
	}
	expected, err := SSOConfig(f.group.Auth)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := GetSSOConfig(f.group.Name)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		t.Fatalf("large configuration did not survive database round-trip: err=%v", err)
	}
	if username, err := AuthorizeSSO(f.group.Name, "immutable-subject-0099-abcdefghijklmnop", actual); err != nil || username != "alice" {
		t.Fatalf("mapping at end of large configuration lost: username=%q err=%v", username, err)
	}
	// SQLite does not enforce VARCHAR lengths, so also inspect the created
	// schema rather than relying solely on a large successful insert.
	columns, err := GetXdb().QueryString("PRAGMA table_info('group')")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range columns {
		if column["name"] == "auth" {
			if !strings.EqualFold(column["type"], "TEXT") {
				t.Fatalf("auth column must use TEXT, got %q", column["type"])
			}
			return
		}
	}
	t.Fatal("auth column not found in group schema")
}
