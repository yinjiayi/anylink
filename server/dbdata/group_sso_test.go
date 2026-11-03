package dbdata

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/bjdgyc/anylink/pkg/sso"
)

func seedGroupSSOEditor(t *testing.T, typ string) *Group {
	t.Helper()
	setupSSODB(t)
	group := &Group{
		Name: "editor-group", Note: "keep this note", Status: 0, AllowLan: true,
		ClientDns:    []ValData{{Val: "10.2.0.53", Note: "private resolver"}},
		SplitDns:     []ValData{{Val: "corp.example.test"}},
		RouteInclude: []ValData{{Val: "10.2.0.0/16"}}, RouteExclude: []ValData{{Val: "10.2.3.0/24"}},
		DsIncludeDomains: "corp.example.test", Bandwidth: 42,
		LinkAcl: []GroupLinkAcl{{Action: Deny, Protocol: TCP, Val: "10.2.3.0/24", Port: "80,443"}},
		Auth:    browserAuthData(typ),
	}
	if err := Add(group); err != nil {
		t.Fatal(err)
	}
	return group
}

func loadEditorUpdate(t *testing.T, id int) GroupSSOUpdate {
	t.Helper()
	info, err := GetGroupSSO(id)
	if err != nil || info.Config == nil {
		t.Fatalf("get editor configuration: %v", err)
	}
	if info.Config.ClientSecret != "" {
		t.Fatal("secret exposed in editor response")
	}
	return GroupSSOUpdate{ID: id, Config: *info.Config, Revision: info.Revision}
}

func storedEditorConfig(t *testing.T, id int) sso.Config {
	t.Helper()
	var group Group
	if err := One("id", id, &group); err != nil {
		t.Fatal(err)
	}
	config, err := SSOConfig(group.Auth)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestGroupSSOSecretLifecycleAndUnrelatedFields(t *testing.T) {
	for _, typ := range []string{"oidc", "oauth2"} {
		t.Run(typ, func(t *testing.T) {
			group := seedGroupSSOEditor(t, typ)
			var before Group
			if err := One("id", group.Id, &before); err != nil {
				t.Fatal(err)
			}
			info, err := GetGroupSSO(group.Id)
			if err != nil || info.Name != group.Name || info.Status != 0 || !info.SecretSet || info.AuthType != typ {
				t.Fatalf("unexpected editor info: %#v, %v", info, err)
			}
			body, _ := json.Marshal(info)
			if strings.Contains(string(body), "test-only-secret") {
				t.Fatal("GET response contains client secret")
			}
			update := loadEditorUpdate(t, group.Id)
			update.Config.BrowserMode = "external"
			updated, err := SetGroupSSO(update)
			if err != nil || !updated.SecretSet || updated.Config.ClientSecret != "" || updated.Revision == update.Revision {
				t.Fatalf("preserve secret: %#v, %v", updated, err)
			}
			if storedEditorConfig(t, group.Id).ClientSecret != "test-only-secret" {
				t.Fatal("omitted secret was not preserved")
			}
			var after Group
			if err := One("id", group.Id, &after); err != nil {
				t.Fatal(err)
			}
			after.Auth, after.UpdatedAt = before.Auth, before.UpdatedAt
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("non-authentication fields changed:\nbefore: %#v\nafter: %#v", before, after)
			}
			update = loadEditorUpdate(t, group.Id)
			update.SecretAction, update.Config.ClientSecret = "replace", "replacement-secret"
			updated, err = SetGroupSSO(update)
			if err != nil || !updated.SecretSet || updated.Config.ClientSecret != "" {
				t.Fatalf("replace secret: %#v, %v", updated, err)
			}
			if storedEditorConfig(t, group.Id).ClientSecret != "replacement-secret" {
				t.Fatal("secret was not replaced")
			}
			update = loadEditorUpdate(t, group.Id)
			update.SecretAction = "clear"
			updated, err = SetGroupSSO(update)
			if err != nil || updated.SecretSet || storedEditorConfig(t, group.Id).ClientSecret != "" {
				t.Fatalf("clear secret: %#v, %v", updated, err)
			}
		})
	}
}

func TestGroupSSOChangedProviderRequiresExplicitSecretAction(t *testing.T) {
	cases := []struct {
		name, typ string
		change    func(*sso.Config)
	}{
		{"oidc issuer", "oidc", func(c *sso.Config) { c.Issuer = "https://other.example.test" }},
		{"oidc client", "oidc", func(c *sso.Config) { c.ClientID = "another-client" }},
		{"oauth authorization", "oauth2", func(c *sso.Config) { c.AuthorizationURL = "https://other.example.test/auth" }},
		{"oauth token", "oauth2", func(c *sso.Config) { c.TokenURL = "https://other.example.test/token" }},
		{"oauth userinfo", "oauth2", func(c *sso.Config) { c.UserInfoURL = "https://other.example.test/user" }},
		{"oauth client", "oauth2", func(c *sso.Config) { c.ClientID = "another-client" }},
		{"protocol", "oidc", func(c *sso.Config) {
			*c, _ = SSOConfig(browserAuthData("oauth2"))
			c.ClientSecret = ""
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			group := seedGroupSSOEditor(t, test.typ)
			update := loadEditorUpdate(t, group.Id)
			test.change(&update.Config)
			if _, err := SetGroupSSO(update); !errors.Is(err, ErrSSOProviderChange) {
				t.Fatalf("changed provider retained previous secret: %v", err)
			}
			if storedEditorConfig(t, group.Id).ClientSecret != "test-only-secret" {
				t.Fatal("rejected write changed stored secret")
			}
			update.SecretAction = "clear"
			if info, err := SetGroupSSO(update); err != nil || info.SecretSet {
				t.Fatalf("explicit public client provider switch failed: %#v, %v", info, err)
			}
		})
	}
}

func TestGroupSSORejectsInvalidEditsAndStaleRevision(t *testing.T) {
	group := seedGroupSSOEditor(t, "oidc")
	original := loadEditorUpdate(t, group.Id)
	cases := []struct {
		name   string
		change func(*GroupSSOUpdate)
		want   error
	}{
		{"zero id", func(u *GroupSSOUpdate) { u.ID = 0 }, ErrSSOGroupID},
		{"missing group", func(u *GroupSSOUpdate) { u.ID += 1000 }, ErrSSOGroupNotFound},
		{"missing revision", func(u *GroupSSOUpdate) { u.Revision = "" }, ErrSSORevision},
		{"wrong revision", func(u *GroupSSOUpdate) { u.Revision = "obsolete" }, ErrSSOConfigConflict},
		{"unknown action", func(u *GroupSSOUpdate) { u.SecretAction = "oops" }, ErrSSOSecretAction},
		{"replace empty", func(u *GroupSSOUpdate) { u.SecretAction = "replace" }, ErrSSOSecretRequired},
		{"preserve nonempty", func(u *GroupSSOUpdate) { u.Config.ClientSecret = "unexpected" }, ErrSSOSecretNotEmpty},
		{"clear nonempty", func(u *GroupSSOUpdate) { u.SecretAction = "clear"; u.Config.ClientSecret = "unexpected" }, ErrSSOSecretNotEmpty},
		{"invalid URL", func(u *GroupSSOUpdate) { u.Config.PublicURL = "http://vpn.example.test" }, ErrSSOConfigInvalid},
		{"local type", func(u *GroupSSOUpdate) { u.SecretAction = "clear"; u.Config.Type = "local" }, ErrSSOConfigInvalid},
		{"oversized config", func(u *GroupSSOUpdate) {
			u.SecretAction = "replace"
			u.Config.ClientSecret = strings.Repeat("x", 65537)
		}, ErrSSOConfigInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			update := original
			test.change(&update)
			if _, err := SetGroupSSO(update); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			info, err := GetGroupSSO(group.Id)
			if err != nil || info.Revision != original.Revision {
				t.Fatal("rejected update changed existing configuration")
			}
		})
	}
	newer := original
	newer.Config.BrowserMode = "external"
	if _, err := SetGroupSSO(newer); err != nil {
		t.Fatal(err)
	}
	if _, err := SetGroupSSO(original); !errors.Is(err, ErrSSOConfigConflict) {
		t.Fatalf("stale page overwrote newer configuration: %v", err)
	}
}

func TestGroupSSOConcurrentEditsOnlyOneWins(t *testing.T) {
	group := seedGroupSSOEditor(t, "oidc")
	update := loadEditorUpdate(t, group.Id)
	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, mode := range []string{"internal", "external"} {
		wait.Add(1)
		go func(mode string) {
			defer wait.Done()
			candidate := update
			candidate.Config.BrowserMode = mode
			<-start
			_, err := SetGroupSSO(candidate)
			results <- err
		}(mode)
	}
	close(start)
	wait.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrSSOConfigConflict) {
			conflicts++
		} else {
			t.Errorf("unexpected concurrent edit failure: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d; expected one of each", successes, conflicts)
	}
}

func TestGroupSSOEnableExistingNonSSOGroup(t *testing.T) {
	for _, auth := range []map[string]interface{}{nil, {"type": "local"}, {"type": "ldap", "ldap": map[string]string{"password": "old-secret"}}} {
		t.Run("existing authentication", func(t *testing.T) {
			setupSSODB(t)
			group := Group{Name: "existing-group", Auth: auth, Status: 1}
			if err := Add(&group); err != nil {
				t.Fatal(err)
			}
			info, err := GetGroupSSO(group.Id)
			if err != nil || info.Config != nil || info.SecretSet {
				t.Fatalf("non-SSO group response: %#v, %v", info, err)
			}
			config, _ := SSOConfig(browserAuthData("oidc"))
			config.ClientSecret = ""
			if _, err := SetGroupSSO(GroupSSOUpdate{ID: group.Id, Config: config, Revision: info.Revision}); err != nil {
				t.Fatal(err)
			}
			if storedEditorConfig(t, group.Id).ClientSecret != "" {
				t.Fatal("non-SSO provider secret was reused")
			}
		})
	}
}

func loadLegacyAdminGroup(t *testing.T, id int) *Group {
	t.Helper()
	var group Group
	if err := One("id", id, &group); err != nil {
		t.Fatal(err)
	}
	if err := PrepareGroupForAdmin(&group); err != nil {
		t.Fatal(err)
	}
	return &group
}

func TestGroupSSOLegacyEditorSecretLifecycle(t *testing.T) {
	group := seedGroupSSOEditor(t, "oidc")
	edit := loadLegacyAdminGroup(t, group.Id)
	body, _ := json.Marshal(edit)
	if strings.Contains(string(body), "test-only-secret") || !edit.SSOSecretSet || edit.AuthRevision == "" {
		t.Fatalf("legacy response is not redacted or versioned: %s", body)
	}
	edit.Note = "changed in group editor"
	if err := SetGroupFromAdmin(edit); err != nil {
		t.Fatal(err)
	}
	if storedEditorConfig(t, group.Id).ClientSecret != "test-only-secret" {
		t.Fatal("legacy group edit erased secret")
	}
	edit = loadLegacyAdminGroup(t, group.Id)
	edit.SSOSecretAction = "replace"
	edit.Auth["oidc"].(map[string]interface{})["client_secret"] = "new-secret"
	if err := SetGroupFromAdmin(edit); err != nil {
		t.Fatal(err)
	}
	if storedEditorConfig(t, group.Id).ClientSecret != "new-secret" {
		t.Fatal("legacy group editor did not replace secret")
	}
	edit = loadLegacyAdminGroup(t, group.Id)
	edit.Auth["oidc"].(map[string]interface{})["issuer"] = "https://changed.example.test"
	if err := SetGroupFromAdmin(edit); !errors.Is(err, ErrSSOProviderChange) {
		t.Fatalf("legacy editor leaked secret to changed provider: %v", err)
	}
	edit.SSOSecretAction = "clear"
	if err := SetGroupFromAdmin(edit); err != nil {
		t.Fatal(err)
	}
	if storedEditorConfig(t, group.Id).ClientSecret != "" {
		t.Fatal("legacy editor did not clear secret")
	}
}

func TestGroupSSOLegacyStalePageCannotOverwriteDedicatedEditor(t *testing.T) {
	for _, originalType := range []string{"local", "oidc"} {
		t.Run(originalType, func(t *testing.T) {
			group := seedGroupSSOEditor(t, "oidc")
			if originalType == "local" {
				group.Auth = map[string]interface{}{"type": "local"}
				if err := Set(group); err != nil {
					t.Fatal(err)
				}
			}
			stale := loadLegacyAdminGroup(t, group.Id)
			config, _ := SSOConfig(browserAuthData("oidc"))
			config.ClientSecret = "updated-in-dedicated-editor"
			if _, err := SetGroupSSO(GroupSSOUpdate{ID: group.Id, Revision: stale.AuthRevision, Config: config, SecretAction: "replace"}); err != nil {
				t.Fatal(err)
			}
			stale.Note = "must not overwrite"
			if err := SetGroupFromAdmin(stale); !errors.Is(err, ErrSSOConfigConflict) {
				t.Fatalf("stale group editor was accepted: %v", err)
			}
			if storedEditorConfig(t, group.Id).ClientSecret != "updated-in-dedicated-editor" {
				t.Fatal("stale page overwrote SSO configuration")
			}
			fresh := loadLegacyAdminGroup(t, group.Id)
			if fresh.Note == stale.Note {
				t.Fatal("rejected stale page changed group fields")
			}
			fresh.AuthRevision = ""
			if err := SetGroupFromAdmin(fresh); !errors.Is(err, ErrSSORevision) {
				t.Fatalf("unversioned group editor was accepted: %v", err)
			}
			fresh = loadLegacyAdminGroup(t, group.Id)
			fresh.Auth = map[string]interface{}{"type": "local"}
			if err := SetGroupFromAdmin(fresh); err != nil {
				t.Fatalf("explicitly disabling SSO failed: %v", err)
			}
		})
	}
}

func TestGroupSSOLegacyEditorCreationAndInactiveSecretRedaction(t *testing.T) {
	setupSSODB(t)
	group := Group{Name: "new-group", Auth: browserAuthData("oidc"), ClientDns: []ValData{{Val: "10.0.0.53"}}, SSOSecretAction: "replace"}
	if err := SetGroupFromAdmin(&group); err != nil {
		t.Fatalf("new SSO group: %v", err)
	}
	if storedEditorConfig(t, group.Id).ClientSecret != "test-only-secret" {
		t.Fatal("new SSO group secret not stored")
	}
	group.Auth["type"] = "local"
	if err := Set(&group); err != nil {
		t.Fatal(err)
	}
	redacted := loadLegacyAdminGroup(t, group.Id)
	body, _ := json.Marshal(redacted)
	if strings.Contains(string(body), "test-only-secret") || redacted.SSOSecretSet || redacted.AuthRevision == "" {
		t.Fatalf("inactive SSO data is not redacted: %s", body)
	}
}

func TestGroupSSOZeroChangedRowsAcceptsOnlyUnchangedAuth(t *testing.T) {
	group := seedGroupSSOEditor(t, "oidc")
	row, err := readGroupSSORow(group.Id)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkGroupAuthUpdate(0, nil, row, group.Auth); err != nil {
		t.Fatalf("idempotent MySQL result was treated as conflict: %v", err)
	}
	changed := map[string]interface{}{"type": "local"}
	if err := checkGroupAuthUpdate(0, nil, row, changed); !errors.Is(err, ErrSSOConfigConflict) {
		t.Fatalf("failed changed Auth CAS accepted: %v", err)
	}
	group.Auth = changed
	if err := Set(group); err != nil {
		t.Fatal(err)
	}
	var original map[string]interface{}
	_ = json.Unmarshal([]byte(*row.Auth), &original)
	if err := checkGroupAuthUpdate(0, nil, row, original); !errors.Is(err, ErrSSOConfigConflict) {
		t.Fatalf("concurrently changed Auth accepted: %v", err)
	}
}

func TestGroupSSOLegacyCASRejectsChangeBetweenReadAndWrite(t *testing.T) {
	group := seedGroupSSOEditor(t, "oidc")
	guard, err := readGroupSSORow(group.Id)
	if err != nil {
		t.Fatal(err)
	}
	var candidate Group
	if err := One("id", group.Id, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Note = "stale pending write"
	update := loadEditorUpdate(t, group.Id)
	update.SecretAction = "replace"
	update.Config.ClientSecret = "concurrently-rotated-secret"
	if _, err := SetGroupSSO(update); err != nil {
		t.Fatal(err)
	}
	// The legacy wrapper has already checked its revision and merged the old
	// secret. A change before its final SQL write must still reject that write.
	if err := setGroup(&candidate, &guard); !errors.Is(err, ErrSSOConfigConflict) {
		t.Fatalf("legacy SQL update lost concurrent Auth change: %v", err)
	}
	current := loadLegacyAdminGroup(t, group.Id)
	if current.Note == candidate.Note || storedEditorConfig(t, group.Id).ClientSecret != "concurrently-rotated-secret" {
		t.Fatal("failed legacy CAS partially changed group")
	}
}
