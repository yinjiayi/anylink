package dbdata

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/bjdgyc/anylink/pkg/sso"
	"github.com/bjdgyc/anylink/pkg/utils"
)

// Browser authentication never accepts a password through CheckUser.
type BrowserAuth struct{}

func init() {
	authRegistry["oidc"] = reflect.TypeOf(BrowserAuth{})
	authRegistry["oauth2"] = reflect.TypeOf(BrowserAuth{})
}

func SSOConfig(auth map[string]interface{}) (sso.Config, error) {
	var c sso.Config
	typ, _ := auth["type"].(string)
	if typ != "oidc" && typ != "oauth2" {
		return c, errors.New("not a browser SSO group")
	}
	b, err := json.Marshal(auth[typ])
	if err != nil || len(b) > 65536 {
		return c, errors.New("invalid SSO configuration")
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, errors.New("invalid SSO configuration")
	}
	c.Type = typ
	return c, c.Validate()
}

func (BrowserAuth) checkData(data map[string]interface{}) error {
	_, err := SSOConfig(data)
	return err
}

func (BrowserAuth) checkUser(string, string, *Group, map[string]interface{}) error {
	return errors.New("this group requires browser SSO authentication")
}

func GetSSOConfig(group string) (sso.Config, error) {
	g := &Group{}
	if err := One("Name", group, g); err != nil || g.Status != 1 {
		return sso.Config{}, errors.New("SSO group unavailable")
	}
	return SSOConfig(g.Auth)
}

// AuthorizeSSO deliberately requires an explicit immutable-subject mapping to
// an existing enabled account. Successful IdP authentication alone grants no VPN access.
func AuthorizeSSO(group, subject string, expected sso.Config) (string, error) {
	c, err := GetSSOConfig(group)
	if err != nil || !reflect.DeepEqual(c, expected) {
		return "", errors.New("SSO configuration changed; restart login")
	}
	username := c.SubjectUsers[subject]
	if username == "" {
		return "", errors.New("SSO identity is not authorized")
	}
	u := &User{}
	if err := One("Username", username, u); err != nil || u.Status != 1 ||
		!utils.InArrStr(u.Groups, group) ||
		(u.LimitTime != nil && !u.LimitTime.After(time.Now())) {
		return "", errors.New("SSO account is disabled, expired or outside the group")
	}
	return username, nil
}
